use anyhow::{Context, Result, bail};
use flate2::{Compression, GzBuilder, read::MultiGzDecoder};
use rustix::fs::{CWD, Mode, OFlags, RenameFlags, open, renameat_with};
#[cfg(target_os = "linux")]
use rustix::fs::{ResolveFlags, openat2};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

pub(crate) const IDENTITY_ENTRY: &str = "foam-compiler-cache-identity-v1.json";
pub(crate) const DEFAULT_CACHE_ROOT: &str = "/workspace/.cache/sccache";
pub(crate) const DEFAULT_RESTORE_ARCHIVE: &str = "/workspace/.foam/compiler-cache-restore.tar.gz";
pub(crate) const DEFAULT_CAPTURE_ARCHIVE: &str = "/workspace/.foam/compiler-cache-capture.tar.gz";

const MAX_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const MAX_ENTRY_BYTES: u64 = 48 * 1024 * 1024;
const MAX_IDENTITY_BYTES: u64 = 1024 * 1024;
const MAX_TAR_BYTES: u64 = MAX_UNCOMPRESSED_BYTES + (MAX_ENTRIES as u64 + 1) * 1024 + 1024;

#[derive(Clone, Copy)]
struct ArchiveLimits {
    max_compressed_bytes: u64,
    max_uncompressed_bytes: u64,
    max_entries: usize,
    max_entry_bytes: u64,
    max_identity_bytes: u64,
}

const LIMITS: ArchiveLimits = ArchiveLimits {
    max_compressed_bytes: MAX_COMPRESSED_BYTES,
    max_uncompressed_bytes: MAX_UNCOMPRESSED_BYTES,
    max_entries: MAX_ENTRIES,
    max_entry_bytes: MAX_ENTRY_BYTES,
    max_identity_bytes: MAX_IDENTITY_BYTES,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArchiveSummary {
    pub(crate) sha256: String,
    pub(crate) compressed_bytes: u64,
    pub(crate) uncompressed_bytes: u64,
    pub(crate) entries: usize,
}

struct SourceFile {
    absolute: PathBuf,
    relative: String,
    size: u64,
    modified: Option<SystemTime>,
}

struct ValidatedEntry {
    path: PathBuf,
    data_offset: u64,
    size: u64,
}

pub(crate) fn capture(
    cache_root: &Path,
    identity: &[u8],
    destination: &Path,
) -> Result<ArchiveSummary> {
    capture_with_limits(cache_root, identity, destination, LIMITS)
}

pub(crate) fn read_identity(path: Option<&Path>) -> Result<Vec<u8>> {
    let mut reader: Box<dyn Read> = match path {
        Some(path) => Box::new(open_regular(path)?),
        None => Box::new(std::io::stdin().lock()),
    };
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_IDENTITY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    validate_identity(&bytes, LIMITS)?;
    Ok(bytes)
}

fn capture_with_limits(
    cache_root: &Path,
    identity: &[u8],
    destination: &Path,
    limits: ArchiveLimits,
) -> Result<ArchiveSummary> {
    validate_identity(identity, limits)?;
    let root = cache_root
        .canonicalize()
        .with_context(|| format!("resolve compiler cache root {}", cache_root.display()))?;
    if !fs::metadata(&root)?.is_dir() {
        bail!("compiler cache root is not a directory");
    }
    let destination_absolute = absolute_path(destination)?;
    if destination_absolute.starts_with(&root) {
        bail!("compiler cache archive destination must be outside the cache root");
    }

    let mut sources = Vec::new();
    collect_sources(&root, &root, &mut sources)?;
    sources.sort_by(|left, right| left.relative.cmp(&right.relative));
    if sources.len() > limits.max_entries {
        bail!("compiler cache contains too many entries");
    }
    let mut uncompressed = identity.len() as u64;
    for source in &sources {
        if source.relative == IDENTITY_ENTRY {
            bail!("compiler cache contains the reserved identity path");
        }
        if source.size > limits.max_entry_bytes {
            bail!("compiler cache entry exceeds its size bound");
        }
        uncompressed = uncompressed
            .checked_add(source.size)
            .context("compiler cache size overflow")?;
        if uncompressed > limits.max_uncompressed_bytes {
            bail!("compiler cache exceeds its uncompressed size bound");
        }
    }

    let parent = destination
        .parent()
        .context("compiler cache archive destination needs a parent")?;
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".compiler-cache-capture-")
        .tempfile_in(parent)?;
    let mut gzip = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(temporary, Compression::best());
    {
        let mut builder = tar::Builder::new(&mut gzip);
        builder.mode(tar::HeaderMode::Deterministic);
        let root_handle = File::open(&root)?;
        let mut source_index = 0usize;
        let mut identity_written = false;
        while source_index < sources.len() || !identity_written {
            let use_identity = !identity_written
                && (source_index == sources.len()
                    || IDENTITY_ENTRY < sources[source_index].relative.as_str());
            if use_identity {
                append_regular(&mut builder, IDENTITY_ENTRY, identity)?;
                identity_written = true;
                continue;
            }
            let source = &sources[source_index];
            let before = fs::symlink_metadata(&source.absolute)?;
            if !source.matches(&before) {
                bail!("compiler cache entry changed while capturing");
            }
            let mut file = open_source(&root_handle, source)?;
            let opened = file.metadata()?;
            if !source.matches(&opened) {
                bail!("compiler cache entry changed while capturing");
            }
            let header = deterministic_header(&source.relative, source.size)?;
            builder.append(&header, &mut file)?;
            if !source.matches(&file.metadata()?) {
                bail!("compiler cache entry changed while capturing");
            }
            source_index += 1;
        }
        builder.finish()?;
    }
    let temporary = gzip.finish()?;
    temporary.as_file().sync_all()?;
    let compressed = temporary.as_file().metadata()?.len();
    if compressed > limits.max_compressed_bytes {
        bail!("compiler cache archive exceeds its compressed size bound");
    }
    let sha256 = digest_file(temporary.as_file(), limits.max_compressed_bytes)?;
    match temporary.persist_noclobber(destination) {
        Ok(file) => file.sync_all()?,
        Err(error) => return Err(error.error).context("publish compiler cache archive"),
    }
    sync_directory(parent)?;
    Ok(ArchiveSummary {
        sha256,
        compressed_bytes: compressed,
        uncompressed_bytes: uncompressed,
        entries: sources.len(),
    })
}

pub(crate) fn restore(
    archive: &Path,
    expected_sha256: &str,
    expected_identity: &[u8],
    cache_root: &Path,
) -> Result<ArchiveSummary> {
    restore_with_limits(
        archive,
        expected_sha256,
        expected_identity,
        cache_root,
        LIMITS,
    )
}

fn restore_with_limits(
    archive: &Path,
    expected_sha256: &str,
    expected_identity: &[u8],
    cache_root: &Path,
    limits: ArchiveLimits,
) -> Result<ArchiveSummary> {
    validate_digest(expected_sha256)?;
    validate_identity(expected_identity, limits)?;
    if cache_root.exists() {
        bail!("compiler cache activation destination already exists");
    }
    let parent = cache_root
        .parent()
        .context("compiler cache activation destination needs a parent")?;
    fs::create_dir_all(parent)?;

    let mut source = open_regular(archive)?;
    let compressed = source.metadata()?.len();
    if compressed > limits.max_compressed_bytes {
        bail!("compiler cache archive exceeds its compressed size bound");
    }
    let actual_sha256 = digest_file(&source, limits.max_compressed_bytes)?;
    if actual_sha256 != expected_sha256 {
        bail!("compiler cache archive digest mismatch");
    }
    source.seek(SeekFrom::Start(0))?;

    let mut tar_snapshot = tempfile::tempfile_in(parent)?;
    let mut decoder = MultiGzDecoder::new(source);
    let tar_limit = limits
        .max_uncompressed_bytes
        .checked_add((limits.max_entries as u64 + 1) * 1024 + 1024)
        .unwrap_or(MAX_TAR_BYTES);
    copy_bounded(&mut decoder, &mut tar_snapshot, tar_limit)?;
    let (entries, identity, uncompressed) = validate_tar(&mut tar_snapshot, limits)?;
    if identity != expected_identity {
        bail!("compiler cache identity does not exactly match expected identity");
    }

    let staging = tempfile::Builder::new()
        .prefix(".compiler-cache-restore-")
        .tempdir_in(parent)?;
    extract_entries(&mut tar_snapshot, &entries, staging.path())?;
    sync_tree(staging.path())?;
    let staging_path = staging.keep();
    if let Err(error) = renameat_with(CWD, &staging_path, CWD, cache_root, RenameFlags::NOREPLACE) {
        let _ = fs::remove_dir_all(&staging_path);
        return Err(error).context("atomically activate compiler cache");
    }
    sync_directory(parent)?;
    Ok(ArchiveSummary {
        sha256: actual_sha256,
        compressed_bytes: compressed,
        uncompressed_bytes: uncompressed,
        entries: entries.len(),
    })
}

fn validate_identity(identity: &[u8], limits: ArchiveLimits) -> Result<()> {
    if identity.is_empty() || identity.len() as u64 > limits.max_identity_bytes {
        bail!("compiler cache identity exceeds its size bound");
    }
    let _: serde_json::Value =
        serde_json::from_slice(identity).context("compiler cache identity must be valid JSON")?;
    Ok(())
}

fn validate_digest(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("compiler cache digest must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn collect_sources(root: &Path, directory: &Path, output: &mut Vec<SourceFile>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            let canonical = path.canonicalize()?;
            if canonical != path || !canonical.starts_with(root) {
                bail!("compiler cache directory escapes its root");
            }
            collect_sources(root, &path, output)?;
        } else if metadata.file_type().is_file() {
            let canonical = path.canonicalize()?;
            if canonical != path || !canonical.starts_with(root) {
                bail!("compiler cache entry escapes its root");
            }
            output.push(SourceFile {
                absolute: path.clone(),
                relative: normalized_relative(root, &path)?,
                size: metadata.len(),
                modified: metadata.modified().ok(),
            });
        } else {
            bail!("compiler cache contains a symlink or special file");
        }
    }
    Ok(())
}

impl SourceFile {
    fn matches(&self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_file()
            && metadata.len() == self.size
            && metadata.modified().ok() == self.modified
    }
}

#[cfg(target_os = "linux")]
fn open_source(root: &File, source: &SourceFile) -> Result<File> {
    let file = File::from(openat2(
        root,
        source.relative.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )?);
    if !file.metadata()?.is_file() {
        bail!("compiler cache entry is not a regular file");
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_source(_root: &File, source: &SourceFile) -> Result<File> {
    open_regular(&source.absolute)
}

fn normalized_relative(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root)?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                parts.push(part.to_str().context("compiler cache path is not UTF-8")?)
            }
            _ => bail!("compiler cache path is not normalized"),
        }
    }
    if parts.is_empty() {
        bail!("compiler cache path is empty");
    }
    Ok(parts.join("/"))
}

fn normalized_archive_path(raw: &str) -> Result<PathBuf> {
    if raw.is_empty() || raw.contains('\0') || raw.contains('\\') {
        bail!("compiler cache archive contains an unsafe path");
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        bail!("compiler cache archive contains an absolute path");
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            _ => bail!("compiler cache archive contains path traversal"),
        }
    }
    if normalized.as_os_str().is_empty() {
        bail!("compiler cache archive contains an empty path");
    }
    Ok(normalized)
}

fn deterministic_header(path: &str, size: u64) -> Result<tar::Header> {
    let mut header = tar::Header::new_ustar();
    header.set_path(path)?;
    header.set_size(size);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    Ok(header)
}

fn append_regular(builder: &mut tar::Builder<impl Write>, path: &str, bytes: &[u8]) -> Result<()> {
    let header = deterministic_header(path, bytes.len() as u64)?;
    builder.append(&header, bytes)?;
    Ok(())
}

fn validate_tar(
    snapshot: &mut File,
    limits: ArchiveLimits,
) -> Result<(Vec<ValidatedEntry>, Vec<u8>, u64)> {
    snapshot.seek(SeekFrom::Start(0))?;
    let archive_size = snapshot.metadata()?.len();
    if !archive_size.is_multiple_of(512) {
        bail!("compiler cache archive is not tar-block aligned");
    }
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    let mut identity = None;
    let mut total = 0u64;
    let mut offset = 0u64;
    let mut saw_trailer = false;
    let mut header_bytes = [0u8; 512];
    while offset < archive_size {
        snapshot.read_exact(&mut header_bytes)?;
        offset += 512;
        if header_bytes.iter().all(|byte| *byte == 0) {
            let remaining = archive_size - offset;
            if remaining > 512 {
                bail!("compiler cache archive trailer exceeds its size bound");
            }
            let mut trailer = vec![0u8; remaining as usize];
            snapshot.read_exact(&mut trailer)?;
            if trailer.iter().any(|byte| *byte != 0) {
                bail!("compiler cache archive contains data after its trailer");
            }
            saw_trailer = true;
            break;
        }
        let header = tar::Header::from_byte_slice(&header_bytes);
        validate_header_checksum(&header_bytes, header.cksum()?)?;
        if !header.entry_type().is_file() {
            bail!("compiler cache archive contains a link or special entry");
        }
        let path_bytes = header.path_bytes();
        let raw = std::str::from_utf8(path_bytes.as_ref())?;
        let path = normalized_archive_path(raw)?;
        if raw != path.to_string_lossy() {
            bail!("compiler cache archive path is not canonically normalized UTF-8");
        }
        if !seen.insert(path.clone()) {
            bail!("compiler cache archive contains a duplicate path");
        }
        let size = header.entry_size()?;
        let bound = if path == Path::new(IDENTITY_ENTRY) {
            limits.max_identity_bytes
        } else {
            limits.max_entry_bytes
        };
        if size > bound {
            bail!("compiler cache archive entry exceeds its size bound");
        }
        total = total
            .checked_add(size)
            .context("compiler cache size overflow")?;
        if total > limits.max_uncompressed_bytes {
            bail!("compiler cache archive exceeds its uncompressed size bound");
        }
        let padded = size
            .checked_add(511)
            .context("compiler cache archive entry size overflow")?
            / 512
            * 512;
        let end = offset
            .checked_add(padded)
            .context("compiler cache archive offset overflow")?;
        if end > archive_size {
            bail!("compiler cache archive entry is truncated");
        }
        if path == Path::new(IDENTITY_ENTRY) {
            let mut bytes = Vec::with_capacity(size as usize);
            Read::by_ref(snapshot).take(size).read_to_end(&mut bytes)?;
            validate_identity(&bytes, limits)?;
            identity = Some(bytes);
        } else {
            if entries.len() == limits.max_entries {
                bail!("compiler cache archive contains too many entries");
            }
            entries.push(ValidatedEntry {
                path,
                data_offset: offset,
                size,
            });
        }
        snapshot.seek(SeekFrom::Start(end))?;
        offset = end;
    }
    if !saw_trailer {
        bail!("compiler cache archive is missing its tar trailer");
    }
    let identity = identity.context("compiler cache archive is missing its identity")?;
    Ok((entries, identity, total))
}

fn extract_entries(
    snapshot: &mut File,
    entries: &[ValidatedEntry],
    destination: &Path,
) -> Result<()> {
    for entry in entries {
        let output = destination.join(&entry.path);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&output)?;
        snapshot.seek(SeekFrom::Start(entry.data_offset))?;
        let copied = std::io::copy(&mut Read::by_ref(snapshot).take(entry.size), &mut file)?;
        if copied != entry.size {
            bail!("compiler cache archive entry was truncated during extraction");
        }
        file.sync_all()?;
    }
    Ok(())
}

fn validate_header_checksum(bytes: &[u8; 512], declared: u32) -> Result<()> {
    let actual = bytes[..148]
        .iter()
        .chain(bytes[156..].iter())
        .fold(8 * u32::from(b' '), |sum, byte| sum + u32::from(*byte));
    if declared != actual {
        bail!("compiler cache archive header checksum mismatch");
    }
    Ok(())
}

fn copy_bounded(reader: &mut impl Read, writer: &mut File, max: u64) -> Result<u64> {
    let mut copied = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .context("archive size overflow")?;
        if copied > max {
            bail!("compiler cache archive expands beyond its physical bound");
        }
        writer.write_all(&buffer[..read])?;
    }
    writer.sync_all()?;
    Ok(copied)
}

fn digest_file(file: &File, max: u64) -> Result<String> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut read_total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        read_total = read_total
            .checked_add(read as u64)
            .context("archive size overflow")?;
        if read_total > max {
            bail!("compiler cache archive exceeds its compressed size bound");
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn open_regular(path: &Path) -> Result<File> {
    let file = File::from(open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    if !file.metadata()?.is_file() {
        bail!("compiler cache archive is not a regular file");
    }
    Ok(file)
}

fn sync_tree(root: &Path) -> Result<()> {
    let mut directories = vec![root.to_path_buf()];
    collect_directories(root, &mut directories)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}

fn collect_directories(root: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            output.push(entry.path());
            collect_directories(&entry.path(), output)?;
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, GzBuilder};
    use sha2::{Digest, Sha256};
    use std::{fs, io::Write, path::Path};

    const FOAM_IDENTITY: &[u8] = br#"{"schemaVersion":1,"host":"github.com","repository":"evalops/foam","sourceTreeSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","patchDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","lockfileDigests":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"compilerIdentity":"rustc 1.95.0 (abc123 2026-07-22)","targetTriple":"x86_64-unknown-linux-gnu","buildProfile":"release","cargoFeatures":["cache"],"executionClass":"trusted-linux","environmentPolicyDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","namespace":{"host":"github.com","repository":"evalops/foam","trustLane":"trusted","visibility":{"kind":"repository_shared"}}}"#;
    type TestEntry<'a> = (&'a str, tar::EntryType, &'a [u8]);
    type RestoreCase<'a> = (&'a str, Vec<TestEntry<'a>>, &'a [u8]);

    fn digest(path: &Path) -> String {
        format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
    }

    fn append(
        builder: &mut tar::Builder<impl Write>,
        path: &str,
        kind: tar::EntryType,
        bytes: &[u8],
    ) {
        let mut header = tar::Header::new_ustar();
        if header.set_path(path).is_err() {
            let path_field = &mut header.as_mut_bytes()[..100];
            path_field.fill(0);
            path_field[..path.len()].copy_from_slice(path.as_bytes());
        }
        header.set_entry_type(kind);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        builder.append(&header, bytes).unwrap();
    }

    fn malicious_archive(path: &Path, entries: &[(&str, tar::EntryType, &[u8])]) {
        let file = fs::File::create(path).unwrap();
        let encoder = GzBuilder::new().mtime(0).write(file, Compression::best());
        let mut builder = tar::Builder::new(encoder);
        for (path, kind, bytes) in entries {
            append(&mut builder, path, *kind, bytes);
        }
        builder.finish().unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn capture_is_deterministic_path_preserving_and_foam_identity_compatible() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        fs::create_dir_all(cache.join("nested")).unwrap();
        fs::write(cache.join("z"), b"last").unwrap();
        fs::write(cache.join("nested/a"), b"first").unwrap();
        let first = root.path().join("first.tar.gz");
        let second = root.path().join("second.tar.gz");

        capture(&cache, FOAM_IDENTITY, &first).unwrap();
        capture(&cache, FOAM_IDENTITY, &second).unwrap();

        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        let restored = root.path().join("restored");
        restore(&first, &digest(&first), FOAM_IDENTITY, &restored).unwrap();
        assert_eq!(fs::read(restored.join("nested/a")).unwrap(), b"first");
        assert_eq!(fs::read(restored.join("z")).unwrap(), b"last");
        assert!(!restored.join(IDENTITY_ENTRY).exists());
    }

    #[test]
    fn restore_rejects_digest_identity_duplicates_and_unsafe_entries_without_activation() {
        let root = tempfile::tempdir().unwrap();
        let cases: Vec<RestoreCase<'_>> = vec![
            (
                "traversal",
                vec![
                    ("../escape", tar::EntryType::Regular, b"x"),
                    (IDENTITY_ENTRY, tar::EntryType::Regular, FOAM_IDENTITY),
                ],
                FOAM_IDENTITY,
            ),
            (
                "symlink",
                vec![
                    ("link", tar::EntryType::Symlink, b""),
                    (IDENTITY_ENTRY, tar::EntryType::Regular, FOAM_IDENTITY),
                ],
                FOAM_IDENTITY,
            ),
            (
                "duplicate",
                vec![
                    ("same", tar::EntryType::Regular, b"a"),
                    ("same", tar::EntryType::Regular, b"b"),
                    (IDENTITY_ENTRY, tar::EntryType::Regular, FOAM_IDENTITY),
                ],
                FOAM_IDENTITY,
            ),
            (
                "identity",
                vec![(IDENTITY_ENTRY, tar::EntryType::Regular, FOAM_IDENTITY)],
                b"{}",
            ),
        ];
        for (label, entries, expected_identity) in cases {
            let archive = root.path().join(format!("{label}.tar.gz"));
            malicious_archive(&archive, &entries);
            let destination = root.path().join(format!("{label}-cache"));
            assert!(
                restore(&archive, &digest(&archive), expected_identity, &destination).is_err(),
                "{label}"
            );
            assert!(!destination.exists(), "{label} activated partial cache");
        }

        let valid = root.path().join("valid.tar.gz");
        malicious_archive(
            &valid,
            &[(IDENTITY_ENTRY, tar::EntryType::Regular, FOAM_IDENTITY)],
        );
        let destination = root.path().join("bad-digest-cache");
        assert!(restore(&valid, &"0".repeat(64), FOAM_IDENTITY, &destination).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn capture_rejects_reserved_links_and_special_files_without_publication() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join(IDENTITY_ENTRY), b"reserved").unwrap();
        let archive = root.path().join("reserved.tar.gz");
        assert!(capture(&cache, FOAM_IDENTITY, &archive).is_err());
        assert!(!archive.exists());

        fs::remove_file(cache.join(IDENTITY_ENTRY)).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("missing", cache.join("link")).unwrap();
            assert!(capture(&cache, FOAM_IDENTITY, &archive).is_err());
            assert!(!archive.exists());
            fs::remove_file(cache.join("link")).unwrap();
            let _socket = std::os::unix::net::UnixListener::bind(cache.join("socket")).unwrap();
            assert!(capture(&cache, FOAM_IDENTITY, &archive).is_err());
            assert!(!archive.exists());
        }
    }

    #[test]
    fn archive_limits_are_enforced_before_activation_or_publication() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("large"), b"12345").unwrap();
        let tiny = ArchiveLimits {
            max_compressed_bytes: 1024,
            max_uncompressed_bytes: 4,
            max_entries: 1,
            max_entry_bytes: 4,
            max_identity_bytes: 4,
        };
        let archive = root.path().join("bounded.tar.gz");
        assert!(capture_with_limits(&cache, b"{}", &archive, tiny).is_err());
        assert!(!archive.exists());
    }
}

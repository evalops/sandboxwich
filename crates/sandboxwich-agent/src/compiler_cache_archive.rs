use anyhow::{Context, Result, bail};
use flate2::{Compression, GzBuilder, read::MultiGzDecoder};
use rustix::{
    fs::{CWD, Mode, OFlags, RenameFlags, mkdirat, open, openat, renameat_with},
    io::Errno,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

pub(crate) const IDENTITY_ENTRY: &str = "foam-compiler-cache-identity-v1.json";
pub(crate) const DEFAULT_CACHE_ROOT: &str = "/workspace/.cache/sccache";
pub(crate) const DEFAULT_RESTORE_ARCHIVE: &str =
    "/workspace/.sandboxwich-private/compiler-cache-restore.tar.gz";
pub(crate) const DEFAULT_CAPTURE_ARCHIVE: &str = "/workspace/.foam/compiler-cache-capture.tar.gz";
const WORKSPACE_ROOT: &str = "/workspace";
const PRIVATE_ROOT: &str = "/workspace/.sandboxwich-private";
const CACHE_PARENT: &str = "/workspace/.cache";
const WORKLOAD_UID: u32 = 10001;
const WORKLOAD_GID: u32 = 10001;

const MAX_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const MAX_ENTRY_BYTES: u64 = 48 * 1024 * 1024;
const MAX_IDENTITY_BYTES: u64 = 1024 * 1024;
const MAX_TAR_BYTES: u64 = MAX_UNCOMPRESSED_BYTES + (MAX_ENTRIES as u64 + 1) * 1024 + 1024;
const IDENTITY_FIELDS: [&str; 13] = [
    "schemaVersion",
    "host",
    "repository",
    "sourceTreeSha",
    "patchDigest",
    "lockfileDigests",
    "compilerIdentity",
    "targetTriple",
    "buildProfile",
    "cargoFeatures",
    "executionClass",
    "environmentPolicyDigest",
    "namespace",
];

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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StagedArchiveSummary {
    sha256: String,
    bytes: u64,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CacheTrustLane {
    Trusted,
    Bulk,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CacheVisibility {
    RepositoryShared,
    TenantRepositoryPrivate { tenant: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompilerCacheNamespace {
    host: String,
    repository: String,
    trust_lane: CacheTrustLane,
    visibility: CacheVisibility,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompilerCacheIdentityV1 {
    schema_version: u32,
    host: String,
    repository: String,
    source_tree_sha: String,
    patch_digest: Option<String>,
    lockfile_digests: BTreeSet<String>,
    compiler_identity: String,
    target_triple: String,
    build_profile: String,
    cargo_features: BTreeSet<String>,
    execution_class: String,
    environment_policy_digest: String,
    namespace: CompilerCacheNamespace,
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
    if !fs::symlink_metadata(cache_root)?.is_dir() {
        bail!("compiler cache root is not a directory");
    }
    let root_handle = open_directory(&root)?;
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

pub(crate) fn prepare_workspace_boundary() -> Result<()> {
    prepare_workspace_boundary_at(Path::new(WORKSPACE_ROOT), 0, 0)
}

pub(crate) fn run_helper() -> Result<()> {
    verify_workspace_boundary(
        Path::new(WORKSPACE_ROOT),
        Path::new(CACHE_PARENT),
        Path::new(PRIVATE_ROOT),
    )?;
    loop {
        std::thread::park();
    }
}

pub(crate) fn stage_restore_archive(expected_sha256: &str) -> Result<StagedArchiveSummary> {
    verify_workspace_boundary(
        Path::new(WORKSPACE_ROOT),
        Path::new(CACHE_PARENT),
        Path::new(PRIVATE_ROOT),
    )?;
    let destination = Path::new(DEFAULT_RESTORE_ARCHIVE);
    let mut staged = tempfile::Builder::new()
        .prefix(".compiler-cache-upload-")
        .tempfile_in(Path::new(PRIVATE_ROOT))?;
    let (actual_sha256, bytes) = copy_hash_bounded(
        &mut std::io::stdin().lock(),
        staged.as_file_mut(),
        MAX_COMPRESSED_BYTES,
    )?;
    if actual_sha256 != expected_sha256 {
        bail!("compiler cache archive digest mismatch while staging");
    }
    staged.as_file().sync_all()?;
    match staged.persist_noclobber(destination) {
        Ok(_) => {}
        Err(error) => return Err(error.error).context("publish staged compiler cache archive"),
    }
    sync_directory(Path::new(PRIVATE_ROOT))?;
    Ok(StagedArchiveSummary {
        sha256: actual_sha256,
        bytes,
    })
}

pub(crate) fn restore_for_workload(
    archive: &Path,
    expected_sha256: &str,
    expected_identity: &[u8],
    cache_root: &Path,
) -> Result<ArchiveSummary> {
    if archive != Path::new(DEFAULT_RESTORE_ARCHIVE) || cache_root != Path::new(DEFAULT_CACHE_ROOT)
    {
        bail!("root compiler-cache restore is confined to its fixed workspace paths");
    }
    verify_workspace_boundary(
        Path::new(WORKSPACE_ROOT),
        Path::new(CACHE_PARENT),
        Path::new(PRIVATE_ROOT),
    )?;
    let summary = restore(archive, expected_sha256, expected_identity, cache_root)?;
    chown_activated_tree(cache_root, WORKLOAD_UID, WORKLOAD_GID)?;
    sync_directory(Path::new(CACHE_PARENT))?;
    Ok(summary)
}

#[cfg(unix)]
fn prepare_workspace_boundary_at(workspace: &Path, owner_uid: u32, owner_gid: u32) -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, fchown};

    let root = open_directory(workspace)?;
    fchown(&root, Some(owner_uid), Some(owner_gid))?;
    root.set_permissions(fs::Permissions::from_mode(0o1777))?;
    for (name, mode) in [(".cache", 0o755), (".sandboxwich-private", 0o700)] {
        let path = Path::new(name);
        match mkdirat(&root, path, Mode::RWXU) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
        let directory = File::from(openat(
            &root,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )?);
        fchown(&directory, Some(owner_uid), Some(owner_gid))?;
        directory.set_permissions(fs::Permissions::from_mode(mode))?;
        directory.sync_all()?;
    }
    root.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn prepare_workspace_boundary_at(
    _workspace: &Path,
    _owner_uid: u32,
    _owner_gid: u32,
) -> Result<()> {
    bail!("compiler-cache helper boundary requires Unix ownership semantics")
}

#[cfg(unix)]
fn verify_workspace_boundary(workspace: &Path, cache_parent: &Path, private: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    for (path, mode) in [(workspace, 0o1777), (cache_parent, 0o755), (private, 0o700)] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.permissions().mode() & 0o7777 != mode
        {
            bail!("compiler-cache helper ownership boundary is not intact");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_workspace_boundary(
    _workspace: &Path,
    _cache_parent: &Path,
    _private: &Path,
) -> Result<()> {
    bail!("compiler-cache helper boundary requires Unix ownership semantics")
}

#[cfg(unix)]
fn chown_activated_tree(root: &Path, uid: u32, gid: u32) -> Result<()> {
    chown_activated_tree_with(root, uid, gid, |_| {})
}

#[cfg(unix)]
fn chown_activated_tree_with(
    root: &Path,
    uid: u32,
    gid: u32,
    mut before_chown: impl FnMut(&Path),
) -> Result<()> {
    use std::os::unix::fs::fchown;

    let root_handle = open_directory(root)?;
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    collect_extracted_tree(root, root, &mut files, &mut directories)?;
    for (path, _) in files {
        let file = open_confined(
            &root_handle,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        before_chown(&path);
        fchown(&file, Some(uid), Some(gid))?;
        file.sync_all()?;
    }
    let mut directories: Vec<_> = directories.into_iter().collect();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in directories {
        let directory = open_confined(
            &root_handle,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )?;
        before_chown(&path);
        fchown(&directory, Some(uid), Some(gid))?;
        directory.sync_all()?;
    }
    before_chown(Path::new(""));
    fchown(&root_handle, Some(uid), Some(gid))?;
    root_handle.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn chown_activated_tree(_root: &Path, _uid: u32, _gid: u32) -> Result<()> {
    bail!("compiler-cache ownership handoff requires Unix ownership semantics")
}

fn restore_with_limits(
    archive: &Path,
    expected_sha256: &str,
    expected_identity: &[u8],
    cache_root: &Path,
    limits: ArchiveLimits,
) -> Result<ArchiveSummary> {
    restore_with_hooks(
        archive,
        expected_sha256,
        expected_identity,
        cache_root,
        limits,
        || {},
        |_, _| {},
    )
}

fn restore_with_hooks<SnapshotHook, ExtractionHook>(
    archive: &Path,
    expected_sha256: &str,
    expected_identity: &[u8],
    cache_root: &Path,
    limits: ArchiveLimits,
    snapshot_hook: SnapshotHook,
    mut extraction_hook: ExtractionHook,
) -> Result<ArchiveSummary>
where
    SnapshotHook: FnOnce(),
    ExtractionHook: FnMut(&Path, &Path),
{
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
    let source_before = source.metadata()?;
    if source_before.len() > limits.max_compressed_bytes {
        bail!("compiler cache archive exceeds its compressed size bound");
    }
    let mut compressed_snapshot = tempfile::tempfile_in(parent)?;
    let (actual_sha256, compressed) = copy_hash_bounded(
        &mut source,
        &mut compressed_snapshot,
        limits.max_compressed_bytes,
    )?;
    let source_after = source.metadata()?;
    if compressed != source_before.len()
        || source_after.len() != source_before.len()
        || source_after.modified().ok() != source_before.modified().ok()
    {
        bail!("compiler cache archive changed while snapshotting");
    }
    if actual_sha256 != expected_sha256 {
        bail!("compiler cache archive digest mismatch");
    }
    compressed_snapshot.sync_all()?;
    compressed_snapshot.seek(SeekFrom::Start(0))?;
    snapshot_hook();

    let mut tar_snapshot = tempfile::tempfile_in(parent)?;
    let mut decoder = MultiGzDecoder::new(compressed_snapshot);
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
    extract_entries(
        &mut tar_snapshot,
        &entries,
        staging.path(),
        &mut extraction_hook,
    )?;
    validate_extracted_tree(staging.path(), &entries)?;
    let staging_handle = open_directory(staging.path())?;
    sync_staging_directories_with(&staging_handle, &entries, |_| Ok(()))?;
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

#[cfg(test)]
fn restore_with_snapshot_hook<Hook>(
    archive: &Path,
    expected_sha256: &str,
    expected_identity: &[u8],
    cache_root: &Path,
    hook: Hook,
) -> Result<ArchiveSummary>
where
    Hook: FnOnce(),
{
    restore_with_hooks(
        archive,
        expected_sha256,
        expected_identity,
        cache_root,
        LIMITS,
        hook,
        |_, _| {},
    )
}

#[cfg(test)]
fn restore_with_extraction_hook<Hook>(
    archive: &Path,
    expected_sha256: &str,
    expected_identity: &[u8],
    cache_root: &Path,
    hook: Hook,
) -> Result<ArchiveSummary>
where
    Hook: FnMut(&Path, &Path),
{
    restore_with_hooks(
        archive,
        expected_sha256,
        expected_identity,
        cache_root,
        LIMITS,
        || {},
        hook,
    )
}

fn validate_identity(identity: &[u8], limits: ArchiveLimits) -> Result<()> {
    if identity.is_empty() || identity.len() as u64 > limits.max_identity_bytes {
        bail!("compiler cache identity exceeds its size bound");
    }
    let raw: serde_json::Value =
        serde_json::from_slice(identity).context("compiler cache identity must be valid JSON")?;
    let object = raw
        .as_object()
        .context("compiler cache identity must be a JSON object")?;
    if object.len() != IDENTITY_FIELDS.len()
        || IDENTITY_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        bail!("compiler cache identity fields do not match the v1 schema");
    }
    let parsed: CompilerCacheIdentityV1 = serde_json::from_value(raw)
        .context("compiler cache identity does not match the v1 schema")?;
    parsed.validate()?;
    if serde_json::to_vec(&parsed)? != identity {
        bail!("compiler cache identity is not in canonical Foam encoding");
    }
    Ok(())
}

impl CompilerCacheIdentityV1 {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("compiler cache schema version must be 1");
        }
        validate_git_host("host", &self.host)?;
        validate_repository("repository", &self.repository)?;
        validate_git_tree(&self.source_tree_sha)?;
        if let Some(digest) = &self.patch_digest {
            validate_sha256("patch digest", digest)?;
        }
        for digest in &self.lockfile_digests {
            validate_sha256("lockfile digest", digest)?;
        }
        validate_compiler_identity(&self.compiler_identity)?;
        validate_text("target triple", &self.target_triple)?;
        validate_text("build profile", &self.build_profile)?;
        for feature in &self.cargo_features {
            validate_text("cargo feature", feature)?;
        }
        validate_text("execution class", &self.execution_class)?;
        validate_sha256("environment policy digest", &self.environment_policy_digest)?;
        validate_git_host("namespace host", &self.namespace.host)?;
        validate_repository("namespace repository", &self.namespace.repository)?;
        if self.host != self.namespace.host || self.repository != self.namespace.repository {
            bail!("compiler cache identity host and repository must match its namespace");
        }
        if let CacheVisibility::TenantRepositoryPrivate { tenant } = &self.namespace.visibility {
            validate_text("namespace tenant", tenant)?;
        }
        Ok(())
    }
}

fn validate_git_host(field: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        bail!("compiler cache {field} must be a normalized lowercase DNS-style hostname");
    }
    Ok(())
}

fn validate_repository(field: &str, value: &str) -> Result<()> {
    let mut components = value.split('/');
    let valid = components.next().is_some_and(valid_repository_component)
        && components.next().is_some_and(valid_repository_component)
        && components.next().is_none();
    if !valid {
        bail!(
            "compiler cache {field} must have exactly two non-empty URL-safe owner/name components"
        );
    }
    Ok(())
}

fn valid_repository_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_git_tree(value: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("compiler cache source tree must be 40 or 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("compiler cache {field} must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_text(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().count() > 256 || value.chars().any(char::is_control) {
        bail!("compiler cache {field} must be non-empty bounded text without control characters");
    }
    Ok(())
}

fn validate_compiler_identity(value: &str) -> Result<()> {
    if value.is_empty()
        || value.chars().count() > 4096
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        bail!("compiler cache compiler identity is invalid");
    }
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

fn open_source(root: &File, source: &SourceFile) -> Result<File> {
    open_confined(
        root,
        Path::new(&source.relative),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
}

fn open_confined(root: &File, path: &Path, final_flags: OFlags, mode: Mode) -> Result<File> {
    let components = normal_components(path)?;
    let mut directory = root.try_clone()?;
    for component in &components[..components.len() - 1] {
        directory = File::from(openat(
            &directory,
            Path::new(component),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )?);
        if !directory.metadata()?.is_dir() {
            bail!("compiler cache path parent is not a directory");
        }
    }
    let file = File::from(openat(
        &directory,
        Path::new(components.last().context("compiler cache path is empty")?),
        final_flags,
        mode,
    )?);
    if final_flags.contains(OFlags::DIRECTORY) && !file.metadata()?.is_dir() {
        bail!("compiler cache path is not a directory");
    }
    if !final_flags.contains(OFlags::DIRECTORY) && !file.metadata()?.is_file() {
        bail!("compiler cache entry is not a regular file");
    }
    Ok(file)
}

fn normal_components(path: &Path) -> Result<Vec<&std::ffi::OsStr>> {
    let components: Vec<_> = path
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value),
            _ => bail!("compiler cache path is not normalized"),
        })
        .collect::<Result<_>>()?;
    if components.is_empty() {
        bail!("compiler cache path is empty");
    }
    Ok(components)
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
    hook: &mut impl FnMut(&Path, &Path),
) -> Result<()> {
    let root = open_directory(destination)?;
    for entry in entries {
        let (parent, file_name) = create_parent_confined(&root, &entry.path)?;
        hook(destination, &entry.path);
        let mut file = File::from(openat(
            &parent,
            Path::new(file_name),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        if !file.metadata()?.is_file() {
            bail!("compiler cache extraction target is not a regular file");
        }
        snapshot.seek(SeekFrom::Start(entry.data_offset))?;
        let copied = std::io::copy(&mut Read::by_ref(snapshot).take(entry.size), &mut file)?;
        if copied != entry.size {
            bail!("compiler cache archive entry was truncated during extraction");
        }
        file.sync_all()?;
    }
    Ok(())
}

fn sync_staging_directories_with(
    root: &File,
    entries: &[ValidatedEntry],
    mut before_sync: impl FnMut(&Path) -> Result<()>,
) -> Result<()> {
    let mut directories = BTreeSet::new();
    for entry in entries {
        let mut parent = entry.path.parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            directories.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    let mut directories: Vec<_> = directories.into_iter().collect();
    directories.sort_by(|left, right| {
        right
            .components()
            .count()
            .cmp(&left.components().count())
            .then_with(|| left.cmp(right))
    });
    for path in directories {
        let directory = open_confined(
            root,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )?;
        before_sync(&path)?;
        directory.sync_all()?;
    }
    before_sync(Path::new(""))?;
    root.sync_all()?;
    Ok(())
}

fn create_parent_confined<'a>(root: &File, path: &'a Path) -> Result<(File, &'a std::ffi::OsStr)> {
    let components = normal_components(path)?;
    let (file_name, parents) = components
        .split_last()
        .context("compiler cache path is empty")?;
    let mut directory = root.try_clone()?;
    for component in parents {
        let next = match openat(
            &directory,
            Path::new(component),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(Errno::NOENT) => {
                mkdirat(&directory, Path::new(component), Mode::RWXU)?;
                File::from(openat(
                    &directory,
                    Path::new(component),
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                    Mode::empty(),
                )?)
            }
            Err(error) => return Err(error.into()),
        };
        if !next.metadata()?.is_dir() {
            bail!("compiler cache extraction parent is not a directory");
        }
        directory = next;
    }
    Ok((directory, file_name))
}

fn validate_extracted_tree(root: &Path, entries: &[ValidatedEntry]) -> Result<()> {
    let expected_files: BTreeSet<_> = entries
        .iter()
        .map(|entry| (entry.path.clone(), entry.size))
        .collect();
    let mut expected_directories = BTreeSet::new();
    for entry in entries {
        let mut parent = entry.path.parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            expected_directories.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    let mut actual_files = BTreeSet::new();
    let mut actual_directories = BTreeSet::new();
    collect_extracted_tree(root, root, &mut actual_files, &mut actual_directories)?;
    if actual_files != expected_files || actual_directories != expected_directories {
        bail!("compiler cache staging tree changed before activation");
    }
    Ok(())
}

fn collect_extracted_tree(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<(PathBuf, u64)>,
    directories: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.file_type().is_dir() {
            directories.insert(relative);
            collect_extracted_tree(root, &path, files, directories)?;
        } else if metadata.file_type().is_file() {
            files.insert((relative, metadata.len()));
        } else {
            bail!("compiler cache staging tree contains a link or special file");
        }
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

fn copy_hash_bounded(reader: &mut impl Read, writer: &mut File, max: u64) -> Result<(String, u64)> {
    let mut copied = 0u64;
    let mut hasher = Sha256::new();
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
            bail!("compiler cache archive exceeds its compressed size bound");
        }
        writer.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    Ok((format!("{:x}", hasher.finalize()), copied))
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

fn open_directory(path: &Path) -> Result<File> {
    let directory = File::from(open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )?);
    if !directory.metadata()?.is_dir() {
        bail!("compiler cache path is not a directory");
    }
    Ok(directory)
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
    const FOAM_IDENTITY_DIGEST: &str =
        "25df318da989c83fd5e2a401d278fda5908c21a7bad1fdfff98c55a9ec5a045d";
    type TestEntry<'a> = (&'a str, tar::EntryType, &'a [u8]);
    type RestoreCase<'a> = (&'a str, Vec<TestEntry<'a>>, &'a [u8]);

    fn digest(path: &Path) -> String {
        format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
    }

    fn identity_replacing(from: &str, to: &str) -> Vec<u8> {
        String::from_utf8(FOAM_IDENTITY.to_vec())
            .unwrap()
            .replacen(from, to, 1)
            .into_bytes()
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
    fn foam_identity_contract_is_closed_canonical_and_digest_compatible() {
        validate_identity(FOAM_IDENTITY, LIMITS).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(FOAM_IDENTITY)),
            FOAM_IDENTITY_DIGEST
        );

        let invalid = [
            identity_replacing("\"schemaVersion\":1", "\"schemaVersion\":2"),
            identity_replacing("\"host\":\"github.com\"", "\"host\":\"GitHub.com\""),
            identity_replacing("\"repository\":\"evalops/foam\"", "\"repository\":\"foam\""),
            identity_replacing(
                "\"sourceTreeSha\":\"aaaaaaaa",
                "\"sourceTreeSha\":\"AAAAAAAA",
            ),
            identity_replacing("\"patchDigest\":\"aaaaaaaa", "\"patchDigest\":\"AAAAAAAA"),
            identity_replacing(
                "\"lockfileDigests\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]",
                "\"lockfileDigests\":[\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]",
            ),
            identity_replacing(
                "\"cargoFeatures\":[\"cache\"]",
                "\"cargoFeatures\":[\"z\",\"a\",\"a\"]",
            ),
            identity_replacing("\"trustLane\":\"trusted\"", "\"trustLane\":\"root\""),
            identity_replacing("\"kind\":\"repository_shared\"", "\"kind\":\"public\""),
            identity_replacing("\"namespace\":{", "\"unknown\":true,\"namespace\":{"),
            identity_replacing(
                "\"patchDigest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
                "",
            ),
            identity_replacing(
                "\"namespace\":{\"host\":\"github.com\"",
                "\"namespace\":{\"host\":\"gitlab.com\"",
            ),
        ];
        for identity in invalid {
            assert!(
                validate_identity(&identity, LIMITS).is_err(),
                "accepted {}",
                String::from_utf8_lossy(&identity)
            );
        }
    }

    #[test]
    fn restore_uses_one_immutable_archive_snapshot_after_hashing() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("object"), b"immutable").unwrap();
        let archive = root.path().join("cache.tar.gz");
        capture(&cache, FOAM_IDENTITY, &archive).unwrap();
        let expected_digest = digest(&archive);
        let restored = root.path().join("restored");

        restore_with_snapshot_hook(&archive, &expected_digest, FOAM_IDENTITY, &restored, || {
            fs::write(&archive, b"mutated after snapshot").unwrap()
        })
        .unwrap();

        assert_eq!(fs::read(restored.join("object")).unwrap(), b"immutable");
    }

    #[test]
    fn nested_staging_directories_are_synced_bottom_up_and_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("a/b")).unwrap();
        fs::write(root.path().join("a/b/object"), b"object").unwrap();
        let handle = open_directory(root.path()).unwrap();
        let entries = vec![ValidatedEntry {
            path: PathBuf::from("a/b/object"),
            data_offset: 0,
            size: 6,
        }];
        let mut synced = Vec::new();
        sync_staging_directories_with(&handle, &entries, |path| {
            synced.push(path.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            synced,
            [PathBuf::from("a/b"), PathBuf::from("a"), PathBuf::new()]
        );

        let error = sync_staging_directories_with(&handle, &entries, |path| {
            if path == Path::new("a") {
                anyhow::bail!("injected directory fsync failure");
            }
            Ok(())
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected directory fsync failure")
        );
    }

    #[cfg(unix)]
    #[test]
    fn workspace_boundary_is_sticky_and_private_roots_are_not_workload_writable() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let workspace = tempfile::tempdir().unwrap();
        let metadata = workspace.path().metadata().unwrap();
        prepare_workspace_boundary_at(workspace.path(), metadata.uid(), metadata.gid()).unwrap();
        assert_eq!(
            workspace.path().metadata().unwrap().permissions().mode() & 0o7777,
            0o1777
        );
        assert_eq!(
            workspace
                .path()
                .join(".cache")
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        assert_eq!(
            workspace
                .path()
                .join(".sandboxwich-private")
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn ownership_handoff_visits_files_and_directories_before_root() {
        use std::os::unix::fs::MetadataExt;

        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("a/b")).unwrap();
        fs::write(root.path().join("a/b/object"), b"object").unwrap();
        let metadata = root.path().metadata().unwrap();
        let mut visited = Vec::new();
        chown_activated_tree_with(root.path(), metadata.uid(), metadata.gid(), |path| {
            visited.push(path.to_path_buf());
        })
        .unwrap();
        assert_eq!(visited.last(), Some(&PathBuf::new()));
        assert!(
            visited
                .iter()
                .position(|path| path == Path::new("a/b/object"))
                < visited.iter().position(|path| path == Path::new("a/b"))
        );
        assert!(
            visited.iter().position(|path| path == Path::new("a/b"))
                < visited.iter().position(|path| path == Path::new("a"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn distinct_workload_uid_cannot_overwrite_or_swap_root_staging() {
        use std::os::unix::{fs::PermissionsExt, process::CommandExt};

        if std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .is_none_or(|uid| uid.trim() != "0")
        {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        prepare_workspace_boundary_at(workspace.path(), 0, 0).unwrap();
        let staging = workspace.path().join(".cache/.compiler-cache-restore-test");
        fs::create_dir_all(staging.join("a/b")).unwrap();
        fs::write(staging.join("a/b/object"), b"original").unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();

        let overwrite = std::process::Command::new("sh")
            .args(["-c", "printf 'mutated!' > \"$1/a/b/object\"", "sh"])
            .arg(&staging)
            .uid(WORKLOAD_UID)
            .gid(WORKLOAD_GID)
            .status()
            .unwrap();
        assert!(!overwrite.success());
        assert_eq!(fs::read(staging.join("a/b/object")).unwrap(), b"original");

        let swap = std::process::Command::new("sh")
            .args(["-c", "mv \"$1/a\" \"$2/swapped-a\"", "sh"])
            .arg(&staging)
            .arg(workspace.path())
            .uid(WORKLOAD_UID)
            .gid(WORKLOAD_GID)
            .status()
            .unwrap();
        assert!(!swap.success());
        assert!(staging.join("a/b/object").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_staging_parent_symlink_swap_without_outside_write() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        fs::create_dir_all(cache.join("nested")).unwrap();
        fs::write(cache.join("nested/object"), b"private").unwrap();
        let archive = root.path().join("cache.tar.gz");
        capture(&cache, FOAM_IDENTITY, &archive).unwrap();
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let restored = root.path().join("restored");

        let result = restore_with_extraction_hook(
            &archive,
            &digest(&archive),
            FOAM_IDENTITY,
            &restored,
            |staging, entry| {
                if entry == Path::new("nested/object") {
                    fs::remove_dir(staging.join("nested")).unwrap();
                    std::os::unix::fs::symlink(&outside, staging.join("nested")).unwrap();
                }
            },
        );

        assert!(result.is_err());
        assert!(!restored.exists());
        assert!(!outside.join("object").exists());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_capture_dirfd_walk_rejects_parent_swapped_to_symlink() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        fs::create_dir_all(cache.join("nested")).unwrap();
        fs::write(cache.join("nested/object"), b"inside").unwrap();
        let canonical = cache.canonicalize().unwrap();
        let mut sources = Vec::new();
        collect_sources(&canonical, &canonical, &mut sources).unwrap();
        let root_handle = File::open(&canonical).unwrap();

        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("object"), b"outside").unwrap();
        fs::remove_file(cache.join("nested/object")).unwrap();
        fs::remove_dir(cache.join("nested")).unwrap();
        std::os::unix::fs::symlink(&outside, cache.join("nested")).unwrap();

        assert!(open_source(&root_handle, &sources[0]).is_err());
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

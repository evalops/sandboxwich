# Releasing

Releases are automated with [release-plz](https://release-plz.dev/). There is
no manual version bump command to run; cutting a release is merging a PR.

## Flow

1. Every push to `main` runs `release-plz release-pr`, which creates or
   updates a single release PR. It bumps the shared version in
   `[workspace.package]` (all crates inherit it via
   `version.workspace = true`) and regenerates the `## Unreleased` section of
   `CHANGELOG.md` from conventional commits.
2. Review the release PR and merge it **with a merge commit, not a squash
   merge** — release-plz can tag the wrong SHA after squash merges
   ([release-plz#2759](https://github.com/release-plz/release-plz/issues/2759)).
3. On the next `main` push, `release-plz release` pushes the `vX.Y.Z` tag.
   All six crates render the same tag name and release-plz skips tags that
   already exist, so exactly one tag is created per release.
4. The tag push triggers `release.yml`, which builds the cross-platform CLI
   binaries (with provenance attestation), the OpenAPI contract, and the
   image digest inventory, and creates the GitHub release.

The version bump level comes from conventional commits since the last tag:
`feat` → minor, `fix` and everything else → patch, `!`/`BREAKING CHANGE` →
major. If nothing releasable changed, no release PR is opened.

## `RELEASE_BOT_TOKEN` secret

Events caused by the default `GITHUB_TOKEN` do not trigger other workflows.
Without a PAT, the release PR gets no CI runs and the tag push does not start
`release.yml`. For the fully automated flow, add a `RELEASE_BOT_TOKEN`
repository secret: a PAT with `repo` scope (or a fine-grained PAT with
contents + pull-requests read/write on this repo). The workflow falls back to
`GITHUB_TOKEN`, so everything still works with two manual kicks: push an
empty commit to the release PR to start CI, and re-run the release build as
below after the tag lands.

## Manual recovery

If the tag exists but the release build never started:

```sh
gh workflow run release.yml --ref vX.Y.Z
```

## Local preview

`just release-preview` runs `release-plz update` on your working tree, shows
the version bump and changelog entries the release PR would contain, then
restores the tree. Run it on a clean checkout.

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

## Release bot credentials

The workflow authenticates release-plz with a short-lived GitHub App
installation token minted at run time from two repository secrets:
`RELEASE_BOT_APP_ID` and `RELEASE_BOT_APP_PRIVATE_KEY`. The mint is scoped
to this repository with only contents + pull-requests permissions.

The default `GITHUB_TOKEN` cannot run this flow for two independent
reasons: the org disallows Actions-created pull requests (`release-pr`
fails with 403), and events caused by `GITHUB_TOKEN` trigger no workflows,
so the release PR would get no CI and the tag push would not start
`release.yml`. App-caused events have neither problem.

To rotate or swap the bot, replace the two secrets with another GitHub App
installed on this repo that has contents + pull-requests write. No
workflow change is needed.

## Manual recovery

If the tag exists but the release build never started:

```sh
gh workflow run release.yml --ref vX.Y.Z
```

## Local preview

`just release-preview` runs `release-plz update` on your working tree, shows
the version bump and changelog entries the release PR would contain, then
restores the tree. Run it on a clean checkout.

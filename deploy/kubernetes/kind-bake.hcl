// Bake definition for the kind conformance workflow
// (.github/workflows/kubernetes-conformance.yml). Building all four
// conformance images through one `docker buildx bake` invocation instead of
// four serial `docker buildx build` calls buys two things:
//
//   1. The `api` and `worker` targets both build from Dockerfile's
//      `runtime-shared` stage, which in turn copies its binary out of the
//      `builder-shared` stage. `builder-shared` compiles both release
//      binaries in a single `cargo build` and its instructions never vary
//      with BIN, so it hashes identically for both targets; BuildKit
//      resolves it once per bake invocation and shares the result instead
//      of compiling the workspace twice.
//   2. Independent targets (api/worker's rust compile vs. the apt-heavy
//      runtime image vs. the trivial postgres pull) build concurrently
//      against the same builder instead of serially blocking each other.
//
// Cache scopes are unchanged from the previous per-image `docker buildx
// build --cache-from/--cache-to type=gha,scope=kind-*` calls.
group "default" {
  targets = ["api", "worker", "runtime", "postgres"]
}

target "api" {
  context    = "."
  dockerfile = "Dockerfile"
  target     = "runtime-shared"
  args = {
    BIN = "sandboxwich-api"
  }
  tags       = ["sandboxwich-api:conformance"]
  cache-from = ["type=gha,scope=kind-api"]
  cache-to   = ["type=gha,mode=max,scope=kind-api"]
}

target "worker" {
  context    = "."
  dockerfile = "Dockerfile"
  target     = "runtime-shared"
  args = {
    BIN = "sandboxwich-worker"
  }
  tags       = ["sandboxwich-worker:conformance"]
  cache-from = ["type=gha,scope=kind-worker"]
  cache-to   = ["type=gha,mode=max,scope=kind-worker"]
}

target "runtime" {
  context    = "deploy/runtime/ubuntu-dev"
  dockerfile = "Dockerfile"
  tags       = ["sandboxwich-runtime:conformance"]
  cache-from = ["type=gha,scope=kind-runtime"]
  cache-to   = ["type=gha,mode=max,scope=kind-runtime"]
}

target "postgres" {
  context    = "."
  dockerfile = "deploy/kubernetes/postgres.Dockerfile"
  tags       = ["postgres:conformance"]
  cache-from = ["type=gha,scope=kind-postgres"]
  cache-to   = ["type=gha,mode=max,scope=kind-postgres"]
}

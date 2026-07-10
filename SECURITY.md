# Security policy

## Supported versions

Sandboxwich is pre-1.0. Security fixes are applied to the latest release and
the `main` branch. Deploy immutable release images; the floating `latest` tag
is for development only.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. Do not open
a public issue containing exploit details, credentials, tenant data, or
production topology. Include affected versions, prerequisites, impact, and a
minimal reproduction when possible.

We aim to acknowledge reports within three business days. Disclosure timing
is coordinated after a fix and release are available.

## Deployment boundary

Treat sandbox workloads as hostile. Shared deployments must use a hardened
RuntimeClass such as gVisor or Kata, namespace-scoped worker RBAC, deny-by-
default network policy, immutable images, and credentials scoped to their
principal and resource. The default development manifests are not a security
certification for a particular cluster or CNI.

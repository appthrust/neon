# AppThrust compute image

`appthrust/main` is upstream `298a0f88a1` plus the reviewed `compute_ctl`
changes for least-privilege service roles (`restricted_roles`). This
directory builds the only image published from it:
`ghcr.io/appthrust/platform/neon-compute:<run_id>-bullseye`.

- **Writer:** `.github/workflows/appthrust-compute-image.yml`. It runs only by
  `workflow_dispatch` on `appthrust/main`. It is declared in appthrust/platform
  `hack/ghcr-external-writers.yaml` (ADR-0091).
- **Shape:** the pinned GA compute image
  (`ghcr.io/appthrust/platform/neon-ga/neon-compute-node-v16@sha256:b9e15f77…`)
  with `/usr/local/bin/compute_ctl` replaced by this commit's build. The
  binary comes from upstream `compute/compute-node.Dockerfile` stage
  `compute-tools`, built with Debian bullseye.
- **Evidence:** the manifest annotations `org.opencontainers.image.base.*` and
  `org.opencontainers.image.revision`, a keyless signature by the workflow
  identity, and a build-provenance attestation.
- **Release:** the platform promotion verifies that evidence against the
  declared identity, copies the image, and signs the copy with the platform
  identity. Clusters never pull this repository directly.

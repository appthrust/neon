# Bake definition for the AppThrust compute image (platform ADR-0091).

variable "RUN_ID" {}
variable "GIT_SHA" {}

variable "IMAGE" {
  default = "ghcr.io/appthrust/platform/neon-compute"
}

# The GA compute image currently pinned by the platform release. Its digest is
# the upstream ghcr.io/neondatabase/compute-node-v16:17202196755-bullseye
# digest (source revision 298a0f88a1, the fork's base commit).
variable "BASE_IMAGE_NAME" {
  default = "ghcr.io/appthrust/platform/neon-ga/neon-compute-node-v16"
}

variable "BASE_IMAGE_DIGEST" {
  default = "sha256:b9e15f77412bc82b5dae9033d25c79ebdb0faf43be4f9e79f52d5d04a942a59c"
}

target "compute-tools" {
  context    = "."
  dockerfile = "compute/compute-node.Dockerfile"
  target     = "compute-tools"
  platforms  = ["linux/amd64"]
  args = {
    DEBIAN_VERSION = "bullseye"
    BUILD_TAG      = "${RUN_ID}"
  }
}

target "neon-compute" {
  context    = "compute/appthrust"
  dockerfile = "overlay.Dockerfile"
  platforms  = ["linux/amd64"]
  contexts = {
    compute-tools = "target:compute-tools"
  }
  args = {
    BASE_IMAGE = "${BASE_IMAGE_NAME}@${BASE_IMAGE_DIGEST}"
  }
  tags = ["${IMAGE}:${RUN_ID}-bullseye"]
  annotations = [
    "manifest:org.opencontainers.image.base.name=${BASE_IMAGE_NAME}",
    "manifest:org.opencontainers.image.base.digest=${BASE_IMAGE_DIGEST}",
    "manifest:org.opencontainers.image.revision=${GIT_SHA}",
  ]
  # One image manifest; provenance is attested separately by the workflow.
  attest = [
    "type=provenance,disabled=true",
    "type=sbom,disabled=true",
  ]
}

# AppThrust compute image: the pinned upstream compute image with this
# branch's compute_ctl. Built by .github/workflows/appthrust-compute-image.yml
# through docker-bake.hcl; the compute-tools context is the upstream
# compute/compute-node.Dockerfile stage of the same commit.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY --from=compute-tools --chown=postgres /home/nonroot/target-bin/compute_ctl /usr/local/bin/compute_ctl

# The detection lab's run-driver image, ghcr.io/hubertmj/detection-lab/lab-runner: the python
# generator/validator (lab/) in a minimal, nonroot, read-only-root container. A cluster CronJob runs
# it once a day to drive one real run end to end (generate -> index -> poll -> validate -> publish).
# Built, Trivy-gated, SBOM'd and cosign-signed by .github/workflows/build-runner.yml, the same
# pipeline as the web image; self-defending-portfolio's Kyverno admits it only with a signature whose
# identity is that workflow on main.
#
# Base: python on Alpine, pinned by tag *and* digest (a tag is mutable, a digest is not), and patched
# in place from Alpine's repositories like the web image (distroless/python3-debian12 was dropped: its
# Debian base carried fixable HIGH CVEs that Trivy gates on and a distroless image has no package
# manager to patch them). run.py is standard library only, so pip and setuptools are removed (they
# carried the only remaining fixable HIGH findings and nothing here needs them). Every endpoint, index,
# id and certificate reaches run.py through the environment or arguments the CronJob sets.
FROM python:3.13-alpine@sha256:2d9aefe2fef018a7eb2c13064c89c71929800fd2e5dccdbf52ea5da5bb8d929a

# Patch the base in place, then strip pip/setuptools/ensurepip (unused; their CVEs would fail Trivy).
RUN apk --no-cache upgrade \
 && python3 -m pip uninstall -y pip setuptools 2>/dev/null; \
    rm -rf /usr/local/lib/python3.*/ensurepip \
           /usr/local/lib/python3.*/site-packages/pip* \
           /usr/local/lib/python3.*/site-packages/setuptools* \
           /usr/local/bin/pip*; \
    true

WORKDIR /app

# Only the generator/validator/driver. No tests, no web app, no git metadata.
COPY lab/ /app/lab/

# 65532 (nonroot) is asserted by the CronJob's securityContext.
USER 65532

LABEL org.opencontainers.image.title="detection-lab runner" \
      org.opencontainers.image.description="Drives one real detection-lab run (generate, index, poll, validate, publish); python stdlib only, nonroot" \
      org.opencontainers.image.source="https://github.com/HubertMJ/detection-lab" \
      org.opencontainers.image.licenses="MIT"

# The driver is the process. Arguments beyond this (or the LAB_* environment) come from the CronJob.
ENTRYPOINT ["python3", "/app/lab/run.py"]

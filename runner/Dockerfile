# The detection lab's run-driver image, ghcr.io/hubertmj/detection-lab/lab-runner: the python
# generator/validator (lab/) in a minimal, nonroot, read-only-root container. A cluster CronJob runs
# it once a day to drive one real run end to end (generate -> index -> poll -> validate -> publish).
# Built, Trivy-gated, SBOM'd and cosign-signed by .github/workflows/build-runner.yml, the same
# pipeline as the web image; self-defending-portfolio's Kyverno admits it only with a signature whose
# identity is that workflow on main.
#
# The base is pinned by tag *and* digest (a tag is mutable, a digest is not). Distroless python3 has
# no shell and no package manager, so the attack surface is tiny; run.py is standard library only, so
# nothing else need be installed. Every endpoint, index, id and certificate reaches run.py through
# the environment or arguments the CronJob sets; nothing is baked in.

# gcr.io/distroless/python3-debian12:nonroot (nonroot = uid 65532, no shell).
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5

WORKDIR /app

# Only the generator/validator/driver. No tests, no web app, no git metadata.
COPY lab/ /app/lab/

# Already nonroot in the base; stated so the Deployment/CronJob can assert the uid.
USER 65532

LABEL org.opencontainers.image.title="detection-lab runner" \
      org.opencontainers.image.description="Drives one real detection-lab run (generate, index, poll, validate, publish); python stdlib only, nonroot" \
      org.opencontainers.image.source="https://github.com/HubertMJ/detection-lab" \
      org.opencontainers.image.licenses="MIT"

# The driver is the process. Arguments beyond this (or the LAB_* environment) come from the CronJob.
ENTRYPOINT ["python3", "/app/lab/run.py"]

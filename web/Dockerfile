# The image behind https://hubertjablon.ski/lab/, ghcr.io/hubertmj/detection-lab/lab: the detection
# lab's web preview, served by nginx-unprivileged on :8080. Built, scanned, SBOM'd and signed by
# .github/workflows/build-image.yml; the cluster's Kyverno refuses to admit it unsigned. The generator
# (lab/, python) lives in the same repository but is not part of this image.
#
# Two stages. The first compiles TypeScript and CSS into content-hashed static files under /lab/ and
# runs the unit tests, so an image cannot be built from code whose tests fail. Nothing from it reaches
# the final image except dist/: no node, no node_modules, no npm, no sources. The second stage is the
# nginx-unprivileged base. Both bases are pinned by tag *and* digest.

FROM node:22.22.0-alpine3.23@sha256:e4bf2a82ad0a4037d28035ae71529873c069b13eb0455466ae0bc13363826e34 AS build

WORKDIR /src
# Lockfile first so the dependency layer is cached until the lockfile changes. `npm ci` installs
# exactly what package-lock.json records (integrity hashes included) and fails if it is out of date.
# --ignore-scripts: no install hook of any dependency runs here; esbuild ships its native binary
# as an optional dependency and needs no postinstall.
COPY package.json package-lock.json ./
RUN PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci --ignore-scripts --no-audit --no-fund

COPY tsconfig.json vitest.config.ts ./
COPY scripts/ scripts/
COPY src/ src/
COPY static/ static/
COPY test/unit/ test/unit/
RUN npm run lint && npm test && npm run build

# nginx-unprivileged rather than nginx because the stock image starts as root to bind :80, which
# PSS `restricted` forbids.
FROM nginxinc/nginx-unprivileged:1.31.6-alpine@sha256:26b0bf6fbf07297983cb341998d79c831508787de26627dd2a112321b9c3a4af

# Build-time only; the running container never reads these. USER is restored below.
USER root

# The pinned base ships pcre2 10.48-r0, tiff 4.7.1-r0, libexpat 2.8.5-r0 and libx11 1.8.13-r0, which
# Trivy gates on CVE-2026-103111 (HIGH, fixed in pcre2 10.49-r0), CVE-2026-4775 (HIGH, fixed in tiff
# 4.7.2-r0), CVE-2026-77214 (HIGH, fixed in libexpat 2.9.0-r0) and CVE-2026-88806 (HIGH, fixed in
# libx11 1.8.14-r0). Upgraded in place from Alpine's repositories until the next base-image bump
# carries the fixes; then this line goes.
# brotli-libs 1.2.0-r1 too: CVE-2026-111497 (HIGH, fixed in 1.2.1-r0), the same way.
RUN apk --no-cache upgrade pcre2 tiff libexpat libx11 brotli-libs

# Our nginx.conf includes no conf.d, so the shipped default vhost is dead config. It is removed
# rather than left in place because the base image's 10-listen-on-ipv6-by-default.sh entrypoint
# edits that file in place at startup, which a read-only root filesystem would reject.
RUN rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf
COPY security-headers.conf /etc/nginx/security-headers.conf
COPY --from=build /src/dist/ /usr/share/nginx/html/

# The commit and the Actions run this image was built from (build-image.yml passes github.sha and
# github.run_id), served as /lab/build.json. Declared here, after the package upgrade and the bundle
# copy, so a new commit invalidates only this layer and the ones after it. A value of the wrong shape
# is written as "" rather than trusted. A local build without the arguments publishes empty strings.
ARG GIT_SHA=""
ARG CI_RUN_ID=""
RUN commit=""; run=""; \
    case "$GIT_SHA" in *[!0-9a-f]*) ;; *) if [ "${#GIT_SHA}" -eq 40 ]; then commit=$GIT_SHA; fi ;; esac; \
    case "$CI_RUN_ID" in *[!0-9]*) ;; *) if [ "${#CI_RUN_ID}" -ge 1 ] && [ "${#CI_RUN_ID}" -le 20 ]; then run=$CI_RUN_ID; fi ;; esac; \
    printf '{"commit":"%s","ci_run_id":"%s"}\n' "$commit" "$run" > /usr/share/nginx/html/lab/build.json

# Owned by root, readable by all: the content must not be writable by the uid serving it.
RUN chown -R root:root /usr/share/nginx/html \
 && chmod -R a=rX /usr/share/nginx/html \
 && chmod a=r /etc/nginx/nginx.conf /etc/nginx/security-headers.conf

# 101 is the `nginx` user baked into the base image; the Deployment asserts the same uid.
USER 101

EXPOSE 8080

LABEL org.opencontainers.image.title="detection-lab web" \
      org.opencontainers.image.description="The detection lab's web preview, served by nginx-unprivileged on :8080 under /lab/" \
      org.opencontainers.image.source="https://github.com/HubertMJ/detection-lab" \
      org.opencontainers.image.licenses="MIT"

# nginx runs in the foreground: the container must be the process, not its supervisor.
CMD ["nginx", "-g", "daemon off;"]

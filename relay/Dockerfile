# syntax=docker/dockerfile:1
# A Colophon 0.5 home: the reference relay (Bun) with the Rust home module, configured by
# environment variables, everything it keeps under the volume /data. See
# docs/self-hosting/docker.md.
#
#   docker build -f relay/Dockerfile -t colophon-home .        (from the repository root)
#
# Multi-arch: neither stage has an architecture-specific step, and both base images are published
# for amd64 and arm64. The build stage names no platform, so it also builds with the legacy
# builder (no BuildKit), which sets no BUILDPLATFORM. Built on amd64 and on arm64.

# --- Stage 1: the home module (wasm32), with the toolchain the release uses. ---
FROM rust:1.99.1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS module
RUN rustup target add wasm32-unknown-unknown
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --target wasm32-unknown-unknown --release -p colophon-home-wasm \
 && mkdir -p /out/app /out/data \
 && cp target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm /out/app/ \
 && chmod 0644 /out/app/colophon_home_wasm.wasm \
 && chown 65532:65532 /out/data && chmod 0700 /out/data
COPY relay/*.js relay/package.json /out/app/
RUN chmod 0644 /out/app/*

# --- Stage 2: Bun and the relay's files only. No shell, no package manager. ---
FROM oven/bun:1.4.5-distroless@sha256:3a210956422ad81cf7532e1fc1f2eb9275d6ef4c2337a9d25d530f798e80726a
# Code and module are root's and read-only to the relay; only /data is its own.
COPY --from=module /out/app /app
COPY --from=module --chown=65532:65532 /out/data /data
USER 65532:65532
WORKDIR /data
ENV PORT=8080 COLOPHON_DATA=/data NODE_ENV=production
# No VOLUME instruction: Railway refuses a Dockerfile that has one, and every guide mounts /data
# by name. Without a mount, what the home keeps is lost with the container.
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/bun", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["/usr/local/bin/bun", "/app/container-entry.js"]

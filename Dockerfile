# syntax=docker/dockerfile:1

# Keystone Vault ships as one executable with the Angular console compiled into it, so this builds
# one small image with no web server or runtime beside it.

# ---------------------------------------------------------------------------------------------
# 1. Console
# ---------------------------------------------------------------------------------------------
FROM node:24-alpine AS console
WORKDIR /build
# The console depends on the vendored Portal SSO browser SDK.
COPY packages/portal-sso/ packages/portal-sso/
COPY ui/package.json ui/package-lock.json ui/
RUN cd ui && npm ci
COPY ui/ ui/
RUN cd ui && npm run build

# ---------------------------------------------------------------------------------------------
# 2. Server, with the console embedded
# ---------------------------------------------------------------------------------------------
FROM rust:1-bookworm AS server
WORKDIR /build
ARG KEYSTONE_VERSION
ENV KEYSTONE_VERSION=${KEYSTONE_VERSION}
# Dependencies first, so a source change does not rebuild the whole dependency tree.
COPY Cargo.toml Cargo.lock ./
COPY back/Cargo.toml back/
RUN mkdir -p back/src && echo 'fn main() {}' > back/src/main.rs && echo '' > back/src/lib.rs \
    && cargo build --release -p keystone && rm -rf back/src
COPY back/ back/
# The license is compiled in (it is shown in first-time setup).
COPY LICENSE ./
COPY --from=console /build/ui/dist/ ui/dist/
RUN touch back/src/main.rs back/src/lib.rs && cargo build --release -p keystone \
    && mkdir -p /out/var/lib/keystone && cp target/release/keystone /out/keystone

# ---------------------------------------------------------------------------------------------
# 3. Runtime: glibc + CA certificates, no shell, non-root
# ---------------------------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=server /out/keystone /usr/local/bin/keystone
COPY --from=server --chown=65532:65532 /out/var/lib/keystone /var/lib/keystone
ENV KEYSTONE_HOME=/var/lib/keystone \
    KEYSTONE_SERVER_ADDRESS=0.0.0.0 \
    KEYSTONE_SERVER_PORT=8090
VOLUME ["/var/lib/keystone"]
EXPOSE 8090
USER 65532:65532
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/keystone", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/keystone"]
CMD ["serve"]

# Kubera container image.
#
#   docker build -t kubera .
#   docker run --rm -v "$PWD:/scan" kubera scan git /scan
#   docker run --rm kubera scan image alpine:3.20
#
# Release images (ghcr.io/dmdhrumilmistry/kubera) are built by the release
# workflow from the same static binaries as the GitHub release, using the
# `prebuilt` stage below.

# --- build from source (default) -------------------------------------------
FROM rust:1.88-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked && cp target/release/kubera /kubera

# --- runtime ----------------------------------------------------------------
FROM alpine:3.20 AS runtime
# git: history scans shell out to it. ca-certificates: TLS verification uses
# the system trust store.
RUN apk add --no-cache git ca-certificates \
    && adduser -D -u 10001 -h /home/kubera kubera \
    # Mounted repositories belong to another uid; without this git refuses
    # them ("dubious ownership"). kubera already runs git with hooks,
    # fsmonitor, external diff and textconv disabled.
    && printf '[safe]\n\tdirectory = *\n' > /home/kubera/.gitconfig \
    && chown kubera:kubera /home/kubera/.gitconfig
USER kubera
WORKDIR /scan
ENTRYPOINT ["kubera"]
CMD ["--help"]

# --- release image from a prebuilt static binary ----------------------------
FROM runtime AS prebuilt
ARG TARGETARCH
COPY --chmod=0755 dist/linux-${TARGETARCH}/kubera /usr/local/bin/kubera

FROM runtime
COPY --from=build /kubera /usr/local/bin/kubera

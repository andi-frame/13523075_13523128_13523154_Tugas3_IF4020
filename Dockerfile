# syntax=docker/dockerfile:1
# Release image: the CLI and all runtime dependencies, no build tools, no keys.
#   docker run --rm <image> <subcommand> ...

ARG PYTHON_IMAGE=python:3.13-slim-bookworm

FROM ghcr.io/astral-sh/uv:0.13.4 AS uv

FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
# Dependencies first (cached layer), then the project itself as a non-editable install.
COPY pyproject.toml uv.lock .python-version README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM ${PYTHON_IMAGE}
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="if4020-signing" \
      org.opencontainers.image.description="Release artifact signing and verification CLI (RSA-PSS, ECDSA P-256, Ed25519)" \
      org.opencontainers.image.source="https://github.com/DaDecky/13523075_13523128_13523154_Tugas3_IF4020" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Any runner UID/GID may be supplied with --user; this is only the default.
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["if4020-signing"]
CMD ["--help"]

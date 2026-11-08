# syntax=docker/dockerfile:1

# ---- builder: compile the yar2sig binary ----
FROM rust:1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY mappings ./mappings
COPY static ./static
RUN cargo build --release --locked

# ---- runtime: python image for sigma-cli + backend plugins, run as non-root ----
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159 AS runtime
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    YAR2SIG_SIGMA_CONCURRENCY=2
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt
COPY --from=builder /app/target/release/yar2sig /usr/local/bin/yar2sig
COPY samples ./samples

# non-root user
RUN useradd -r -u 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

# YAR2SIG_SIGMA_CONCURRENCY caps concurrent sigma-cli subprocesses (busy -> 503)
CMD ["yar2sig", "serve", "--host", "0.0.0.0", "--port", "8000"]

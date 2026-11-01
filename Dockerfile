# syntax=docker/dockerfile:1

# ---- builder: install deps into a venv ----
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159 AS builder
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install -r requirements.txt

# ---- runtime: copy venv + app, run as non-root ----
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159 AS runtime
ENV PATH="/opt/venv/bin:$PATH" \
    HOME=/tmp \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    YAR2SIG_SIGMA_CONCURRENCY=1
WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY yar2sig ./yar2sig
COPY static ./static
COPY samples ./samples
COPY app.py ./

# non-root user
RUN useradd -r -u 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

# 2 workers x 4 threads; YAR2SIG_SIGMA_CONCURRENCY caps sigma-cli subprocesses per worker (busy -> 503)
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", \
     "--timeout", "60", "--access-logfile", "-", "app:app"]

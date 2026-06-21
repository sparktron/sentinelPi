# =============================================================================
# SentinelPi container image
# =============================================================================
# Multi-stage build: compile a wheel, then install it into a slim runtime image
# that runs as a non-root user. For packet capture, start the container with
# `--cap-add NET_RAW --cap-add NET_ADMIN` and host networking (see
# docker-compose.yml / the README): Docker grants those capabilities directly to
# the non-root process, so it never needs to run as root. Without them the app
# falls back to /proc polling. (No file capabilities are baked in — a file cap
# outside the container's bounding set would block exec on a plain `docker run`.)
# -----------------------------------------------------------------------------

FROM python:3.12-slim AS builder
WORKDIR /build
# Only what the build backend needs to produce the wheel.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist

# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Dedicated unprivileged runtime user.
RUN useradd --system --create-home --home-dir /opt/sentinelpi \
    --shell /usr/sbin/nologin sentinelpi

# Install the built wheel (pulls runtime deps from the wheel metadata).
COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Default config baked in; override by mounting your own at this path.
COPY config/sentinelpi.yaml /etc/sentinelpi/sentinelpi.yaml

# Writable state/log dirs owned by the runtime user.
RUN mkdir -p /var/lib/sentinelpi /var/log/sentinelpi \
    && chown -R sentinelpi:sentinelpi /var/lib/sentinelpi /var/log/sentinelpi /etc/sentinelpi

ENV SENTINELPI_CONFIG=/etc/sentinelpi/sentinelpi.yaml \
    PYTHONUNBUFFERED=1

# Dashboard (informational under host networking).
EXPOSE 8888

USER sentinelpi
WORKDIR /opt/sentinelpi

# Fail fast on a bad config before the daemon claims to be healthy.
HEALTHCHECK --interval=60s --timeout=10s --start-period=20s --retries=3 \
    CMD sentinelpi --check-config || exit 1

ENTRYPOINT ["sentinelpi"]
CMD ["--config", "/etc/sentinelpi/sentinelpi.yaml"]

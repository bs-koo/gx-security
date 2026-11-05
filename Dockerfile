FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337 AS runtime-deps
ENV PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
    HOME=/tmp/gxsec-home GXSEC_PLUGIN_ROOT=/opt/gx-security
WORKDIR /opt/gx-security
COPY runtime/engines.lock.json runtime/engines.lock.json
COPY scripts/install-engines.py scripts/install-engines.py
RUN python scripts/install-engines.py --output /usr/local/bin
COPY requirements-bundle.lock requirements-bundle.lock
RUN pip install --no-cache-dir --require-hashes -r requirements-bundle.lock
RUN apt-get update && apt-get install -y --no-install-recommends git=1:2.39.5-0+deb12u3 && \
    rm -rf /var/lib/apt/lists/*
ENV GXSEC_RUNTIME_MANIFEST=/opt/gx-security/runtime/tool-provenance.json
FROM runtime-deps AS release
COPY . .
RUN pip install --no-deps --no-build-isolation . && \
    python scripts/record-runtime.py --output /opt/gx-security/runtime/tool-provenance.json && \
    mkdir -p /results /tmp/gxsec-home && chmod 1777 /results /tmp/gxsec-home
WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["gxsec"]
CMD ["doctor", "--source", "/workspace", "--json"]

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG INSTALL_QEMU=0
ARG INSTALL_GHIDRA=0
ARG GHIDRA_VERSION=12.0.4
ARG GHIDRA_RELEASE_DATE=20260303

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       binwalk \
       ca-certificates \
       curl \
       file \
       git \
       openjdk-21-jre-headless \
       squashfs-tools \
       unzip \
    && if [ "$INSTALL_QEMU" = "1" ]; then \
       apt-get install -y --no-install-recommends \
       qemu-system-arm \
       qemu-user \
       qemu-utils; \
    fi \
    && if [ "$INSTALL_GHIDRA" = "1" ]; then \
       curl -fsSL \
       "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE_DATE}.zip" \
       -o /tmp/ghidra.zip \
       && unzip -q /tmp/ghidra.zip -d /opt \
       && ln -sf "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC/support/analyzeHeadless" /usr/local/bin/analyzeHeadless \
       && rm -f /tmp/ghidra.zip; \
    fi \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY references ./references
COPY samples ./samples

RUN pip install --no-cache-dir -e .

CMD ["firmware-mvp", "--help"]

FROM base AS dev

ARG INSTALL_QILING=0

COPY tests ./tests
COPY schemas ./schemas
COPY docs ./docs
COPY DEVELOPMENT_CHECKLIST.md ./

RUN pip install --no-cache-dir -e ".[dev]" \
    && if [ "$INSTALL_QILING" = "1" ]; then \
       pip install --no-cache-dir -e ".[qiling]"; \
    fi

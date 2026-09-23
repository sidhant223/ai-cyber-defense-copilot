# Run the scanner without installing Python:
#
#   docker build -t copilot .
#   docker run --rm -v "$PWD:/repo:ro" copilot scan .
#   docker run --rm -v "$PWD:/repo:ro" copilot scan . --format sarif > copilot.sarif
#
# The repository is mounted read-only on purpose: this tool reads code, runs
# nothing and writes nothing, and the container should not be able to either.
FROM python:3.12-slim

# Install from the source tree rather than an index: there is no published
# package, and pinning a copy here keeps the image reproducible.
WORKDIR /opt/copilot
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache

# Scans happen against whatever is mounted here.
WORKDIR /repo

# Unbuffered, UTF-8 output so the summary line survives a CI log.
ENV PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8

ENTRYPOINT ["copilot"]
CMD ["scan", "."]

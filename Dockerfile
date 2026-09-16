# Development/test image for ipa-diagnose. Not used for production installs
# (that path is the RPM built in packaging/rpm/). This image never touches
# the host - it only builds/runs the project inside the container.
FROM python:3.11-slim

# libcairo2 is only needed for scripts/capture_screenshots.py (SVG->PNG via
# cairosvg) - not a runtime dependency of ipa-diagnose itself.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        build-essential \
        libcairo2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir -e ".[dev,ai]"

COPY . .

CMD ["bash"]

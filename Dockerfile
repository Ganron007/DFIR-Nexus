# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies useful for forensic parsing
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy package metadata and install Python dependencies
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir -e ".[all]"

# Copy the rest of the application (docs, scripts, data, etc.)
COPY . .

# Expose the HTTP MCP + Examiner Portal port
EXPOSE 4508

# Default: run the HTTP MCP server
ENTRYPOINT ["nexus"]
CMD ["serve", "--http", "--port", "4508"]

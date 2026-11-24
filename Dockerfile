# syntax=docker/dockerfile:1
FROM node:22-slim AS frontend-builder

WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

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

# Copy the rest of the application (docs, scripts, data, etc.) and built SPA bundle
COPY . .
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist

# Expose the HTTP MCP + Examiner Portal port
EXPOSE 4508

# Default: run the HTTP MCP + Portal server (set NEXUS_PORTAL_PASSWORD and NEXUS_BEARER_TOKEN on 0.0.0.0)
ENTRYPOINT ["nexus"]
CMD ["serve", "--http", "--host", "0.0.0.0", "--port", "4508"]

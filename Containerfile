# Stage 1: Builder

FROM python:3.10-slim AS builder

# Prevent .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install uv
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir uv

# Copy project files
COPY . .

# Step 1: Sync dependencies (creates venv automatically if not exists)
RUN uv sync

# Step 2: Build the project (wheel + sdist)
RUN uv build

# Step 3: Install the built wheel into the venv created by uv sync
RUN uv pip install --no-cache-dir dist/*.whl

# Stage 2: Runtime

FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 
    
WORKDIR /app

# Copy only the virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Add venv binaries to PATH
ENV PATH="/app/.venv/bin:$PATH"

# Set entrypoint to your script
ENTRYPOINT ["sbom"]
CMD ["--help"]

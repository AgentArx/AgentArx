FROM python:3.11-slim

# Update package lists and install basic dependencies first
RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security and configure sudo
RUN useradd --create-home --shell /bin/bash agentarx && \
    usermod -aG sudo agentarx && \
    echo "agentarx ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Install development and troubleshooting tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    nano \
    git \
    htop \
    tree \
    jq \
    procps \
    lsof \
    && rm -rf /var/lib/apt/lists/*

# Install network tools (some may not be available in all base images)
RUN apt-get update && apt-get install -y --no-install-recommends \
    net-tools \
    iputils-ping \
    dnsutils \
    gnupg \
    nmap \
    netcat-openbsd \
    telnet \
    && rm -rf /var/lib/apt/lists/* || true

WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code (prompts now in src/agentarx/config/prompts/)
COPY --chown=agentarx:agentarx src/ ./src/
COPY --chown=agentarx:agentarx attack_scenarios/ ./attack_scenarios/
COPY --chown=agentarx:agentarx tests/ ./tests/

# Create results and logs directories
RUN mkdir -p /app/results /app/logs && chown agentarx:agentarx /app/results /app/logs

# Switch to non-root user
USER agentarx

# Set Python path
ENV PYTHONPATH=/app/src

# Expose ports for external services access
EXPOSE 8080
EXPOSE 3301
EXPOSE 11434
EXPOSE 5000

# Set working directory and drop to shell by default
CMD ["/bin/bash"]
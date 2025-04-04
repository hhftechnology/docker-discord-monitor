# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set metadata labels
LABEL maintainer="HHF Technology <discourse@hhf.technology>"
LABEL description="Docker container event monitoring with Discord notifications"
LABEL version="1.0"

# Set the working directory in the container
WORKDIR /app

# Install system dependencies including Docker CLI
# This is needed for the docker-py library to communicate with the Docker daemon
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    lsb-release \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the script and default config
COPY docker_monitor.py .
COPY config.json .

# Create a volume for persistent logging
VOLUME /app/logs

# Set environment variables (can be overridden at runtime)
ENV CONFIG_PATH=/app/config.json
ENV LOG_LEVEL=INFO

# Run the script
CMD ["python", "docker_monitor.py", "--config", "${CONFIG_PATH}"]

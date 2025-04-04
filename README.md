# Docker Discord Event  Monitor

A Docker container monitoring tool that sends notifications to Discord when container events occur or resource usage exceeds defined thresholds.

## Features

- **Event Monitoring**: Detects container start, stop, restart, and failure events
- **Resource Monitoring**: Alerts on high CPU and memory usage
- **Customizable Notifications**: Configurable Discord webhook notifications with rich embeds
- **Container Filtering**: Monitor only specific containers based on names or labels
- **Rate Limiting**: Prevents notification spam during container issues
- **Detailed Container Information**: Provides context about containers in notifications
- **Exit Code Information**: Human-readable explanations for container exit codes

## Setup

### Prerequisites

- Docker and Docker Compose
- Discord webhook URL (create one in your Discord server settings)

### Configuration

1. Edit the `config.json` file with your Discord webhook URL and desired settings

```json
{
  "webhook_url": "YOUR_DISCORD_WEBHOOK_URL",
  "events": {
    "start": {
      "title": "🚀 Container Started: {name}",
      "description": "The container '{name}' has started successfully.",
      "color": 3066993
    },
    ...
  },
  ...
}
```

### Running with Docker

Build and run the container using Docker Compose:

```bash
docker compose up -d
```

Or manually with Docker:

```bash
docker build -t docker-monitor .
docker run -d \
  --name docker-monitor \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/config.json:/app/config.json:ro \
  -v $(pwd)/logs:/app/logs \
  docker-monitor
```

## Security Considerations

This container requires access to the Docker socket (`/var/run/docker.sock`) to monitor events. This gives the container significant privileges on your host system. Always:

- Use read-only access to the Docker socket when possible
- Run the container with the minimum required privileges
- Keep the container updated and secure

## Logging

Logs are written to both the console and `/app/logs/docker_monitor.log` file, which is persisted via a volume mount.

## Troubleshooting

- **No notifications**: Check the webhook URL and container logs
- **Missing events**: Ensure the event types are defined in your config.json
- **Access errors**: Verify Docker socket permissions

## License

MIT License

import docker
import requests
import json
import time
import logging
import argparse
import os
import signal
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("docker_monitor.log")
    ]
)
logger = logging.getLogger("DockerMonitor")

class DockerMonitor:
    def __init__(self, config_path: str):
        """Initialize the Docker monitor with the given configuration file."""
        self.config_path = config_path
        self.config = self._load_config()
        self.validate_config()
        
        # Connect to Docker
        try:
            self.client = docker.from_env()
            logger.info("Successfully connected to Docker daemon")
        except docker.errors.DockerException as e:
            logger.error(f"Failed to connect to Docker daemon: {e}")
            sys.exit(1)
        
        # Initialize event counters for rate limiting
        self.event_counters = {}
        self.last_notification_time = {}
        
        # Flag to control monitoring loop
        self.running = True
        
        # Resource monitoring thread
        self.resource_monitor_thread = None
        if self.config.get('monitor_resources', False):
            self.resource_monitor_thread = threading.Thread(
                target=self.monitor_container_resources
            )

    def _load_config(self) -> Dict:
        """Load configuration from the JSON file."""
        try:
            with open(self.config_path, 'r') as config_file:
                config = json.load(config_file)
                logger.info(f"Configuration loaded from {self.config_path}")
                return config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {self.config_path}")
            sys.exit(1)
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in configuration file: {self.config_path}")
            sys.exit(1)

    def validate_config(self) -> None:
        """Validate the configuration structure."""
        required_keys = ['webhook_url', 'events']
        missing_keys = [key for key in required_keys if key not in self.config]
        
        if missing_keys:
            logger.error(f"Missing required configuration keys: {', '.join(missing_keys)}")
            sys.exit(1)
            
        # Set default values for optional configuration
        if 'container_filters' not in self.config:
            self.config['container_filters'] = {}
            
        if 'rate_limit' not in self.config:
            self.config['rate_limit'] = {
                'enabled': False,
                'max_events': 5,
                'time_window': 60
            }
            
        if 'monitor_resources' not in self.config:
            self.config['monitor_resources'] = False
            
        if 'resource_check_interval' not in self.config:
            self.config['resource_check_interval'] = 300  # 5 minutes
            
        if 'resource_thresholds' not in self.config:
            self.config['resource_thresholds'] = {
                'cpu_percent': 90,
                'memory_percent': 90
            }
        
        logger.info("Configuration validation successful")

    def should_process_container(self, container_name: str, labels: Dict) -> bool:
        """Check if the container should be processed based on filters."""
        filters = self.config['container_filters']
        
        # If no filters are specified, process all containers
        if not filters:
            return True
            
        # Check include/exclude patterns for container names
        if 'include_names' in filters:
            if not any(pattern in container_name for pattern in filters['include_names']):
                return False
                
        if 'exclude_names' in filters:
            if any(pattern in container_name for pattern in filters['exclude_names']):
                return False
                
        # Check labels
        if 'labels' in filters:
            for key, value in filters['labels'].items():
                if key not in labels or labels[key] != value:
                    return False
                    
        return True

    def check_rate_limit(self, container_name: str, action: str) -> bool:
        """Check if an event should be rate-limited."""
        if not self.config['rate_limit']['enabled']:
            return False
            
        current_time = time.time()
        event_key = f"{container_name}:{action}"
        
        # Initialize counters if this is the first event
        if event_key not in self.event_counters:
            self.event_counters[event_key] = 0
            self.last_notification_time[event_key] = 0
            
        # Check if we're within the time window
        time_window = self.config['rate_limit']['time_window']
        if current_time - self.last_notification_time[event_key] > time_window:
            # Reset counter if the time window has passed
            self.event_counters[event_key] = 0
            
        # Increment counter
        self.event_counters[event_key] += 1
        
        # Check if we've exceeded the maximum number of events
        max_events = self.config['rate_limit']['max_events']
        if self.event_counters[event_key] > max_events:
            # Only log once per time window
            if self.event_counters[event_key] == max_events + 1:
                logger.info(f"Rate limit exceeded for {event_key}, suppressing notifications")
            return True
            
        # Update the last notification time
        self.last_notification_time[event_key] = current_time
        return False

    def send_discord_embed(self, webhook_url: str, title: str, description: str, 
                         color: int, fields: List[Dict], footer: Optional[str] = None) -> None:
        """Send an embed message to Discord."""
        embed = {
            "title": title,
            "description": description,
            "color": color,
            "fields": fields,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if footer:
            embed["footer"] = {"text": footer}
            
        payload = {"embeds": [embed]}
        headers = {"Content-Type": "application/json"}
        
        try:
            response = requests.post(
                webhook_url, 
                data=json.dumps(payload), 
                headers=headers,
                timeout=10  # Add timeout to prevent hanging
            )
            if response.status_code == 204:
                logger.info(f"Message sent to Discord: {title}")
            else:
                logger.error(f"Failed to send message to Discord: {response.status_code} - {response.text}")
        except requests.RequestException as e:
            logger.error(f"Request exception when sending to Discord: {e}")

    def get_additional_container_info(self, container_id: str) -> Dict:
        """Get additional information about a container."""
        try:
            container = self.client.containers.get(container_id)
            container_info = {
                "image": container.image.tags[0] if container.image.tags else container.image.id,
                "created": container.attrs['Created'],
                "status": container.status,
                "ports": container.attrs['NetworkSettings']['Ports'] if 'Ports' in container.attrs['NetworkSettings'] else {},
            }
            return container_info
        except (docker.errors.NotFound, docker.errors.APIError) as e:
            logger.error(f"Failed to get container info for {container_id}: {e}")
            return {}

    def monitor_container_resources(self) -> None:
        """Monitor container resource usage and send alerts when thresholds are exceeded."""
        logger.info("Starting resource monitoring thread")
        
        while self.running:
            try:
                for container in self.client.containers.list():
                    container_name = container.name
                    
                    # Skip containers that don't match our filters
                    if not self.should_process_container(container_name, container.labels):
                        continue
                        
                    # Get container stats
                    stats = container.stats(stream=False)
                    
                    # Calculate CPU percentage
                    cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                               stats['precpu_stats']['cpu_usage']['total_usage']
                    system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                                 stats['precpu_stats']['system_cpu_usage']
                    cpu_percent = 0.0
                    if system_delta > 0 and cpu_delta > 0:
                        cpu_percent = (cpu_delta / system_delta) * len(stats['cpu_stats']['cpu_usage']['percpu_usage']) * 100.0
                    
                    # Calculate memory percentage
                    memory_usage = stats['memory_stats']['usage']
                    memory_limit = stats['memory_stats']['limit']
                    memory_percent = (memory_usage / memory_limit) * 100.0
                    
                    # Check thresholds
                    thresholds = self.config['resource_thresholds']
                    alerts = []
                    
                    if cpu_percent > thresholds['cpu_percent']:
                        alerts.append(f"CPU usage: {cpu_percent:.1f}% (threshold: {thresholds['cpu_percent']}%)")
                        
                    if memory_percent > thresholds['memory_percent']:
                        alerts.append(f"Memory usage: {memory_percent:.1f}% (threshold: {thresholds['memory_percent']}%)")
                        
                    # Send alerts if any thresholds are exceeded
                    if alerts and not self.check_rate_limit(container_name, "resource_alert"):
                        title = f"⚠️ Resource Alert: {container_name}"
                        description = f"Container '{container_name}' has exceeded resource thresholds."
                        
                        fields = [
                            {"name": "Alert Type", "value": "Resource Usage", "inline": True},
                            {"name": "Timestamp", "value": f"<t:{int(time.time())}>", "inline": True}
                        ]
                        
                        for alert in alerts:
                            fields.append({"name": "Issue", "value": alert, "inline": False})
                            
                        self.send_discord_embed(
                            self.config['webhook_url'],
                            title,
                            description,
                            15548997,  # Orange color
                            fields
                        )
                        
            except Exception as e:
                logger.error(f"Error in resource monitoring: {e}")
                
            # Sleep until next check
            time.sleep(self.config['resource_check_interval'])

    def process_event(self, event: Dict) -> None:
        """Process a Docker event and send a notification if needed."""
        if event['Type'] != 'container':
            return
            
        container_name = event['Actor']['Attributes']['name']
        container_id = event['Actor']['ID']
        action = event['Action']
        
        # Skip containers that don't match our filters
        if not self.should_process_container(container_name, event['Actor']['Attributes']):
            logger.debug(f"Skipping event for filtered container: {container_name}")
            return
            
        # Check if this event should be rate-limited
        if self.check_rate_limit(container_name, action):
            return
            
        # Check if the action is in the configuration
        if action in self.config['events']:
            event_config = self.config['events'][action]
            title = event_config['title'].format(name=container_name)
            description = event_config['description'].format(name=container_name)
            color = event_config['color']
            
            # Get additional container information
            container_info = self.get_additional_container_info(container_id)
            
            # Prepare fields for the embed
            fields = [
                {"name": "Event Type", "value": action, "inline": True},
                {"name": "Timestamp", "value": f"<t:{int(time.time())}>", "inline": True}
            ]
            
            # Add image information
            if 'image' in container_info:
                fields.append({"name": "Image", "value": container_info['image'], "inline": False})
                
            # Include custom fields if specified in the event config
            if 'custom_fields' in event_config:
                for field in event_config['custom_fields']:
                    fields.append({
                        "name": field['name'],
                        "value": field['value'].format(name=container_name, **event['Actor']['Attributes']),
                        "inline": field.get('inline', False)
                    })
                    
            # Include shutdown reason if the event is 'die'
            if action == 'die':
                # Get the exit code and reason
                exit_code = event['Actor']['Attributes'].get('exitCode', 'Unknown')
                
                # Try to get a more descriptive reason based on the exit code
                reason = f"Exited with code {exit_code}"
                
                # Common exit codes and their meanings
                exit_codes = {
                    "0": "Normal exit (success)",
                    "1": "General error",
                    "2": "Misuse of shell builtins",
                    "126": "Command invoked cannot execute",
                    "127": "Command not found",
                    "130": "Script terminated by Ctrl+C",
                    "137": "Container received SIGKILL (possibly OOM)",
                    "143": "Container received SIGTERM"
                }
                
                if exit_code in exit_codes:
                    reason += f" - {exit_codes[exit_code]}"
                    
                fields.append({"name": "Shutdown Reason", "value": reason, "inline": False})
                
            # Add a footer if specified in the config
            footer = None
            if 'footer' in event_config:
                footer = event_config['footer'].format(name=container_name)
                
            # Send the embed to Discord
            self.send_discord_embed(
                self.config['webhook_url'],
                title,
                description,
                color,
                fields,
                footer
            )

    def monitor_docker_events(self) -> None:
        """Monitor Docker events and process them."""
        logger.info("Starting Docker event monitoring")
        
        try:
            for event in self.client.events(decode=True):
                if not self.running:
                    break
                self.process_event(event)
        except docker.errors.APIError as e:
            logger.error(f"Docker API error: {e}")
            return
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down")
            self.shutdown()

    def shutdown(self) -> None:
        """Gracefully shut down the monitor."""
        logger.info("Shutting down Docker monitor")
        self.running = False
        
        if self.resource_monitor_thread and self.resource_monitor_thread.is_alive():
            self.resource_monitor_thread.join(timeout=5)
            
        logger.info("Docker monitor shut down successfully")

    def run(self) -> None:
        """Run the Docker monitor."""
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, lambda sig, frame: self.shutdown())
        signal.signal(signal.SIGTERM, lambda sig, frame: self.shutdown())
        
        # Start resource monitoring if enabled
        if self.resource_monitor_thread:
            self.resource_monitor_thread.daemon = True
            self.resource_monitor_thread.start()
            
        # Start event monitoring
        self.monitor_docker_events()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Docker Event Monitor for Discord Notifications')
    parser.add_argument('-c', '--config', default='config.json', 
                      help='Path to the configuration file (default: config.json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose logging')
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        
    # Create and run the monitor
    monitor = DockerMonitor(args.config)
    
    try:
        monitor.run()
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

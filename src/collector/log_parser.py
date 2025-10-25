import re
import ipaddress

def is_private_ip(ip_str):
    """Checks if an IP address string is in a private range."""
    try:
        ip = ipaddress.ip_network(ip_str, strict=False) # Use ip_network to handle CIDR
        # Check against known private ranges (RFC 1918)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def load_threat_feed(feed_path="data/firehol_level1.netset"):
    """
    Loads the FireHOL IP feed into a set, filtering out private IPs.
    Skips comments and empty lines.
    """
    malicious_ips = set()
    print(f"Loading threat feed from {feed_path}...")
    try:
        with open(feed_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Ignore comments and empty lines
                if line and not line.startswith("#"):
                    if not is_private_ip(line):
                        malicious_ips.add(line)

        print(f"Successfully loaded {len(malicious_ips)} public malicious IP entries.")
        return malicious_ips

    except FileNotFoundError:
        print(f"Error: Threat feed file not found at {feed_path}.")
        print("Please run 'python src/collector/feed_downloader.py' first.")
        return None
    except Exception as e:
        print(f"An error occurred while loading the feed: {e}")
        return None

def parse_server_log(log_path="data/sample_nginx.log"):
    """
    Parses a web server log file and extracts all unique visitor IP addresses.
    
    Returns:
        set: A set of unique IP addresses found in the log.
    """
    visitor_ips = set()
    print(f"Parsing server log: {log_path}...")
    
    # This regex is designed to find the first IP address at the start of each line
    ip_regex = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    
    try:
        with open(log_path, 'r') as f:
            for line in f:
                match = ip_regex.match(line)
                if match:
                    visitor_ips.add(match.group(1))
                    
        print(f"Found {len(visitor_ips)} unique visitor IPs in the log.")
        return visitor_ips
        
    except FileNotFoundError:
        print(f"Error: Server log file not found at {log_path}.")
        return None
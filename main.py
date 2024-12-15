#!/usr/bin/env python3

import socket
import ssl
import sys
import json
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import ipaddress
import time
from datetime import datetime

class NetworkUtilityClient:
    def __init__(self, 
                 host: str, 
                 port: int, 
                 use_ssl: bool = False, 
                 timeout: float = 10.0,
                 log_level: str = 'INFO'):
        """
        Initialize the Network Utility Client with configurable parameters.
        
        Args:
            host (str): Target server hostname or IP address
            port (int): Target server port
            use_ssl (bool): Enable SSL/TLS encryption
            timeout (float): Connection and read timeout in seconds
            log_level (str): Logging verbosity level
        """
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        # Validate input parameters
        self._validate_host(host)
        self._validate_port(port)

        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.socket = None

    def _validate_host(self, host: str):
        """
        Validate and sanitize host input.
        
        Supports:
        - IPv4 addresses
        - IPv6 addresses
        - Fully qualified domain names
        """
        try:
            # Try parsing as IP address (IPv4 or IPv6)
            ipaddress.ip_address(host)
        except ValueError:
            # If not an IP, perform DNS resolution check
            try:
                socket.gethostbyname(host)
            except socket.gaierror:
                self.logger.error(f"Invalid host: {host}")
                raise ValueError(f"Cannot resolve hostname: {host}")

    def _validate_port(self, port: int):
        """
        Validate port number is within valid range.
        """
        if not (0 < port < 65536):
            self.logger.error(f"Invalid port number: {port}")
            raise ValueError("Port must be between 1 and 65535")

    def connect(self) -> None:
        """
        Establish connection to server, with support for SSL/TLS.
        """
        try:
            # Create base socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)

            # Wrap with SSL if required
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.socket = context.wrap_socket(
                    self.socket, 
                    server_hostname=self.host
                )

            # Connect to server
            self.socket.connect((self.host, self.port))
            self.logger.info(f"Connected to {self.host}:{self.port} {'(SSL)' if self.use_ssl else ''}")

        except (socket.error, ssl.SSLError) as e:
            self.logger.error(f"Connection error: {e}")
            raise

    def send_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send JSON-encoded message and receive JSON response.
        
        Args:
            message (dict): Message to send
        
        Returns:
            dict: Server's response
        """
        try:
            # Convert message to JSON
            json_message = json.dumps(message) + '\n'
            
            # Send message
            if self.use_ssl:
                self.socket.write(json_message.encode())
                response = self.socket.read(4096).decode()
            else:
                self.socket.send(json_message.encode())
                response = self.socket.recv(4096).decode()

            # Parse response
            return json.loads(response)

        except (json.JSONDecodeError, socket.error) as e:
            self.logger.error(f"Message transmission error: {e}")
            raise

    def perform_network_diagnostic(self) -> Dict[str, Any]:
        """
        Perform a comprehensive network diagnostic operation.
        
        Returns diagnostic information about network path and performance.
        """
        diagnostics = {
            'timestamp': datetime.now().isoformat(),
            'host': self.host,
            'port': self.port,
            'diagnostics': {}
        }

        try:
            # Measure connection time
            start_time = time.time()
            self.connect()
            connect_time = time.time() - start_time

            # Send diagnostic request
            diagnostic_request = {
                'type': 'network_diagnostic',
                'client_timestamp': start_time
            }
            response = self.send_message(diagnostic_request)

            # Compile diagnostics
            diagnostics['diagnostics'] = {
                'connection_time_ms': round(connect_time * 1000, 2),
                'server_response_time_ms': response.get('server_processing_time', 0),
                'server_timestamp': response.get('server_timestamp'),
                'network_path_info': response.get('network_path', {})
            }

        except Exception as e:
            diagnostics['error'] = str(e)

        finally:
            if self.socket:
                self.socket.close()

        return diagnostics

def main():
    # Advanced argument parsing
    parser = argparse.ArgumentParser(description='Advanced Network Utility Client')
    parser.add_argument('host', help='Target server hostname or IP')
    parser.add_argument('-p', '--port', type=int, default=443, 
                        help='Target port (default: 443)')
    parser.add_argument('-s', '--ssl', action='store_true', 
                        help='Enable SSL/TLS encryption')
    parser.add_argument('--log', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                        default='INFO', help='Set logging level')
    
    args = parser.parse_args()

    # Create and run client
    try:
        client = NetworkUtilityClient(
            host=args.host, 
            port=args.port, 
            use_ssl=args.ssl,
            log_level=args.log
        )
        
        # Perform network diagnostic
        diagnostic_results = client.perform_network_diagnostic()
        
        # Pretty print results
        print(json.dumps(diagnostic_results, indent=2))

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

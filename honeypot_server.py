# -*- coding: utf-8 -*-
"""
Created on Sat Aug 17 19:36:57 2024

@author: Dell
"""

# Implemented HTTP Server
# Authentication: Implement a fake login prompt to see if attackers try to guess passwords
# Block Known Malicious IPs: Integrate with threat intelligence feeds to block or flag connections from known malicious IP addresses
# Create Decoy Files: Set up a fake file system with decoy files that attackers might try to access or download. Monitor access to these files
# Honeytokens: Place fake credentials or data in the honeypot that would alert you if they are used outside the honeypot environment
# Automatic IP Blocking: Automatically block or throttle connections from IP addresses that exhibit suspicious behavior

# honeypot_server.py

import socket
import threading
import logging
from datetime import datetime
import os
from collections import defaultdict
from time import time

# Initialization
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
ip_attempts = defaultdict(int)
ip_requests = defaultdict(list)
RATE_LIMIT = 60  # seconds
REQUEST_LIMIT = 10  # number of requests

def block_ip(ip_address):
    """Block an IP address using iptables."""
    os.system("iptables -A INPUT -s {ip_address} -j DROP")
    logging.info("Blocked IP address: {ip_address}".format(ip_address=ip_address))

def throttle_ip(ip_address):
    """Throttle connections from an IP address based on request rate."""
    current_time = time()
    timestamps = ip_requests[ip_address]
    
    # Remove outdated timestamps
    timestamps = [t for t in timestamps if current_time - t < RATE_LIMIT]
    
    # Check if the request limit is exceeded
    if len(timestamps) >= REQUEST_LIMIT:
        block_ip(ip_address)
    else:
        timestamps.append(current_time)
        ip_requests[ip_address] = timestamps

def log_failed_login(ip_address):
    """Log failed login attempts."""
    logging.warning("Failed login attempt from IP: {ip_address}".format(ip_address=ip_address))

def track_attempt(ip_address):
    """Track failed login attempts and block IP if necessary."""
    ip_attempts[ip_address] += 1
    # Example threshold for blocking
    if ip_attempts[ip_address] > 5:
        block_ip(ip_address)

def handle_client_connection(client_socket, client_address):
    """Handle incoming client connections."""
    ip_address = client_address[0]
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Example of logging and tracking failed login attempts
    log_failed_login(ip_address)
    track_attempt(ip_address)
    
    # Example of throttling connections
    throttle_ip(ip_address)
    
    # Log connection details
    logging.info("{timestamp} - Connection from {client_address} established.".format(timestamp=timestamp, client_address=client_address))
    
    try:
        # Receive and process data from client
        data = client_socket.recv(1024).decode('utf-8')
        logging.info("{timestamp} - Received request from {client_address}: {data}".format(timestamp=timestamp, client_address=client_address, data=data))
        
        # Simulate a basic HTTP response
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n\r\n"
            "<html><body><h1>Welcome to My Fake HTTP Server!</h1></body></html>"
        )
        client_socket.sendall(response.encode('utf-8'))
        logging.info("{timestamp} - Sent response to {client_address}: {response}".format(timestamp=timestamp, client_address=client_address, response=response))
    
    except socket.error as e:
        logging.error("{timestamp} - Socket error with {client_address}: {e}".format(timestamp=timestamp, client_address=client_address, e=e))
    except Exception as e:
        logging.error("{timestamp} - An error occurred with {client_address}: {e}".format(timestamp=timestamp, client_address=client_address, e=e))
    finally:
        client_socket.close()
        logging.info("{timestamp} - Connection with {client_address} closed.".format(timestamp=timestamp, client_address=client_address))

def honeypot_server(host="0.0.0.0", port=8080):
    """Start the honeypot server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        server.bind((host, port))
        server.listen(5)
        logging.info("Honeypot listening on {host}:{port}".format(host=host, port=port))
        
        while True:
            client_socket, client_address = server.accept()
            logging.info("Accepted connection from {client_address}".format(client_address=client_address))
            client_handler = threading.Thread(target=handle_client_connection, args=(client_socket, client_address))
            client_handler.daemon = True
            client_handler.start()
    
    except socket.error as e:
        logging.error("Socket error: {e}".format(e=e))
    except Exception as e:
        logging.error("An error occurred: {e}".format(e=e))
    finally:
        server.close()
        logging.info("Server socket closed.")

if __name__ == "__main__":
    honeypot_server()

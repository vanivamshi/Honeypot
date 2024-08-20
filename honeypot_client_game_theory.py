# -*- coding: utf-8 -*-
"""
Created on Sat Aug 17 19:36:53 2024

@author: Dell
"""

# Implemented HTTP Server
# Authentication: Implement a fake login prompt to see if attackers try to guess passwords
# Block Known Malicious IPs: Integrate with threat intelligence feeds to block or flag connections from known malicious IP addresses
# Create Decoy Files: Set up a fake file system with decoy files that attackers might try to access or download. Monitor access to these files
# Honeytokens: Place fake credentials or data in the honeypot that would alert you if they are used outside the honeypot environment
# Automatic IP Blocking: Automatically block or throttle connections from IP addresses that exhibit suspicious behavior
# Bayesian equilibrium to predict attack possibility

# honeypot_client.py

import socket
import logging
from datetime import datetime

def connect_to_server(host="127.0.0.1", port=8080, username="admin", password="password123"):
    client = None
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        logging.info("{timestamp} - Connected to server at {host}:{port}".format(timestamp=timestamp, host=host, port=port))
        
        # Construct HTTP POST request with fake credentials
        post_data = "username={username}&password={password}"
        request = (
            "POST /login HTTP/1.1\r\n"
            "Host: {host}:{port}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: {len(post_data)}\r\n"
            "Connection: close\r\n\r\n"
            "{post_data}"
        )
        
        # Send the fake login credentials to the server
        client.sendall(request.encode('utf-8'))
        logging.info("{timestamp} - Sent fake credentials to server: {post_data}".format(timestamp=timestamp, post_data=post_data))
        
        # Receive the response from the server
        response = client.recv(4096)
        logging.info("{timestamp} - Received response from server: {response.decode('utf-8')}")
        print(response.decode('utf-8'))  # Print the server's response for verification
        
    except socket.error as e:
        logging.error("{timestamp} - Socket error: {e}", exc_info=True)
    except Exception as e:
        logging.error("{timestamp} - An error occurred: {e}", exc_info=True)
    finally:
        if client:
            client.close()  # Ensure the socket is closed properly
            logging.info("{timestamp} - Connection closed")

if __name__ == "__main__":
    connect_to_server()

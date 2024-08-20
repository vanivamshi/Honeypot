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
# K-means clustering to analyse attack frequency

# honeypot_server.py

import socket
import threading
import logging
from datetime import datetime
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Example data for clustering (to be replaced with actual data collection)
data = {
    'request_frequency': [5, 20, 15, 10, 50, 45, 30, 60],
    'response_time': [200, 300, 250, 220, 400, 350, 280, 450]
}
df = pd.DataFrame(data)

def preprocess_data(data):
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(data)
    return scaled_data

def apply_kmeans(data):
    scaled_data = preprocess_data(data)
    kmeans = KMeans(n_clusters=3, random_state=0).fit(scaled_data)
    data['cluster'] = kmeans.labels_
    distances = kmeans.transform(scaled_data)
    data['distance_to_centroid'] = np.min(distances, axis=1)
    threshold = np.percentile(data['distance_to_centroid'], 95)
    data['anomaly'] = data['distance_to_centroid'] > threshold
    return data, kmeans

def generate_response():
    return (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<html><body><h1>Welcome to the honeypot!</h1></body></html>"
    )

def handle_client_connection(client_socket, client_address):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    logging.info("{timestamp} - Connection from {client_address} established.".format(timestamp=timestamp, client_address=client_address))
    
    try:
        # Receive and process data from client
        data = client_socket.recv(1024).decode('utf-8')
        logging.info("{timestamp} - Received request from {client_address}: {data}".format(timestamp=timestamp, client_address=client_address, data=data))
        
        # Generate a generic response
        response = generate_response()
        client_socket.sendall(response.encode('utf-8'))
        logging.info("{timestamp} - Sent response to {client_address}: {response}".format(timestamp=timestamp, client_address=client_address, response=response))
        
        # Update and analyze data for clustering
        new_data = {
            'request_frequency': [data.count('GET')],
            'response_time': [len(data)]
        }
        new_df = pd.DataFrame(new_data)
        global df
        df = pd.concat([df, new_df], ignore_index=True)
        df, kmeans = apply_kmeans(df)
        
        # Print clustering results
        print("\nCurrent Clustering Results:")
        print(df)
        
        # Check if the new data point is considered an anomaly
        new_point = new_df.iloc[0]
        new_point_scaled = preprocess_data(new_data)
        cluster = kmeans.predict(new_point_scaled)[0]
        distance_to_centroid = np.min(kmeans.transform(new_point_scaled))
        
        if distance_to_centroid > np.percentile(df['distance_to_centroid'], 95):
            print("\nPossible attack detected from {client_address}: Distance to centroid = {distance_to_centroid}".format(client_address=client_address, distance_to_centroid=distance_to_centroid))
        else:
            print("\nNormal behavior detected from {client_address}: Distance to centroid = {distance_to_centroid}".format(client_address=client_address, distance_to_centroid=distance_to_centroid))
    
    except socket.error as e:
        logging.error("{timestamp} - Socket error with {client_address}: {e}".format(timestamp=timestamp, client_address=client_address, e=e))
    except Exception as e:
        logging.error("{timestamp} - An error occurred with {client_address}: {e}".format(timestamp=timestamp, client_address=client_address, e=e))
    finally:
        client_socket.close()
        logging.info("{timestamp} - Connection with {client_address} closed.".format(timestamp=timestamp, client_address=client_address))

def honeypot_server(host="0.0.0.0", port=8080):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        server.bind((host, port))
        server.listen(5)
        logging.info("Honeypot listening on {host}:{port}")
        
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

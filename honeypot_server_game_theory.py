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
# Bayesian equilibrium to predict attack possibility

# honeypot_server.py

import socket
import threading
import logging
from datetime import datetime
from scipy.optimize import minimize
import numpy as np

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define Bayesian Nash Equilibrium functions
def defender_payoff(defense, attack, defender_type):
    # Example payoff function for defender
    return - (defense * attack + defender_type * defense)

def attacker_payoff(attack, defense, attacker_type):
    # Example payoff function for attacker
    return - (attack * (1 - defense) + attacker_type * attack)

def compute_bayesian_nash_equilibrium():
    # Define the types and probabilities
    attacker_types = [1, 2]  # 1 for novice, 2 for advanced
    defender_types = [1, 2]  # 1 for basic, 2 for advanced
    prob_attacker_type = [0.5, 0.5]  # Probabilities of attacker types
    prob_defender_type = [0.5, 0.5]  # Probabilities of defender types

    # Define the strategy space (e.g., attack and defense levels)
    defense_strategy = np.linspace(0, 1, 10)
    attack_strategy = np.linspace(0, 1, 10)

    # Objective function for finding equilibrium
    def objective_function(strategy):
        defense, attack = strategy
        expected_payoff_defender = 0
        expected_payoff_attacker = 0
        
        for defender_type in defender_types:
            for attacker_type in attacker_types:
                prob_defender = prob_defender_type[defender_type - 1]
                prob_attacker = prob_attacker_type[attacker_type - 1]
                
                expected_payoff_defender += prob_defender * prob_attacker * defender_payoff(defense, attack, defender_type)
                expected_payoff_attacker += prob_defender * prob_attacker * attacker_payoff(attack, defense, attacker_type)
        
        return - (expected_payoff_defender + expected_payoff_attacker)

    # Optimize to find the equilibrium strategy
    initial_strategy = [0.5, 0.5]
    result = minimize(objective_function, initial_strategy, bounds=[(0, 1), (0, 1)])
    
    return result.x[0], result.x[1], -result.fun

def handle_client_connection(client_socket, client_address):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    logging.info("{timestamp} - Connection from {client_address} established.".format(timestamp=timestamp, client_address=client_address))
    
    # Compute Bayesian Nash Equilibrium
    optimal_defense, optimal_attack, expected_payoff = compute_bayesian_nash_equilibrium()
    
    # Print and log the game theory results
    print("{timestamp} - Optimal Defense Strategy: {optimal_defense}".format(timestamp=timestamp, optimal_defense=optimal_defense))
    print("{timestamp} - Optimal Attack Strategy: {optimal_attack}".format(timestamp=timestamp, optimal_attack=optimal_attack))
    print("{timestamp} - Expected Payoff: {expected_payoff}".format(timestamp=timestamp, expected_payoff=expected_payoff))
    
    logging.info("{timestamp} - Optimal Defense Strategy: {optimal_defense}".format(timestamp=timestamp, optimal_defense=optimal_defense))
    logging.info("{timestamp} - Optimal Attack Strategy: {optimal_attack}".format(timestamp=timestamp, optimal_attack=optimal_attack))
    logging.info("{timestamp} - Expected Payoff: {expected_payoff}".format(timestamp=timestamp, expected_payoff=expected_payoff))

    try:
        # Receive and process data from client
        data = client_socket.recv(1024).decode('utf-8')
        logging.info("{timestamp} - Received request from {client_address}: {data}".format(timestamp=timestamp, client_address=client_address, data=data))
        
        # Generate a generic HTTP response
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n\r\n"
            "<html><body><h1>Welcome to the honeypot!</h1></body></html>"
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
        logging.error("Socket error: {e}".format(e))
    except Exception as e:
        logging.error("An error occurred: {e}".format(e))
    finally:
        server.close()
        logging.info("Server socket closed.")

if __name__ == "__main__":
    honeypot_server()

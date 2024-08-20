# Honeypot

Honeypot (honeypot_client and honeypot_server) is designed to include the following,
1) Implemented HTTP Server
2) Authentication: Implement a fake login prompt to see if attackers try to guess passwords
3) Block Known Malicious IPs: Integrate with threat intelligence feeds to block or flag connections from known malicious IP addresses
4) Create Decoy Files: Set up a fake file system with decoy files that attackers might try to access or download. Monitor access to these files
5) Honeytokens: Place fake credentials or data in the honeypot that would alert you if they are used outside the honeypot environment
6) Automatic IP Blocking: Automatically block or throttle connections from IP addresses that exhibit suspicious behavior

Additionally,
1) honeypot_client_ml and honeypot_server_ml - Includes K-Means algorithms to analyse and predict attacks
2) honeypot_client_game_theory and honeypot_server_game_theory - Includes Bayesian game to predict the possibility of attacks

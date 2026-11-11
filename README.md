Technical Project Report: Network Intrusion Detection & Threat Simulation

1. Project Objective
The objective of this lab was to design, deploy, and validate an Intrusion Detection System (IDS) capable of identifying volumetric Denial of Service (DoS) attacks. Specifically, the project focused on detecting TCP SYN Flood vectors while implementing thresholds to minimize false positives from legitimate high-traffic network events.
2. Environment Setup
Defender Architecture: Ubuntu Linux, Snort IDS (configured with Promiscuous Mode enabled)
Attacker Architecture: Kali Linux / Ubuntu, hping3 (packet crafting and injection)
Network Protocol: TCP/IPv4
3. Threat Profile: TCP SYN Flood
A TCP SYN flood is a type of Denial of Service (DoS) attack that exploits the standard TCP three-way handshake. The attacker sends a rapid succession of SYN (synchronize) requests to a target system. The target acknowledges these with SYN-ACKs and leaves the connections half-open, waiting for the final ACK. By flooding the server with these initial requests and never completing the handshake, the attacker exhausts the server's connection queues, rendering it unresponsive to legitimate traffic.
4. Detection Strategy & Signature Development
To detect this specific threat without overwhelming the monitoring infrastructure with false alerts during normal peak traffic, a custom Snort signature was authored and deployed to the local.rules configuration.
Custom Snort Signature:
alert tcp any any -> $HOME_NET any (msg:"Possible TCP SYN Flood DoS Attack"; flags:S; detection_filter:track by_src, count 100, seconds 1; sid:1000001; rev:1;)
Signature Component Breakdown:
alert tcp any any -> $HOME_NET any: Monitors inbound TCP traffic originating from any external source traversing into the defined home network.
flags:S: Isolates packets where only the SYN flag is set, indicating the initiation phase of the TCP handshake.
detection_filter:track by_src, count 100, seconds 1: The critical thresholding mechanism. This instructs the IDS to track traffic statefully by source IP. An alert is only generated if a single source transmits 100 or more SYN packets within a 1-second window, distinguishing malicious volumetric floods from normal web scraping or database sync operations.
5. Attack Simulation & Validation
To validate the efficacy of the custom signature, volumetric network attacks were simulated using the hping3 packet crafting utility.
Simulation Command executed from attacker machine:
sudo hping3 -S -p 80 --flood <TARGET_IP>
Command Flags:
-S: Explicitly sets the SYN flag on generated packets.
--flood: Instructs hping3 to transmit packets at the maximum physical rate of the network interface, successfully exceeding the IDS rule threshold of 100 packets/second.
6. Results and Conclusion
Upon execution of the simulated flood, Snort successfully identified the volumetric anomaly and triggered the custom alert. The detection filter functioned as designed, proving that the monitoring environment was successfully configured to identify stateful anomalies based on defined threshold logic.

# Understanding_Networks_Attacks

Assignment 2 — Cyber & Infrastructure Defense


Author: Deeksha Reddy Patlolla


## Overview

Assignment 2 focuses on LAN-level attacks, WAN-level threats, protocol weaknesses, and hands-on exploitation, combining conceptual depth with practical execution.

It consists of two major components:

Conceptual Cybersecurity Topics
– ARP spoofing, NDP attacks, DHCP starvation, VLAN hopping
– Wireless attacks, IP spoofing, DNS poisoning, BGP hijacking
– Amplification DDoS, mitigation strategies
– Cloud + AI-driven threat evolution
– Secure network design, segmentation, internal defenses

Hands-On Attack Labs
– ARP spoofing
– SYN flood (with & without spoofing)
– Remote code execution exploit (vsftpd backdoor)
– Passive LAN sniffing with Wireshark

This strengthens your understanding of real-world attacker techniques and defensive strategies.

### Section 1 — Conceptual Assignments
### ARP Poisoning & MITM on Switched Networks

Covered advanced attack methods:

Gratuitous ARP timing attacks

ARP cache flooding

Proxy ARP hijacking

VLAN-based MITM in segmented networks

VLAN hopping, trunk misconfigurations, insider misuse

Mitigations include:
DAI, static ARP, port security, 802.1X, MACsec, IDS/ARP monitoring.

### ARP Spoofing in IPv6 / NDP Attacks

Explored:

NDP spoofing (NS/NA manipulation)

Rogue Router Advertisement (RA) attacks

Redirect attacks

SLAAC and privacy extension impacts

Defenses:
RA Guard, NDP Inspection, SEND, 802.1X, IPv6-aware IDS.

### DHCP Starvation & Rogue DHCP Persistence

Explained how attackers:

Exhaust the DHCP pool

Deploy a rogue server for MITM, DNS hijacking, proxying

Maintain long-term persistence across reboots

Mitigation: DHCP Snooping, port ACLs, 802.1X, SIEM monitoring.

### VLAN Hopping & Segmentation Bypass

Beyond double-tagging:

Native VLAN mismatch exploitation

Mis-tagged access ports

VXLAN/overlay misconfigurations

Insider abuse & dynamic VLAN manipulation

Mitigation includes strict ACLs, disabling DTP, hardening RADIUS/802.1X.

### Wireless Attacks: Rogue AP & Evil Twin

Explored:

SSID hiding bypass

MAC filtering bypass

Deauthentication-based hijacking

WPA3/SAE (Dragonfly) strengths & weaknesses

Defenses include 802.11w, WPA3-only, EAP-TLS, WIPS/WIDS, segmentation.

### IP Spoofing & Multi-Stage Attacks

Covered:

UDP vs TCP spoofing

Reflection & amplification

Blind TCP injection & session hijack limits

On-path vs off-path attacks

Mitigation: BCP38, uRPF, IPSec, TLS, firewall asymmetry monitoring.

### DNS Cache Poisoning (Pre- & Post-Kaminsky)

Topics covered:

TXID prediction weaknesses

Source port randomization

DNSSEC benefits & deployment hurdles

Remaining bypass vectors

### BGP Hijacking & Route Manipulation

Explained:

Route leaks vs prefix hijacks

Nation-state exploitation (surveillance, censorship)

2018 Amazon Route 53 incident

RPKI & origin validation

### Amplification DDoS (DNS, NTP, Memcached)

Discussed:

Why memcached had extreme amplification

How spoofing + BGP manipulation increases scale

Application-layer amplification possibilities

### DDoS Defense: Proactive vs Reactive

Covered:

Anycast, scrubbing centers, autoscaling

Behavioral analytics & ML detection

Incident runbooks & emergency communication

### Emerging Cloud & AI Threats

Examples include:

Serverless abuse

IAM misconfigurations

ML model poisoning, adversarial examples

AI-driven phishing automation

### Security Mindset & Network Prioritization

Key lessons:

LAN segmentation first to block lateral movement

WAN hardening (BGP/DNS) for global services

Importance of telemetry, logs, and Zero Trust

### Designing a Secure Segmented Network

Strategies included:

Least-privilege VLAN design

Microsegmentation for critical workloads

Policy automation through SDN/Infrastructure-as-Code

RADIUS + 802.1X authentication

Preventing misconfigurations

### Protecting Against DDoS & Global Threats

Covered:

Immediate response workflow

Long-term resiliency

Cloud vs on-prem trade-offs

### LAN Security & Preventing Lateral Movement

Focused on:

Detecting footholds (failed logins, anomalous SMB/LDAP, ARP/DHCP anomalies)

Using NAC/EDR to isolate infected hosts

Preventing rogue devices

Using honeypots & honeytokens

### Section 2 — Hands-On Network Attacks
### Attack 1 — ARP Spoofing (Local MITM)

Executed poisoning to impersonate gateway → enabled:

Sniffing

Session hijacking

Traffic manipulation

Reconnaissance

Defenses: VLAN segmentation, DAI, static ARP, encrypted protocols (HTTPS/SSH).

### Attack 2 — SYN Flood (with & without spoofing)

Observed patterns in Wireshark:

Standard flood → consistent attacker IP

Spoofed flood → SYN-ACKs to many fake IPs + ARP queries

Backscatter and attribution difficulty

Defenses:
SYN cookies, SYN proxy, BCP38 anti-spoofing, backlog tuning.

### Attack 3 — Remote Code Execution (vsftpd Backdoor)

Used Metasploit exploit:
exploit/unix/ftp/vsftpd_234_backdoor
Outcome:

Gained root shell on port 6200

Verified with whoami and root directory access

Discussion covered supply-chain risks, FTP deprecation, SELinux/AppArmor, firewalling.

### Attack 4 — Passive LAN Sniffing (Wireshark)

Captured:

Full HTTP request/response

Session cookies

Paths, metadata, visible plaintext

Showed danger of unencrypted traffic and enabled session hijacking.

Defenses:
HTTPS-only, HSTS, HttpOnly/Secure cookies, VLANs, WPA2-Enterprise, IDS, VPN.

### Submission Contents

a2_report.md

a2_report.pdf (

a2_report

)

screenshots/ folder



### Summary

Assignment 2 deepened understanding of:

LAN & WAN attack surfaces

MITM, spoofing, segmentation bypass, and protocol-level weaknesses

DDoS, BGP, DNS, and global-scale network threats

Hands-on exploitation in realistic network environments

Defensive layering & Zero Trust design

This assignment builds strong foundations for advanced cyber defense, red teaming, incident response, and secure architecture design.

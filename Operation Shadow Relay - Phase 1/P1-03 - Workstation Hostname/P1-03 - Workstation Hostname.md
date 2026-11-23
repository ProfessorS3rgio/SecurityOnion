P1-03 - Workstation Hostname

Scenario: Operation Shadow Relay, Phase 1

Objective:

Determine the hostname of the affected Windows workstation.

Tool:

CTF Security Onion: https://seco.cyberex.quest/

Time range:

December 10–20, 2025 (UTC). If the Phase 1 import ID is available, I will apply it as an additional filter.

Method:

I used the affected workstation address from P1-01, 10.9.11.135, and searched the DHCP records for the hostname and MAC address associated with it.

In Group Metrics, I will look for the host.hostname value associated with 10.9.11.135 and record the hostname, MAC address, and event count. I will then expand the matching DHCP event under Events and record the assigned IP, hostname, MAC address, and UTC timestamp.

Primary query:

event.dataset:dhcp AND dhcp.assigned_ip:"10.9.11.135" | groupby host.hostname host.mac

Fallback query:

If the DHCP search returns no results, I will use this query to find Windows Browser traffic and pivot to the PCAP from a matching event:

source.ip:"10.9.11.135" AND destination.port:138 | sortby @timestamp^

I will inspect the Windows Browser announcement for the computer-name field and record the exact hostname and UTC timestamp.

Evidence:

The affected workstation address to verify is 10.9.11.135. The required evidence is either an expanded DHCP event showing the assigned IP and hostname, or a Windows Browser packet containing the workstation name.

Finding:

The hostname is still pending verification in the Phase 1 Security Onion data.

Answer:

The expected flag format is CTK{hostname}.
answer:CTK{DESKTOP-6T17ZFM} 

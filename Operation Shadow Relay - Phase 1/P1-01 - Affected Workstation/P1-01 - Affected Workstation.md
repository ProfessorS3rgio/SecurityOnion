P1-01 - Affected Workstation

Scenario: Operation Shadow Relay, Phase 1

Objective:

Identify the internal IPv4 address of the workstation responsible for the suspicious activity.

Tool:

CTF Security Onion Hunt: https://seco.cyberex.quest/

Time range:

December 10–20, 2025 (UTC).

Answer format:

CTK{IPv4}

Discovery query:

tags:alert | groupby rule.name source.ip destination.ip

Method:

I ran the discovery query in Hunt to group alerts by detection rule and network endpoints. I reviewed the rule names for activity that identified a compromised workstation.

The FormBook alerts showed 172.16.8.49 as the source. I submitted that address, but the challenge platform rejected it, so I did not use it as the final finding.

The grouped results also showed the following alert:

ET EXPLOIT_KIT LandUpdate808 Domain in DNS Lookup

The alert contained this source and destination information:

Source IP: 10.9.11.135

Destination IP: 10.9.11.2

Queried domain: aatthews.cfd

Alert count: 2

Verification query:

tags:alert AND source.ip:"10.9.11.135" | groupby rule.name source.ip destination.ip

I expanded a matching LandUpdate808 event and checked the rule name, source IP, destination IP, queried domain, and UTC timestamp.

Screenshot evidence:

I captured one Group Metrics screenshot showing the query, Phase 1 time range, LandUpdate808 rule, and the 10.9.11.135 source row.

I also captured an expanded event screenshot showing the same source IP, destination IP, queried domain, and timestamp.

Finding:

The affected workstation was 10.9.11.135. It originated the DNS lookup that matched the LandUpdate808 detection.

Answer:

CTK{10.9.11.135}

Status:

Confirmed correct by the challenge platform.

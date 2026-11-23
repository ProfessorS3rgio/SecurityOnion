P2-01 - Affected Workstation

Scenario: Operation False Assurance, Phase 2

Objective:

Identify the internal IPv4 address associated with the suspicious remote-access activity.

Tool:

CTF Security Onion Hunt: https://seco.cyberex.quest/

Time range:

Use the Phase 2 evidence window in UTC.

Method:

I set the Hunt time range to the Phase 2 evidence window and grouped the alert records by rule name, source IP, and destination IP.

I then looked for remote-access alerts mentioning ScreenConnect, ConnectWise, or RMM. The same internal source, 10.9.14.101, appeared in both ScreenConnect-related alerts.

I used the verification query to confirm the source and inspect the matching events. I would expand an event and record the rule name, source IP, destination IP, and UTC timestamp for the evidence screenshot.

Discovery query:

tags:alert | groupby rule.name source.ip destination.ip

Verification query:

tags:alert AND source.ip:"10.9.14.101" | groupby rule.name source.ip destination.ip

Evidence:

Remote-access rule 1: ET REMOTE_ACCESS Observed DNS Query to Known ScreenConnect/ConnectWise Remote Desktop Service Domain

Remote-access rule 2: ET REMOTE_ACCESS Remote Monitoring and Management (RMM) Tool in DNS Lookup (screenconnect.com)

Source IP: 10.9.14.101

Destination IP: 10.9.14.1

Timestamp: Record the UTC timestamp from the expanded Phase 2 alert.

Finding:

The internal workstation associated with the suspicious ScreenConnect remote-access activity was 10.9.14.101.

Answer:

CTK{10.9.14.101}

Status:

Verify the alert rows and timestamp in the Phase 2 Security Onion data before submitting.

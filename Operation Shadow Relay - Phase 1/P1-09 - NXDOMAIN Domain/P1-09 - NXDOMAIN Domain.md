P1-09 - NXDOMAIN Domain

Scenario: Operation Shadow Relay, Phase 1

Objective:

Identify the suspicious domain repeatedly queried by the affected workstation that returned NXDOMAIN responses.

Tool:

CTF Security Onion Hunt: https://seco.cyberex.quest/

Time range:

December 10–20, 2025 (UTC). If the Phase 1 import ID is available, I will apply it as an additional filter.

Method:

I used the affected workstation address from P1-01, 10.9.11.135, and filtered its DNS events to responses with the NXDOMAIN response code.

I grouped the results by queried domain and looked for the domain that appeared repeatedly. I then expanded a matching event to confirm the query name, workstation IP, resolver IP, response code, and UTC timestamp.

Query:

tags:dns AND source.ip:"10.9.11.135" AND dns.response.code_name:"NXDOMAIN" | groupby dns.query.name

Evidence:

Source IP: 10.9.11.135

Destination IP: 10.9.11.2

Queried domain: globalcert8618.net

DNS response: NXDOMAIN

Repeated-query evidence: Group Metrics count for globalcert8618.net

Timestamp: Record the UTC timestamp from the expanded Hunt event.

Finding:

The suspicious domain repeatedly queried by the affected workstation and returned as nonexistent was globalcert8618.net.

Answer:

CTK{globalcert8618.net}

Status:

Verify the Group Metrics count and expanded event in the Phase 1 Security Onion data before submitting.

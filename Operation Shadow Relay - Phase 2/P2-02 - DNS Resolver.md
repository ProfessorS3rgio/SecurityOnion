P2-02 - DNS Resolver

Scenario: Operation False Assurance, Phase 2

Objective:

Identify the IPv4 address that served as the affected workstation's internal DNS resolver.

Tool:

CTF Security Onion Hunt: https://seco.cyberex.quest/

Time range:

Use the Phase 2 evidence window in UTC.

Method:

I set the Hunt time range to the Phase 2 evidence window and filtered DNS events to the affected workstation identified in P2-01, 10.9.14.101.

I restricted the results to traffic sent to destination port 53 and grouped the events by destination IP. In Group Metrics, I looked for 10.9.14.1 and then expanded a matching event under Events to record the source IP, resolver IP, port, query name, and UTC timestamp.

Query:

tags:dns AND source.ip:"10.9.14.101" AND destination.port:53 | groupby destination.ip

Evidence to capture:

The Group Metrics screenshot should include the complete query, the Phase 2 UTC time range, and the destination IP row for 10.9.14.1 with its event count.

The expanded event screenshot should show the timestamp, source IP 10.9.14.101, destination IP 10.9.14.1, destination port 53, DNS query name, and the response field if it is available.

The query and expanded event should be kept together as one evidence set so the resolver address can be tied to the affected workstation.

Evidence:

Affected workstation: 10.9.14.101

DNS resolver: 10.9.14.1

Destination port: 53

DNS query name: Record this from the expanded Hunt event.

Timestamp: Record this from the expanded Hunt event.

Finding:

The internal DNS resolver used by the affected workstation was 10.9.14.1.

Answer:

CTK{10.9.14.1}

Status:

Verify the Group Metrics row and expanded DNS event in the Phase 2 Security Onion data before submitting.

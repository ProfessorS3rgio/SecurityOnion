# P1-10 — NXDOMAIN Query Count

**Scenario** — Operation Shadow Relay, Phase 1

## Objective

Count DNS queries for `globalcert8618.net` sent by the affected workstation.

## Investigation

**Tool** — [CTF Security Onion](https://seco.cyberex.quest/)

**Time range** — December 10–20, 2025 UTC. Apply the Phase 1 import filter if its `import.id` is available.

**Query**

```text
tags:dns AND source.ip:"10.9.11.135" AND dns.query.name:"globalcert8618.net" | groupby dns.response.code_name
```

**Method**

1. Filter DNS events to the affected workstation IP and the exact query name from the challenge.
2. Record **Total Found** for the number of matching queries and the **NXDOMAIN** group count for the response-code breakdown.
3. Open a matching event and record the source IP, resolver IP, exact query name, response code, and UTC timestamp.

## Evidence

- **Affected workstation** — `10.9.11.135`, established in P1-01.
- **Evidence to record** — Matching DNS event count and NXDOMAIN group count.

## Finding

Pending verification in the Phase 1 Security Onion data.

## Answer

**Flag format** — `CTK{number}`

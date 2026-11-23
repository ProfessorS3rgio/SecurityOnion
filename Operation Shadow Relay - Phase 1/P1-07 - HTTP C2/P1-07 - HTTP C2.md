# P1-07 — HTTP C2

**Scenario** — Operation Shadow Relay, Phase 1

## Objective

Identify the domain, destination IPv4 address, and port used for the principal cleartext HTTP command-and-control communication.

## Investigation

**Tool** — [CTF Security Onion](https://seco.cyberex.quest/)

**Time range** — December 10–20, 2025 UTC. Apply the Phase 1 import filter if its `import.id` is available.

**Query**

```text
event.dataset:http AND source.ip:"10.9.11.135" | groupby http.virtual_host destination.ip destination.port
```

**Method**

1. Review **Group Metrics** for repeated HTTP requests from the workstation. Keep the HTTP Host, destination IP, and destination port together because multiple hostnames can share one IP.
2. Drill down into the groups that show recurring traffic. Review the request method and timestamps to identify the principal C2 flow.
3. Record `http.virtual_host`, `destination.ip`, and `destination.port` from a matching request, along with its UTC timestamp.

## Evidence

- **Affected workstation** — `10.9.11.135`, established in P1-01.
- **Evidence to record** — Recurring cleartext HTTP events showing the Host, destination IP, and port.

## Finding

Pending verification in the Phase 1 Security Onion data.

## Answer

**Flag format** — `CTK{domain|IPv4|port}`

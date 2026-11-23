# P2-03 — URL Shortening Domain

**Scenario** — Operation False Assurance, Phase 2

## Objective

Identify the URL-shortening domain contacted at the beginning of the observed activity.

## Investigation

**Tool** — [CTF Security Onion](https://seco.cyberex.quest/), Hunt interface.

**Time range** — The Phase 2 evidence window in UTC.

**Query**

```text
tags:dns AND source.ip:"10.9.14.101" | sortby @timestamp^ | table @timestamp dns.query.name destination.ip
```

**Method**

1. Filter DNS events to the affected workstation identified in P2-01, `10.9.14.101`.
2. Display the query name, destination IP, and timestamp together.
3. Review the earliest events in chronological order. The first URL-shortening domain is `t.co`.
4. Expand the event if needed and verify the exact UTC timestamp and resolver address.

## Screenshot Evidence

The Hunt Events screenshot shows:

- `dns.query.name` = `t.co`
- `@timestamp` = `2025-12-12T09:00:00.000Z`
- `destination.ip` = `10.9.14.1`
- Total Found = `4`

The `t.co` event occurs before `icci-sa.com` at `2025-12-12T09:00:01.603Z` and before the later ScreenConnect lookups. Keep the screenshot with the query bar and UTC time range visible.

## Evidence

| Field | Value |
| --- | --- |
| Affected workstation | `10.9.14.101` |
| URL-shortening domain | `t.co` |
| First observed timestamp | `2025-12-12T09:00:00.000Z` |
| DNS resolver | `10.9.14.1` |

## Finding

The URL-shortening domain contacted at the beginning of the observed activity was `t.co`.

## Answer

```text
CTK{t.co}
```

**Status** — Supported by the Phase 2 Security Onion Hunt screenshot.

# Evidence Documentation Workflow

This project documents each CTF question from the CTF Security Onion instance at [seco.cyberex.quest](https://seco.cyberex.quest/).

## Standard Process

Every challenge write-up should follow the same sequence.

1. **Record the objective.** Copy the question into plain language and note the required flag format.
2. **Set the investigation scope.** Set the challenge phase time range and UTC display. Record the affected workstation or other indicator already established by an earlier challenge.
3. **Run one discovery query.** Use a broad query to find the relevant event type. Keep the exact query in a fenced code block.
4. **Inspect the result.** Explain what each relevant field means and why the row is related to the question.
5. **Run one verification query.** Narrow the search to the candidate value and show the exact fields needed for confirmation.
6. **Capture screenshots.** Save a Group Metrics screenshot showing the query, time range, candidate value, and count. Save an expanded Events screenshot showing the timestamp and all fields that support the conclusion.
7. **Record timestamps in UTC.** If the interface displays `+08:00`, subtract eight hours and record the converted value.
8. **Separate observation from conclusion.** Put values visible in Security Onion under **Evidence**. Put the interpretation under **Finding**.
9. **Submit only the required flag value.** Keep the exact flag in a fenced code block.
10. **Record status.** Use `Confirmed correct` only after the challenge platform accepts the submission. Otherwise state that platform confirmation is pending.

## Screenshot Checklist

Each evidence screenshot should include as much of the following as the interface allows:

- Hunt query bar
- Phase time range and time zone
- Total Found or Group Metrics count
- Relevant field names and values
- Expanded event timestamp
- Source and destination IPs and ports
- Domain, hostname, username, rule name, or protocol field needed by the question

## File Layout

Store each write-up and its screenshots together in a folder named for the challenge:

```text
Operation False Assurance - Phase 1/
└── P1-xx - Challenge Name/
    ├── P1-xx - Challenge Name.md
    └── evidence-description.png
```

Use the same layout for later phases.

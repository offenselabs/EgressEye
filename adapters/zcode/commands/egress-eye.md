---
description: Show the EgressEye per-session egress report
---

Run `egress-eye report` (or `node <path-to>/egress-eye/dist/cli.js report`, or `node <plugin-root>/dist/cli.js report` if running from the installed plugin) and show the output to the user verbatim.

If the report says no events were recorded, tell the user that EgressEye records tool calls via hooks and that they should try again after some agent activity in this session. Offer `egress-eye sessions` to list past sessions and `egress-eye report --last` for the most recent one.

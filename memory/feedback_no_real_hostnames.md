---
name: feedback-no-real-hostnames
description: Never put real server hostnames belonging to the user's infrastructure into any persisted artifact (repo source, README, docs, plan files, example configs, memory files, etc.) — use RFC 2606 placeholders like example.com.
metadata:
  type: feedback
---

Never put real server hostnames into any file that gets persisted in
the repo or in the plan/memory area. This includes source code,
README, docs, plan files, example configs, test fixtures, systemd
env file examples, nginx configs in documentation, and memory files
themselves.

Use RFC 2606 placeholders such as `example.com`, `example.org`,
`example.net`, with subdomains like `cdn.example.com`,
`jump.example.com`, `relay.example.org`.

**Why:** the user has caught me twice doing this. Real hostnames
belonging to their infrastructure are not something that should leak
into committed or shared artefacts. They are happy to have real
hostnames inside *transient artefacts that only exist on the actual
server itself* (deployed `/etc/nginx/sites-available/default`,
deployed `/etc/bidichan/*.env`, etc. — these naturally must reference
the real hostname because they configure it, and they are not
committed to the repo).

**How to apply:** before writing any file under
`/home/torkve/workspace/bidichan/`, `/home/torkve/.claude/plans/`, or
the memory dir, scan the content for any real domain the user has
mentioned and replace it with an `example.com`-style placeholder.
Especially watch the "Why" section of memory entries — that is where
I almost reflexively quote the user's specific case.

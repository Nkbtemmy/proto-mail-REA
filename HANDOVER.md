# HANDOVER — ReconMail, Claude → manzi

**Date:** 2026-10-22. Written by Claude at the point of handing the remaining work
to the local Qwen model (`manzi --big` / `manzi-14b`).

> **UPDATE — all handover tasks were then completed in-session.** Tier A (A1–A4) and
> Tier B (B1 HTTP api, B2 Curve25519, B3 James mailet) are done: **9 modules, 39 tests
> green**, a networked HTTP API with an over-HTTP integration test, a deployable jar,
> and a real Apache James mailet. `manzi` drafted A1–A4 (logged in `ai-collab/`, each
> `*.REVIEW.md`); Claude wrote/fixed the correctness-critical parts and owned Tier B.
> This document and `ai-collab/MANZI_TASKS.md` remain as the method for *future* work
> (e.g. splitting the API into separate networked services + Postgres).

## 1. Where things stand (the base is solid and GREEN)

- **Dossier (deliverable 1): complete.** `docs/dossier/00..07` — the full reverse
  engineering of Proton Mail's design, sourced and mapped to code.
- **Reference system (deliverable 2): core complete, `mvn test` = 30 tests green.**
  Six Maven modules under `reference-system/` (Java 25 + Bouncy Castle):
  `crypto`, `srp`, `keyserver` (SKL + Key Transparency), `auth-server`, `mail`
  (encrypt-on-arrival), `app` (end-to-end scenario), and `cli` (interactive).
- **Proof it works:**
  ```bash
  mvn -f reference-system/pom.xml test
  mvn -f reference-system/pom.xml -q -DskipTests install
  mvn -f reference-system/app/pom.xml -q -Dexec.mainClass=com.reconmail.app.EndToEndScenario exec:java
  mvn -f reference-system/cli/pom.xml -q -Dexec.mainClass=com.reconmail.cli.Cli exec:java   # interactive
  ```

Read these first: `README.md`, `reference-system/README.md`, `docs/dossier/07-reconstruction-plan.md`.

## 2. The team rule you must keep (why this handover is shaped the way it is)

`manzi-14b` is Java-tuned and good at **self-contained boilerplate** (data records,
simple wiring, tests, config files). It is **unreliable** at: intricate third-party
library APIs (it fabricated Bouncy Castle classes), cryptographic/protocol math (it
botched SRP), and framework wiring. Evidence is in `ai-collab/outputs/*.REVIEW.md`.

**THE GOLDEN RULE — never break it:**
> After applying ANY manzi output, run `mvn -f reference-system/pom.xml test`.
> If the build goes red, manzi hallucinated. Fix it or revert. Never keep a red build.

Keep the audit trail: every task's prompt in `ai-collab/prompts/`, raw output in
`ai-collab/outputs/`, and a one-line verdict in `ai-collab/outputs/<task>.REVIEW.md`.

## 3. How to drive manzi

```bash
# turnkey: run a prompt file, save the output, get the verify reminder
cd ai-collab && ./ask-manzi.sh prompts/A1-cli-extra-commands.md

# or one-shot from the terminal (ALWAYS use -n so it ignores the SecureMail project context)
manzi --big -n "your precise prompt here"
```

The full backlog, with **ready-to-paste prompts** and a risk rating per task, is in
**`ai-collab/MANZI_TASKS.md`**. Start at the top (Tier A, manzi does these well) and
work down. Tier B (HTTP services, Curve25519, Apache James) is where manzi is weakest
— treat its output as a rough draft and verify hard, or save those for a human / a
future Claude session.

## 4. What is left (summary; details + prompts in MANZI_TASKS.md)

| Task | What | Risk for manzi |
|------|------|----------------|
| A1 | More CLI commands (wire existing services) | LOW ✅ |
| A2 | More unit tests for existing modules | LOW ✅ |
| A3 | `reference-system/USAGE.md` walkthrough | LOW ✅ |
| A4 | `deployment/docker-compose.yml` + `Caddyfile` skeletons | LOW–MED |
| B1 | Spring Boot HTTP `api` module over the services | HIGH ⚠ |
| B2 | Curve25519 key profile in `PgpCrypto` (Bouncy Castle) | HIGH ⚠ |
| B3 | Apache James encrypt-on-arrival mailet | HIGH ⚠ |

None of Tier B is required for the system to be *correct* — the logic is already
done and tested. Tier B is the **networked deployment form** (dossier ch. 05 / M9).

## 5. Guardrails (don't let the handoff drift)

- This stays a **study/reference** system — never deploy it to impersonate Proton or
  collect anyone's real Proton credentials.
- Keep **RSA-3072** working until B2's Curve25519 profile passes tests; don't rip out
  the verified path to chase the new one.
- Keep the dossier honest: the server reads **metadata incl. subject** by design;
  don't let any change claim otherwise.

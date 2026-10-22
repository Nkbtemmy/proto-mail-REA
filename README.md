# ReconMail — a clean-room reconstruction of Proton Mail

**Goal:** understand *everything* about how Proton Mail is built — its cryptography,
authentication, key management, and mail data flow — by studying Proton's own
open-source clients and published security design, then build a working reference
system (`reference-system/`) that embodies the same architecture.

This is **Option A**: reconstruction from public, open-source material + published
security papers. No live reverse engineering of the running product. Proton
open-sources its clients and crypto libraries precisely so this kind of study is
possible.

> This project is a **learning / reference** reconstruction. It is *inspired by*
> Proton Mail's publicly documented design. It is not affiliated with Proton AG,
> does not use Proton's branding, and must never be deployed to impersonate Proton
> or collect anyone's real Proton credentials.

## How this repo is organized

```
proton-mail/
├── README.md                 ← you are here
├── docs/
│   └── dossier/              ← the reverse-engineering design dossier (deliverable 1)
│       ├── 00-overview.md             system map + threat model
│       ├── 01-cryptography.md         OpenPGP usage + the key hierarchy
│       ├── 02-authentication-srp.md   SRP-6a login, 2FA, sessions
│       ├── 03-key-management.md        keyserver + Key Transparency
│       ├── 04-mail-data-flow.md        E2E, zero-access, outgoing, storage
│       ├── 05-system-architecture.md   components and how they connect
│       ├── 06-open-source-map.md       Proton's real repos = our sources
│       └── 07-reconstruction-plan.md   how our Java system maps to the design
├── reference-system/         ← the working Java reconstruction (deliverable 2)
└── ai-collab/                ← the human+AI teamwork log (audit trail)
    ├── prompts/              every task handed to manzi (Qwen 14B)
    └── outputs/              what manzi produced, before review
```

## The team

| Member | Role |
|--------|------|
| **Claude (Opus)** | research & synthesis, architecture, integration, review, final code |
| **manzi / `manzi-14b`** (Qwen 2.5 Coder 14B, local via Ollama) | drafts Java classes and tests from precise specs |

Every delegation to `manzi` is written to `ai-collab/prompts/NN-*.md`; its raw output
lands in `ai-collab/outputs/NN-*` **before** review, so the collaboration is
auditable and nothing it writes is trusted blindly.

Delegation channel: `http://localhost:11434/api/generate` (Ollama), model
`manzi-14b:latest`. Helper: `ai-collab/run_manzi.py <prompt-file> <out-file>`.

## Status

- [x] Workspace + AI channel established
- [x] **Dossier (deliverable 1)** — complete: `docs/dossier/00..07` (8 chapters)
- [x] **Reference system (deliverable 2)** — **complete, 10 modules, 45 tests green**
  - [x] `crypto` (RSA-3072 **and Curve25519**) · `srp` · `keyserver` (SKL + Key Transparency) · `auth-server` · `mail` (encrypt-on-arrival)
  - [x] `app` — end-to-end scenario, **SCENARIO PASSED**; `cli` — interactive client
  - [x] `persistence` — durable embedded **H2** repos (survives restart; Postgres = driver swap)
  - [x] `api` — HTTP system **split into auth/keys/mail microservices behind a gateway**, with over-HTTP + restart-durability integration tests; deployable jar + multi-container `docker-compose` + Caddy
  - [x] `mta` — real Apache James encrypt-on-arrival **mailet**
  - [x] `Makefile` — `make test | demo | cli | api | cluster | docker-up`

```bash
make test        # build + run all 45 tests
make demo        # the end-to-end scenario
make cli         # interactive client
make cluster     # the split stack (gateway + auth/keys/mail) in one JVM
make docker-up   # the multi-container distributed stack (needs Docker)
```

`reference-system/USAGE.md` is the developer walkthrough; `reference-system/deployment/`
has the distributed Docker/Caddy stack; `make help` lists every command.

See `reference-system/README.md` for the module guide.

> **Continuing the work?** Read **`HANDOVER.md`** (top level). The remaining tasks are
> handed to the local Qwen model as ready-to-run prompts in **`ai-collab/MANZI_TASKS.md`**
> (run them with `ai-collab/ask-manzi.sh`). Golden rule: after any AI-generated change,
> `mvn -f reference-system/pom.xml test` — never keep a red build.
# proto-mail-REA

# Deployment

The distributed form of ReconMail (dossier chapter 05 / plan M9):

```
caddy (TLS)  →  gateway  →  ┌── auth   (SRP login/sessions)      · own H2 volume
                            ├── keys   (vault + directory + KT)  · own H2 volume
                            └── mail   (store + encrypt-on-arrival, calls keys over HTTP) · own H2 volume
```

Each microservice is a separate process with its own durable database. State
survives restarts (verified by `PersistenceRestartTest`); the whole flow works
across services through the gateway (verified by `DistributedIntegrationTest`).

## Quick commands (from the repo root)

```bash
make test        # build + run all 45 tests
make cluster     # run the split stack (gateway + 3 services) in ONE JVM, on random ports
make api         # run the all-in-one HTTP API on :8080
make jar         # build the runnable jar used by the Docker image
make docker-up   # build images + start the distributed stack (needs Docker)
make docker-down # stop and remove volumes
```

## Run the split stack without Docker (separate processes)

Exactly what the containers do — one image, a main class per service:

```bash
make jar
CP="reference-system/api/target/reconmail-api.jar:reference-system/api/target/lib/*"
PORT=8082 DB_DIR=data/keys java -cp "$CP" com.reconmail.api.KeyServiceMain &
PORT=8081 DB_DIR=data/auth java -cp "$CP" com.reconmail.api.AuthServiceMain &
PORT=8083 DB_DIR=data/mail KEY_SERVICE_URL=http://localhost:8082 java -cp "$CP" com.reconmail.api.MailServiceMain &
PORT=8080 AUTH_URL=http://localhost:8081 KEY_URL=http://localhost:8082 MAIL_URL=http://localhost:8083 \
  java -cp "$CP" com.reconmail.api.GatewayMain &
curl -s localhost:8080/api/v1/auth-server/modulus-key | head -c 80
```

## Containerized stack

```bash
make docker-up    # http://localhost:8080 via Caddy → gateway → services
```

The gateway routes by path prefix and passes the path through unchanged:

| Prefix | Service | Swagger UI |
|--------|---------|------------|
| `/api/v1/auth-server` | auth | http://localhost:8080/api/v1/auth-server/docs |
| `/api/v1/key-server`  | keys | http://localhost:8080/api/v1/key-server/docs |
| `/api/v1/mail-server` | mail | http://localhost:8080/api/v1/mail-server/docs |

Each service also serves its OpenAPI document at `<prefix>/openapi.json`. Only Caddy's
port is published; the services are reachable from the host through it.

One image (`reconmail-service:latest`) is built from `../api/Dockerfile`; each
compose service runs it with a different `command:` (its main class) and env
(ports, DB dir, peer URLs). Base image: `eclipse-temurin:25-jre`. For real TLS,
set a domain in `Caddyfile` and expose 443.

## Config (environment variables)

| Service | Vars |
|---------|------|
| auth    | `PORT` (8081), `DB_DIR` |
| keys    | `PORT` (8082), `DB_DIR` |
| mail    | `PORT` (8083), `DB_DIR`, `KEY_SERVICE_URL` |
| gateway | `PORT` (8080), `AUTH_URL`, `KEY_URL`, `MAIL_URL` |

## Note on storage

Durable embedded **H2** per service. Moving to **Postgres** is a JDBC-URL + driver
swap in the `persistence` module — the repository SQL is standard.

Write a Markdown file USAGE.md for a Java project called ReconMail (a learning
reconstruction of Proton Mail). Audience: a new developer. Output ONLY Markdown.

Cover, concisely and factually:
- Prerequisites: Java 25, Maven.
- Build & test: `mvn -f reference-system/pom.xml test` (state there are ~38 tests).
- Run the interactive CLI: `mvn -f reference-system/cli/pom.xml -q -Dexec.mainClass=com.reconmail.cli.Cli exec:java`
  and show a sample session using these commands: register <email> <password>,
  login <email> <password>, send <from> <to> <subject> <body>, read <email> <msgId> <senderEmail>,
  inbox <email>, accounts, external <from> <to> <subject> <body>.
- Run the end-to-end demo: `mvn -f reference-system/app/pom.xml -q -Dexec.mainClass=com.reconmail.app.EndToEndScenario exec:java`
- Run the HTTP API: `mvn -f reference-system/api/pom.xml -q -Dexec.mainClass=com.reconmail.api.ApiMain exec:java`
  and list its routes: POST /auth/register, POST /auth/info, POST /auth, GET /auth/modulus-key,
  POST /keys, GET /keys/{email}, GET /keys/{email}/proof, POST /messages, POST /messages/external,
  GET /messages/{id}, GET /messages/inbox/{email}.
- One short paragraph per module: crypto, srp, keyserver, auth-server, mail, app, cli, api.
Keep it tight. No invented commands beyond those listed.

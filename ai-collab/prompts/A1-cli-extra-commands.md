You are a senior Java engineer extending an existing class. Output ONLY code
snippets, each under a clear `// ==== PASTE INTO <file> ====` header. Do NOT rewrite
whole files. Do NOT invent any method not listed below.

Context: class `com.reconmail.cli.CliEngine` already has these PRIVATE fields you may
use from inside new methods:
  PgpCrypto pgp; AddressKeyFactory addressKeys; KeyServer keyServer;
  MailStore mailStore; MailPipeline pipeline;
  Map<String, Account> clients;   // Account is a private record; clients.keySet() = registered emails

Available calls (use ONLY these):
  keyServer.directory(String email).keys().get(0).armoredKey()  -> String (recipient public key)
  pipeline.deliverExternalInbound(String id, String from, String to, String subject,
                                  String plaintextBody, String recipientPublicKeyArmored) -> StoredMessage (has .id())
  java.util.UUID.randomUUID().toString().substring(0,8) -> a short id

Task — add TWO public methods to CliEngine:

1. `public String accounts()` — return "accounts: " followed by the registered emails
   (clients.keySet()) comma-separated, or "accounts: (none)".

2. `public String external(String from, String to, String subject, String body) throws Exception`
   — simulate inbound external mail: get the recipient's public key from the directory,
   call pipeline.deliverExternalInbound(...) with a fresh short id, and return
   "delivered external mail to <to> (id=<id>)".

Then provide:
- the two new `case` lines for `com.reconmail.cli.Cli` main switch:
    case "accounts" -> System.out.println(engine.accounts());
    case "external" -> { String[] s = rest.split("\\s+", 4); System.out.println(engine.external(s[0], s[1], s[2], s.length>3?s[3]:"")); }
- one new JUnit test method for CliEngineTest that registers "bob@recon.test"/"pw",
  calls engine.external("ext@gmail.com","bob@recon.test","Hi","hello"), and asserts the
  result contains "delivered external mail".

Output only the three paste-blocks. No prose.

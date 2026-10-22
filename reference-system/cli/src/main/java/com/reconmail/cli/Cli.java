package com.reconmail.cli;

import java.util.Scanner;

/**
 * Thin REPL over {@link CliEngine}. Type {@code help} for commands.
 * Run: {@code mvn -f reference-system/cli/pom.xml -q -Dexec.mainClass=com.reconmail.cli.Cli exec:java}
 *
 * <p>BASE for manzi: to add a command, add a method to {@link CliEngine} and one
 * {@code case} below. Do NOT put crypto here — call the engine. (See HANDOVER.md CLI-1.)</p>
 */
public final class Cli {

    private static final String HELP = """
            commands:
              register <email> <password>
              login    <email> <password>
              send     <from> <to> <subject> <body...>
              read     <email> <msgId> <senderEmail>
              inbox    <email>
              accounts
              external <from> <to> <subject> <body...>
              help | quit""";

    public static void main(String[] args) throws Exception {
        CliEngine engine = new CliEngine();
        Scanner in = new Scanner(System.in);
        System.out.println("ReconMail CLI. Type 'help'.");
        while (true) {
            System.out.print("reconmail> ");
            if (!in.hasNextLine()) {
                break;
            }
            String line = in.nextLine().trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] p = line.split("\\s+", 2);
            String cmd = p[0];
            String rest = p.length > 1 ? p[1] : "";
            try {
                switch (cmd) {
                    case "quit", "exit" -> { return; }
                    case "help" -> System.out.println(HELP);
                    case "register" -> System.out.println(engine.register(arg(rest, 0), arg(rest, 1)));
                    case "login" -> System.out.println(engine.login(arg(rest, 0), arg(rest, 1)));
                    case "send" -> {
                        String[] s = rest.split("\\s+", 4); // from to subject body...
                        System.out.println(engine.send(s[0], s[1], s[2], s.length > 3 ? s[3] : ""));
                    }
                    case "read" -> {
                        String[] s = rest.split("\\s+", 3);
                        System.out.println(engine.read(s[0], s[1], s[2]));
                    }
                    case "inbox" -> System.out.println(engine.inbox(arg(rest, 0)));
                    case "accounts" -> System.out.println(engine.accounts());
                    case "external" -> {
                        String[] s = rest.split("\\s+", 4); // from to subject body...
                        System.out.println(engine.external(s[0], s[1], s[2], s.length > 3 ? s[3] : ""));
                    }
                    default -> System.out.println("unknown command; type 'help'");
                }
            } catch (Exception e) {
                System.out.println("error: " + e.getMessage());
            }
        }
    }

    private static String arg(String rest, int i) {
        String[] parts = rest.split("\\s+");
        if (i >= parts.length || parts[i].isEmpty()) {
            throw new IllegalArgumentException("missing argument " + (i + 1));
        }
        return parts[i];
    }
}

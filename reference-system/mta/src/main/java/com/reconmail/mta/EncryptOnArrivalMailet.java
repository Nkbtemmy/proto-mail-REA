package com.reconmail.mta;

import com.reconmail.keyserver.KeyServer;
import com.reconmail.mail.MailPipeline;
import org.apache.james.core.MailAddress;
import org.apache.mailet.Mail;
import org.apache.mailet.base.GenericMailet;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.util.List;

/**
 * Apache James mailet that applies ReconMail's <b>encrypt-on-arrival</b> (dossier
 * chapter 04 §2) to inbound external mail. For each recipient it looks up the
 * published public key and hands the plaintext to {@link MailPipeline}, which
 * stores only ciphertext; the original plaintext mail is then ghosted.
 *
 * <p>The cryptography lives in {@code MailPipeline} (unit-tested in the mail
 * module). This class is the thin SMTP-side binding: drop it into James'
 * {@code mailetcontainer.xml} in the local-delivery processor, constructed with the
 * running {@link KeyServer} and {@link MailPipeline}.</p>
 */
public class EncryptOnArrivalMailet extends GenericMailet {

    private final KeyServer keyServer;
    private final MailPipeline pipeline;

    public EncryptOnArrivalMailet(KeyServer keyServer, MailPipeline pipeline) {
        this.keyServer = keyServer;
        this.pipeline = pipeline;
    }

    @Override
    public String getMailetInfo() {
        return "ReconMail encrypt-on-arrival mailet";
    }

    @Override
    public void service(Mail mail) throws MessagingException {
        MailAddress sender = mail.getSender();
        String from = sender == null ? "<>" : sender.asString();
        List<String> recipients = mail.getRecipients().stream().map(MailAddress::asString).toList();
        encryptOnArrival(mail.getName(), from, mail.getMessage(), recipients);
        mail.setState(Mail.GHOST); // plaintext consumed; encrypted copies are stored
    }

    /**
     * The mailet's core, independent of the James {@link Mail} plumbing so it can be
     * tested directly: read the subject + body from the message and store a
     * ciphertext copy per recipient via {@link MailPipeline} (encrypt-on-arrival).
     */
    void encryptOnArrival(String name, String from, MimeMessage message, List<String> recipientEmails)
            throws MessagingException {
        try {
            String subject = message.getSubject() == null ? "" : message.getSubject();
            String body = extractText(message);
            for (String email : recipientEmails) {
                String publicKey = keyServer.directory(email).keys().get(0).armoredKey();
                pipeline.deliverExternalInbound(name, from, email, subject, body, publicKey);
            }
        } catch (MessagingException e) {
            throw e;
        } catch (Exception e) {
            throw new MessagingException("encrypt-on-arrival failed", e);
        }
    }

    private static String extractText(MimeMessage message) throws Exception {
        Object content = message.getContent();
        return (content instanceof String s) ? s : String.valueOf(content);
    }
}

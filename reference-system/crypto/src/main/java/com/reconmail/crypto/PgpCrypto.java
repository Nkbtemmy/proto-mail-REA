package com.reconmail.crypto;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

/**
 * OpenPGP crypto core, mirroring how Proton Mail uses PGP (see
 * {@code docs/dossier/01-cryptography.md}).
 *
 * <p>Hybrid OpenPGP: a random session key encrypts the body symmetrically
 * (AES-256, integrity-protected), and that session key is wrapped to the
 * recipient's public key. Messages are signed with the sender's private key
 * using a one-pass signature.</p>
 *
 * <p>This verified profile uses <b>RSA-3072</b> keys because that path is the
 * most robust to pin and test. Proton's production default is
 * <b>Curve25519</b> (Ed25519 signing + X25519 encryption); adding that is a
 * drop-in second profile — only the key-generation method changes.</p>
 */
public final class PgpCrypto {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private final SecureRandom random = new SecureRandom();

    /** An armored public key and an armored, passphrase-encrypted private key. */
    public record KeyPairResult(String publicKeyArmored, String privateKeyArmored) {}

    /** Decrypted plaintext plus whether the attached signature verified. */
    public record DecryptResult(String plaintext, boolean signatureValid) {}

    /** Key algorithm profile. RSA is the verified default; Curve25519 is Proton's production default. */
    public enum Profile { RSA_3072, CURVE25519 }

    /**
     * Generate an OpenPGP key ring (RSA-3072). The secret key ring is encrypted
     * with {@code passphrase} (AES-256) — the ciphertext the server may store.
     */
    public KeyPairResult generateKeyPair(String userId, char[] passphrase) throws PGPException, IOException {
        return generateKeyPair(userId, passphrase, Profile.RSA_3072);
    }

    /**
     * Generate an OpenPGP key ring with the chosen profile. {@code CURVE25519}
     * builds an Ed25519 signing master + an X25519 encryption subkey — matching
     * Proton's default (dossier chapter 01 §1). Encrypt/decrypt/sign are
     * algorithm-agnostic, so the rest of this class works unchanged.
     */
    public KeyPairResult generateKeyPair(String userId, char[] passphrase, Profile profile)
            throws PGPException, IOException {
        try {
            PGPDigestCalculator sha1 = new JcaPGPDigestCalculatorProviderBuilder().setProvider(BC).build()
                    .get(HashAlgorithmTags.SHA1);
            PGPDigestCalculator sha256 = new JcaPGPDigestCalculatorProviderBuilder().setProvider(BC).build()
                    .get(HashAlgorithmTags.SHA256);
            var keyEncryptor = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, sha256)
                    .setProvider(BC).build(passphrase);

            PGPKeyRingGenerator ringGen;
            if (profile == Profile.CURVE25519) {
                PGPKeyPair master = new JcaPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY,
                        KeyPairGenerator.getInstance("Ed25519", BC).generateKeyPair(), new Date());
                PGPKeyPair encSubKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH,
                        KeyPairGenerator.getInstance("X25519", BC).generateKeyPair(), new Date());
                JcaPGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(
                        master.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256).setProvider(BC);
                ringGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, master, userId,
                        sha1, null, null, signerBuilder, keyEncryptor);
                ringGen.addSubKey(encSubKey);
            } else {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
                kpg.initialize(3072);
                PGPKeyPair master = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL,
                        kpg.generateKeyPair(), new Date());
                JcaPGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(
                        master.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256).setProvider(BC);
                ringGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, master, userId,
                        sha1, null, null, signerBuilder, keyEncryptor);
            }

            return new KeyPairResult(
                    armor(ringGen.generatePublicKeyRing().getEncoded()),
                    armor(ringGen.generateSecretKeyRing().getEncoded()));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new PGPException("key generation failed", e);
        }
    }

    /** Encrypt {@code plaintext} to the recipient and sign it with the sender's key. */
    public String encryptAndSign(String plaintext, String recipientArmoredPublicKey,
                                 String senderArmoredPrivateKey, char[] senderPassphrase)
            throws PGPException, IOException {

        PGPPublicKey recipientKey = firstEncryptionKey(readPublicKeyRing(recipientArmoredPublicKey));
        PGPSecretKey senderSecret = readSecretKeyRing(senderArmoredPrivateKey).getSecretKey();
        PGPPrivateKey senderPrivate = senderSecret.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider(BC).build())
                        .setProvider(BC).build(senderPassphrase));

        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try (ArmoredOutputStream armored = new ArmoredOutputStream(out)) {
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                            .setWithIntegrityPacket(true).setSecureRandom(random).setProvider(BC));
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(recipientKey).setProvider(BC));

            try (OutputStream encOut = encGen.open(armored, new byte[1 << 16])) {
                PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
                try (OutputStream compOut = compGen.open(encOut)) {
                    PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                            new JcaPGPContentSignerBuilder(senderSecret.getPublicKey().getAlgorithm(),
                                    HashAlgorithmTags.SHA256).setProvider(BC));
                    sigGen.init(PGPSignature.BINARY_DOCUMENT, senderPrivate);

                    Iterator<String> uids = senderSecret.getPublicKey().getUserIDs();
                    if (uids.hasNext()) {
                        PGPSignatureSubpacketGenerator sp = new PGPSignatureSubpacketGenerator();
                        sp.addSignerUserID(false, uids.next());
                        sigGen.setHashedSubpackets(sp.generate());
                    }
                    sigGen.generateOnePassVersion(false).encode(compOut);

                    PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
                    try (OutputStream litOut = litGen.open(compOut, PGPLiteralData.BINARY, "msg",
                            data.length, new Date())) {
                        litOut.write(data);
                        sigGen.update(data);
                    }
                    sigGen.generate().encode(compOut);
                }
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    /** Decrypt a message with the recipient's key and verify the sender's signature. */
    public DecryptResult decryptAndVerify(String armoredMessage, String recipientArmoredPrivateKey,
                                          char[] recipientPassphrase, String senderArmoredPublicKey)
            throws PGPException, IOException {

        PGPSecretKeyRing recipientRing = readSecretKeyRing(recipientArmoredPrivateKey);
        PGPPublicKeyRing senderRing = readPublicKeyRing(senderArmoredPublicKey);

        InputStream in = PGPUtil.getDecoderStream(
                new ByteArrayInputStream(armoredMessage.getBytes(StandardCharsets.UTF_8)));
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(in);

        Object first = factory.nextObject();
        PGPEncryptedDataList encList = (first instanceof PGPEncryptedDataList)
                ? (PGPEncryptedDataList) first : (PGPEncryptedDataList) factory.nextObject();

        PGPPublicKeyEncryptedData encData = null;
        PGPPrivateKey privateKey = null;
        for (Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects(); it.hasNext(); ) {
            PGPEncryptedData ed = it.next();
            if (ed instanceof PGPPublicKeyEncryptedData pked) {
                PGPSecretKey secret = recipientRing.getSecretKey(pked.getKeyID());
                if (secret != null) {
                    privateKey = secret.extractPrivateKey(
                            new JcePBESecretKeyDecryptorBuilder(
                                    new JcaPGPDigestCalculatorProviderBuilder().setProvider(BC).build())
                                    .setProvider(BC).build(recipientPassphrase));
                    encData = pked;
                    break;
                }
            }
        }
        if (encData == null) {
            throw new PGPException("no matching recipient key for this message");
        }

        InputStream clear = encData.getDataStream(
                new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BC).build(privateKey));
        JcaPGPObjectFactory plainFactory = new JcaPGPObjectFactory(clear);

        Object message = plainFactory.nextObject();
        if (message instanceof PGPCompressedData compressed) {
            plainFactory = new JcaPGPObjectFactory(compressed.getDataStream());
            message = plainFactory.nextObject();
        }

        PGPOnePassSignature onePass = null;
        if (message instanceof PGPOnePassSignatureList onePassList) {
            onePass = onePassList.get(0);
            PGPPublicKey signerKey = senderRing.getPublicKey(onePass.getKeyID());
            if (signerKey != null) {
                onePass.init(new JcaPGPContentVerifierBuilderProvider().setProvider(BC), signerKey);
            } else {
                onePass = null; // signer unknown -> cannot verify
            }
            message = plainFactory.nextObject();
        }

        PGPLiteralData literal = (PGPLiteralData) message;
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] buffer = new byte[1 << 16];
        int n;
        try (InputStream lin = literal.getInputStream()) {
            while ((n = lin.read(buffer)) > 0) {
                body.write(buffer, 0, n);
                if (onePass != null) {
                    onePass.update(buffer, 0, n);
                }
            }
        }

        boolean signatureValid = false;
        if (onePass != null) {
            PGPSignatureList sigList = (PGPSignatureList) plainFactory.nextObject();
            signatureValid = onePass.verify(sigList.get(0));
        }
        if (encData.isIntegrityProtected() && !encData.verify()) {
            throw new PGPException("message integrity check failed (possible tampering)");
        }
        return new DecryptResult(body.toString(StandardCharsets.UTF_8), signatureValid);
    }

    /**
     * Produce an ASCII-armored <b>detached signature</b> over {@code text}.
     * Used to sign Signed Key Lists (dossier chapter 03), which are public and
     * signed rather than encrypted.
     */
    public String signDetached(String text, String signerArmoredPrivateKey, char[] passphrase)
            throws PGPException, IOException {
        PGPSecretKey secret = readSecretKeyRing(signerArmoredPrivateKey).getSecretKey();
        PGPPrivateKey priv = secret.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder(
                        new JcaPGPDigestCalculatorProviderBuilder().setProvider(BC).build())
                        .setProvider(BC).build(passphrase));

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(secret.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256)
                        .setProvider(BC));
        sigGen.init(PGPSignature.BINARY_DOCUMENT, priv);
        sigGen.update(text.getBytes(StandardCharsets.UTF_8));
        PGPSignature signature = sigGen.generate();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ArmoredOutputStream aos = new ArmoredOutputStream(bos)) {
            signature.encode(aos);
        }
        return bos.toString(StandardCharsets.UTF_8);
    }

    /** Verify an ASCII-armored detached signature over {@code text}. */
    public boolean verifyDetached(String text, String armoredSignature, String signerArmoredPublicKey)
            throws PGPException, IOException {
        PGPPublicKeyRing signerRing = readPublicKeyRing(signerArmoredPublicKey);
        InputStream in = PGPUtil.getDecoderStream(
                new ByteArrayInputStream(armoredSignature.getBytes(StandardCharsets.UTF_8)));
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(in);
        Object o = factory.nextObject();
        PGPSignatureList sigList = (o instanceof PGPSignatureList)
                ? (PGPSignatureList) o : (PGPSignatureList) factory.nextObject();

        PGPSignature signature = sigList.get(0);
        PGPPublicKey key = signerRing.getPublicKey(signature.getKeyID());
        if (key == null) {
            return false;
        }
        signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider(BC), key);
        signature.update(text.getBytes(StandardCharsets.UTF_8));
        return signature.verify();
    }

    // ---- helpers -----------------------------------------------------------

    public PGPPublicKeyRing readPublicKeyRing(String armored) throws IOException, PGPException {
        try (InputStream in = PGPUtil.getDecoderStream(
                new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)))) {
            PGPPublicKeyRingCollection c = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
            Iterator<PGPPublicKeyRing> it = c.getKeyRings();
            if (it.hasNext()) {
                return it.next();
            }
            throw new PGPException("no public key ring found");
        }
    }

    public PGPSecretKeyRing readSecretKeyRing(String armored) throws IOException, PGPException {
        try (InputStream in = PGPUtil.getDecoderStream(
                new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)))) {
            PGPSecretKeyRingCollection c = new PGPSecretKeyRingCollection(in, new JcaKeyFingerprintCalculator());
            Iterator<PGPSecretKeyRing> it = c.getKeyRings();
            if (it.hasNext()) {
                return it.next();
            }
            throw new PGPException("no secret key ring found");
        }
    }

    private static PGPPublicKey firstEncryptionKey(PGPPublicKeyRing ring) throws PGPException {
        for (Iterator<PGPPublicKey> it = ring.getPublicKeys(); it.hasNext(); ) {
            PGPPublicKey k = it.next();
            if (k.isEncryptionKey()) {
                return k;
            }
        }
        throw new PGPException("recipient key ring has no encryption-capable key");
    }

    private static String armor(byte[] data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ArmoredOutputStream aos = new ArmoredOutputStream(bos)) {
            aos.write(data);
        }
        return bos.toString(StandardCharsets.UTF_8);
    }
}

package org.esimwallet;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.web3j.crypto.*;
import org.web3j.utils.Numeric;

public class ECKeyManagement {

    public static String compressPublicKey(BigInteger pubKey) {
        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
        String pubKeyHex = pubKey.toString(16);
        String pubKeyX = pubKeyHex.substring(0, 64);

        return pubKeyYPrefix + pubKeyX;
    }

    public static String signMessage(String message, ECKeyPair ecKeyPair) {
        byte[] hash = message.getBytes(StandardCharsets.UTF_8);
        Sign.SignatureData signature = Sign.signPrefixedMessage(hash, ecKeyPair);
        String r = Numeric.toHexString(signature.getR());
        String s = Numeric.toHexString(signature.getS()).substring(2);
        String v = Numeric.toHexString(signature.getV()).substring(2);

        return r + s + v;
    }

    public static ECKeyPair generateECKeyPair() throws Exception {
        try {
            // Generate a random private key
            BigInteger privateKey = Keys.createEcKeyPair().getPrivateKey();
            BigInteger publicKey = Sign.publicKeyFromPrivate(privateKey);

            return new ECKeyPair(privateKey, publicKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String deriveAddress(BigInteger publicKey) {
        return "0x" + Keys.getAddress((publicKey));
    }

    public static String generateKeystoreJSON(String walletPassword, String storagePath, ECKeyPair ecKeyPair) throws Exception {
        return WalletUtils.generateWalletFile(
                walletPassword,
                ecKeyPair,
                new File(storagePath),
                true
        );
    }

    public static Credentials decryptCredentials(String keystorePath, String walletPassword) throws Exception {
        return WalletUtils.loadCredentials(walletPassword, keystorePath);
    }

    public static void main(String[] args) throws Exception {
        String walletPassword = "Test123";
        String walletPath = "./src/test/sampleKeystores";

        // Generate a random EC Key Pair
        ECKeyPair keyPair = generateECKeyPair();

        // Derive private key from the EC Key Pair
        BigInteger privateKey = keyPair.getPrivateKey();
        System.out.println("Private key (256 bits): " + privateKey.toString(16));

        // Derive public key from the EC Key Pair
        BigInteger publicKey = keyPair.getPublicKey();
        System.out.println("Public key (512 bits): " + publicKey.toString(16));
        System.out.println("Public key (compressed): " + compressPublicKey(publicKey));

        // Derive address from the public key
        String address = deriveAddress(publicKey);
        System.out.println("Address: " + address);

        // Generate keystore file for the EC Key Pair
        String walletFileName = generateKeystoreJSON(walletPassword, walletPath, keyPair);
        System.out.println(walletFileName);

        String keystorePath = walletPath + File.separator + walletFileName;

        // Unlock keystore
        ECKeyPair derivedKeys = decryptCredentials(keystorePath, walletPassword).getEcKeyPair();
        System.out.println("Unlocked Private key: " + derivedKeys.getPrivateKey().toString(16));
        System.out.println("Unlocked Public Key " + derivedKeys.getPublicKey().toString(16));

        // Sign message
        String msg = "TEST";
        String signedMessage = signMessage(msg, keyPair);
        System.out.println("SignedMessage: " + signedMessage);
    }
}

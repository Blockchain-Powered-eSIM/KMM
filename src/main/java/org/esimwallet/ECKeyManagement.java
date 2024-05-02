package org.esimwallet;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.web3j.crypto.*;
import org.web3j.utils.Numeric;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

public class ECKeyManagement {

	private final static String EC_CURVE = "secp256k1";

	// https://github.com/web3j/web3j/issues/915#issuecomment-483145928
	private static final void setupBouncyCastle() {
		final Provider p = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
		if (p == null || p.getClass().equals(BouncyCastleProvider.class)) {
			return;
		}
		Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
	}

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

	public static String deriveAddress(BigInteger publicKey) {
		return "0x" + Keys.getAddress((publicKey));
	}

	public static String generateKeystoreJSON(String walletPassword, String storagePath, ECKeyPair ecKeyPair) throws Exception {

		try {
			return
					WalletUtils.generateWalletFile(
							walletPassword,
							ecKeyPair,
							new File(storagePath),
							true
					);
		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	public static Credentials decryptCredentials(String keystorePath, String walletPassword) throws Exception {
		return WalletUtils.loadCredentials(walletPassword, keystorePath);
	}

	public static String generateBIP39Mnemonic() throws Exception {
		try {
			SecureRandom random = new SecureRandom();
			byte[] initialEntropy = new byte[16];
			random.nextBytes(initialEntropy);

			String mnemonic = MnemonicUtils.generateMnemonic(initialEntropy);

			return mnemonic;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	// To be used by other native modules, to generate EC Key Pair and securely store it in the android keystore
	// Also creates a password protected Kyestore JSON file in user's mobile device
	public static ECKeyPair generateECKeyPairFromMnemonic(String mnemonic, String password, String destinationDirectory) throws Exception {
		try {
			byte[] seed = MnemonicUtils.generateSeed(mnemonic, password);

			setupBouncyCastle();
			ECKeyPair keyPair = ECKeyPair.create(Hash.sha256(seed));

			String walletFile = WalletUtils.generateWalletFile(password, keyPair, new File(destinationDirectory), false);

			return keyPair;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private static java.security.spec.ECPoint getECPoint(BigInteger publicKeyInt, ECNamedCurveParameterSpec ecParams) {
		byte[] publicKeyBytes = publicKeyInt.toByteArray();
		byte[] correctedBytes;

		if (publicKeyBytes[0] == 0) { // If there's a leading zero byte (sign bit), remove it
			correctedBytes = new byte[publicKeyBytes.length - 1];
			System.arraycopy(publicKeyBytes, 1, correctedBytes, 0, correctedBytes.length);
		} else {
			correctedBytes = publicKeyBytes;
		}

		// Check length to decide if it's just X or X and Y
		ECPoint point;
		if (correctedBytes.length == 32) { // Only X coordinate
			// Prefix with 0x02 or 0x03 to indicate compressed encoding (requires knowing if Y is even or odd)
			byte[] encodedPoint = new byte[33];
			encodedPoint[0] = 0x02; // Assume Y is even, change to 0x03 if Y is odd
			System.arraycopy(correctedBytes, 0, encodedPoint, 1, 32);

			return EC5Util.convertPoint(ecParams.getCurve().decodePoint(encodedPoint));

		} else if (correctedBytes.length == 64) { // Both X and Y coordinates
			byte[] encodedPoint = new byte[65];
			encodedPoint[0] = 0x04; // Uncompressed encoding
			System.arraycopy(correctedBytes, 0, encodedPoint, 1, 64);

			return EC5Util.convertPoint(ecParams.getCurve().decodePoint(encodedPoint));

		} else {
			throw new IllegalArgumentException("Invalid byte array length: " + correctedBytes.length);
		}
	}

	public static KeyPair convertECKeyPairToKeyPair(ECKeyPair ecKeyPair) throws Exception {
		try {
			// Extract components from ECKeyPair
			BigInteger privateKeyInt = ecKeyPair.getPrivateKey();
			BigInteger publicKeyInt = ecKeyPair.getPublicKey();

			ECNamedCurveParameterSpec paramSpec = ECNamedCurveTable.getParameterSpec(EC_CURVE);
			ECNamedCurveSpec curveSpec = new ECNamedCurveSpec(EC_CURVE, paramSpec.getCurve(), paramSpec.getG(), paramSpec.getN());
			// Create EC private and public key specifications
			ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyInt, curveSpec);
			ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(getECPoint(publicKeyInt, paramSpec), curveSpec);

			// Generate PrivateKey and PublicKey objects
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

			return new KeyPair(publicKey, privateKey);

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	// Generate Wallet from Mnemonic and save into a JSON file
	public static String generateAndSaveWallet(String mnemonic, String password, String destinationDirectory) throws Exception {
		try {
			byte[] seed = MnemonicUtils.generateSeed(mnemonic, password);

			ECKeyPair keyPair = ECKeyPair.create(Hash.sha256(seed));

			String walletFile = WalletUtils.generateWalletFile(password, keyPair, new File(destinationDirectory), false);

			return walletFile;
		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	public static String loadCredentialsFromFile(String password, String filePath) throws Exception {
		try {
			Credentials cred = WalletUtils.loadCredentials(password, filePath);
			ECKeyPair keyPair = cred.getEcKeyPair();
			String address = cred.getAddress();
			String privateKey = keyPair.getPrivateKey().toString(16);
			String publicKey = keyPair.getPublicKey().toString(16);

			return address;
		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	public static ECKeyPair generateECKeyPair() throws Exception {
		try {
			// Setup Bouncy Castle.
			setupBouncyCastle();
			// Generate a random private key
			BigInteger privateKey = Keys.createEcKeyPair().getPrivateKey();
			BigInteger publicKey = Sign.publicKeyFromPrivate(privateKey);

			ECKeyPair ec = new ECKeyPair(privateKey, publicKey);

			return ec;

		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	public static void main(String[] args) throws Exception {
		String walletPassword = "Test123";
		String walletPath = "./sampleKeystores";

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

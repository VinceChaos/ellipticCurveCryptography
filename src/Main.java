import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {
    public static void main(String[] args) throws Exception {
        /*
          This program utilizes the BouncyCastle Java API
          https://www.bouncycastle.org/download/bouncy-castle-java/#latest
         */
        Security.addProvider(new BouncyCastleProvider());

// Obtain user input
        Scanner in = new Scanner(System.in);
        System.out.println("Enter a message to be encrypted:");
        String originalMessage = in.nextLine();

// Generate an ECC key pair
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

// Encrypt Message
        byte[] cipherText = encryptMessage(originalMessage, publicKey);
        System.out.println("Original message: " + originalMessage);
        System.out.println("ECC Encrypted message: " + new String(cipherText));

// Decrypt Message
        String originalText = decryptMessage(cipherText, privateKey);
        System.out.println("Decrypted message: " + originalText);
    }

    /**
     * Generates a new ECC key pair using the secp256k1 curve.
     *
     * @return A KeyPair object containing the generated private and public keys.
     * @throws Exception If key generation fails.
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Encrypts a message using the provided public key with ECIES.
     *
     * @param message   The plaintext message to be encrypted.
     * @param publicKey The public key used for encryption.
     * @return The encrypted message as a byte array.
     * @throws Exception If encryption fails.
     */
    public static byte[] encryptMessage(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    /**
     * Decrypts an encrypted message using the provided private key with ECIES.
     *
     * @param cipherText The encrypted message as a byte array.
     * @param privateKey The private key used for decryption.
     * @return The decrypted plaintext message.
     * @throws Exception If decryption fails.
     */
    public static String decryptMessage(byte[] cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(cipherText));
    }
}
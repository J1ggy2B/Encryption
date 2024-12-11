package com.encrypt;
import java.math.BigInteger;
import java.security.SecureRandom;
public class Encrypt {


	    public static void main(String[] args) {
	        // Generate RSA key pair
	        RSAKeyPair keyPair = generateKeyPair(1024);

	        // Message to encrypt
	        String message = "My Password Here!";

	        // Encrypt the message
	        BigInteger ciphertext = encrypt(keyPair.publicKey, message);

	        // Decrypt the message
	        String decryptedMessage = decrypt(keyPair.privateKey, ciphertext);

	        // Print results
	        System.out.println("Public Key: " + keyPair.publicKey);
	        System.out.println("Private Key: " + keyPair.privateKey);
	        System.out.println("Original Message: " + message);
	        System.out.println("Ciphertext: " + ciphertext);
	        System.out.println("Decrypted Message: " + decryptedMessage);
	    }

	    // Generate RSA key pair
	    private static RSAKeyPair generateKeyPair(int keySize) {
	        SecureRandom random = new SecureRandom();
	        BigInteger p = BigInteger.probablePrime(keySize / 2, random);
	        BigInteger q = BigInteger.probablePrime(keySize / 2, random);
	        BigInteger n = p.multiply(q);
	        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
	        BigInteger e = BigInteger.valueOf(65537); // Common public exponent
	        BigInteger d = e.modInverse(phi); // Private key exponent
	        return new RSAKeyPair(new RSAKey(e, n), new RSAKey(d, n));
	    }

	    // Encrypt message using public key
	    private static BigInteger encrypt(RSAKey publicKey, String message) {
	        BigInteger m = new BigInteger(message.getBytes());
	        return m.modPow(publicKey.exponent, publicKey.modulus);
	    }

	    // Decrypt message using private key
	    private static String decrypt(RSAKey privateKey, BigInteger ciphertext) {
	        BigInteger m = ciphertext.modPow(privateKey.exponent, privateKey.modulus);
	        return new String(m.toByteArray());
	    }

	    // Simple class to represent RSA keys
	    private static class RSAKey {
	        BigInteger exponent;
	        BigInteger modulus;

	        public RSAKey(BigInteger exponent, BigInteger modulus) {
	            this.exponent = exponent;
	            this.modulus = modulus;
	        }

	        @Override
	        public String toString() {
	            return "(e=" + exponent + ", n=" + modulus + ")";
	        }
	    }

	    // Class to hold both public and private keys
	    private static class RSAKeyPair {
	        RSAKey publicKey;
	        RSAKey privateKey;

	        public RSAKeyPair(RSAKey publicKey, RSAKey privateKey) {
	            this.publicKey = publicKey;
	            this.privateKey = privateKey;
	        }
	    }



}

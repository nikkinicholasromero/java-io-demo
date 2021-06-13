package com.demo;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class FileEncryption {
    private static final String password = "asdosfu8901ens98fy2nr89ssdf1f";
    private static final String galleryFolder = "C:\\Users\\nikki\\Desktop\\Gallery\\";
    private static final String encryptedGalleryFolder = "C:\\Users\\nikki\\Desktop\\Encrypted_Gallery\\";

    public static void main(String[] args) throws Exception {
        String fromFile = galleryFolder + "Capture.PNG";
        String toFile = encryptedGalleryFolder + "Capture.PNG";

        CryptoUtils.encryptFile(fromFile, toFile, password);
        CryptoUtils.decryptFile(fromFile, toFile, password);
    }
}

class CryptoUtils {
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;

    public static void encryptFile(String fromFile, String toFile, String password) throws Exception {
        byte[] fileContent = Files.readAllBytes(Paths.get(fromFile));
        byte[] encryptedText = encrypt(fileContent, password);
        Path path = Paths.get(toFile);
        Files.write(path, encryptedText);

        File file = new File(fromFile);
        if (file.delete()) {
            System.out.println("Original file deleted. ");
        }
    }

    public static void decryptFile(String fromFile, String toFile, String password) throws Exception {
        byte[] encryptedText = decryptFile(toFile, password);
        Path path = Paths.get(fromFile);
        Files.write(path, encryptedText);
        File file = new File(toFile);
        if (file.delete()) {
            System.out.println("Encrypted file deleted. ");
        }
    }

    private static byte[] decryptFile(String fromEncryptedFile, String password) throws Exception {
        byte[] fileContent = Files.readAllBytes(Paths.get(fromEncryptedFile));
        return decrypt(fileContent, password);
    }

    private static byte[] encrypt(byte[] pText, String password) throws Exception {
        byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);
        byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] cipherText = cipher.doFinal(pText);

        return ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array();
    }

    private static byte[] decrypt(byte[] cText, String password) throws Exception {
        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[12];
        bb.get(iv);

        byte[] salt = new byte[16];
        bb.get(salt);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        return cipher.doFinal(cipherText);
    }

    private static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
}

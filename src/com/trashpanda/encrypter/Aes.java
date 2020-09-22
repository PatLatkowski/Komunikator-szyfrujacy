package com.trashpanda.encrypter;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class Aes {
    public static final String AES_KEY_NAME = Encrypter.ID + "AESSymetricKey.key";
    public static final String AES_ENCRYPTED_FILE_EXTENSION = ".enc";
    public static final String TEMP_TEXT = "temp_text";
    public static final String ENCRYPTION_TYPE_CBC = "AES/CBC/PKCS5Padding";
    public static final String ENCRYPTION_TYPE_ECB = "AES/ECB/PKCS5Padding";
    public static final String ENCRYPTION_TYPE_CFB = "AES/CFB/PKCS5Padding";
    public static final String ENCRYPTION_TYPE_OFB = "AES/OFB/PKCS5Padding";
    private final byte[] salt = "00001111x".getBytes();

    private Encrypter encrypter;
    private String ivName = "IV.vec";
    private File ivFile;
    private IvParameterSpec ivParameterSpec;
    private byte[] iv;
    private Cipher cipher;
    private SecretKey secretKey;

    public Aes(Encrypter encrypter){
        this.encrypter = encrypter;
        createKey();// do usuniecia
    }

    public File getIvFile() {
        return ivFile;
    }

    public File getSecretKeyFile() {
        return new File(AES_KEY_NAME);
    }

    public void createKey(){
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            secretKey = keyGenerator.generateKey();
            saveKey(secretKey);
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    public static String toHexString(byte[] hash)
    {
        BigInteger number = new BigInteger(1, hash);
        StringBuilder hexString = new StringBuilder(number.toString(16));

        while (hexString.length() < 32)
        {
            hexString.insert(0, '0');
        }
        return hexString.toString();
    }

    public void createOwnKeyFromPassword(String password){
        try{
            char[] pass = password.toCharArray();
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(pass, salt, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            System.out.println(secretKey.getEncoded());

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private void saveKey(SecretKey secretKey) throws IOException {
        try(FileOutputStream fileOutputStream = new FileOutputStream(AES_KEY_NAME);){
            byte[] keyBuffor = secretKey.getEncoded();
            fileOutputStream.write(keyBuffor);
        }
    }

    public void loadKey(File fileKey){
        try {
            byte[] keyBuffor = Files.readAllBytes(fileKey.toPath());
            secretKey = new SecretKeySpec(keyBuffor, "AES");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void loadIV(File fileIV){
        try {
            byte[] keyBuffor = Files.readAllBytes(fileIV.toPath());
            ivParameterSpec = new IvParameterSpec(keyBuffor);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /*private boolean checkIfKeyExists(){
        File tmpDir = new File(aesKeyName);
        if(tmpDir.exists()) return true;
        return false;
    }*/

    private void createIV(){
        iv = new byte[128/8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
        ivFile = new File(ivName);
        try(FileOutputStream fileOutputStream = new FileOutputStream(ivFile);){
            fileOutputStream.write(iv);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getPasswordFromUser(){
        String pass = JOptionPane.showInputDialog("Wprowadź hasło do klucza prywatnego", "123456");
        return pass;
    }

    public void encryptPrivateKey(File privateKey, String directory){
        createOwnKeyFromPassword(getPasswordFromUser());
        ivName = directory + ivName;
        initializeEncryptCipher(ENCRYPTION_TYPE_CBC);
        File encryptedFile = new File(directory + privateKey.getName() + AES_ENCRYPTED_FILE_EXTENSION);
        try(FileInputStream fileInputStream = new FileInputStream(privateKey);
            FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile);){
            byte[] inBuffor = new byte[1024];
            int length;
            while((length = fileInputStream.read(inBuffor)) != -1){
                byte[] outBuffor = cipher.update(inBuffor, 0, length);
                if (outBuffor != null) fileOutputStream.write(outBuffor);
            }
            byte[] outBuffor = cipher.doFinal();
            if (outBuffor != null) fileOutputStream.write(outBuffor);
        } catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        privateKey.delete();
    }

    public File decryptPrivateKey(String directory, String pvtKeyName){
        createOwnKeyFromPassword(getPasswordFromUser());
        File encryptedPvtFile = new File(directory + pvtKeyName + AES_ENCRYPTED_FILE_EXTENSION);
        ivName = directory + ivName;
        initializeDecryptCipher(ENCRYPTION_TYPE_CBC, new File(ivName));
        File decryptedPvtKey = new File(directory + pvtKeyName);
        try(FileInputStream fileInputStream = new FileInputStream(encryptedPvtFile);
            FileOutputStream fileOutputStream = new FileOutputStream(decryptedPvtKey);){
            byte[] inBuffor = new byte[1024];
            int length;
            while((length = fileInputStream.read(inBuffor)) != -1){
                byte[] outBuffor = cipher.update(inBuffor, 0, length);
                if (outBuffor != null) fileOutputStream.write(outBuffor);
            }
            byte[] outBuffor = cipher.doFinal();
            if (outBuffor != null) fileOutputStream.write(outBuffor);
        } catch (IOException | IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            decryptedPvtKey = null;
        }
        return decryptedPvtKey;
    }

    public File encryptString(String strToEncrypt, String cipherType){
        initializeEncryptCipher(cipherType);
        File tempTextFile = new File(TEMP_TEXT);
        try (FileOutputStream fileOutputStream = new FileOutputStream(tempTextFile);){
            byte[] input = strToEncrypt.getBytes("UTF-8");
            byte[] encoded = cipher.doFinal(input);
            fileOutputStream.write(encoded);
        } catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }
        return tempTextFile;

        /*try {
            return new String(cipher.doFinal((Base64.getDecoder().decode(strToEncrypt))));
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return "x";*/
    }

    public String decryptString(File strToDecrypt, File fileIV, String cipherType){
        initializeDecryptCipher(cipherType, fileIV);
        try {
            byte[] encoded = Files.readAllBytes(strToDecrypt.toPath());
            return new String(cipher.doFinal(encoded), "UTF-8");
        } catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }
        /*try {
            return new String(cipher.doFinal((Base64.getDecoder().decode(strToDecrypt))));
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }*/
        return "x";
    }

    public File encryptFile(File fileToEncrypt, String cipherType){
        initializeEncryptCipher(cipherType);
        File encryptedFile = new File(fileToEncrypt.getName() + AES_ENCRYPTED_FILE_EXTENSION);
        try(FileInputStream fileInputStream = new FileInputStream(fileToEncrypt);
            FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile);){
            byte[] inBuffor = new byte[1024];
            int length;
            long fileSize = fileToEncrypt.length();
            long totalLength = 0;
            encrypter.initializeProgressBar("AES Encrypting");
            while((length = fileInputStream.read(inBuffor)) != -1){
                totalLength += length;
                int n = (int)(((double)totalLength/fileSize)*100);
                encrypter.updateProgressBar(n);
                byte[] outBuffor = cipher.update(inBuffor, 0, length);
                if (outBuffor != null) fileOutputStream.write(outBuffor);
            }
            encrypter.resetProgressBar();
            byte[] outBuffor = cipher.doFinal();
            if (outBuffor != null) fileOutputStream.write(outBuffor);
        } catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return encryptedFile;
    }

    public File decryptFile(File fileToDecrypt, File fileIV, String cipherType){
        initializeDecryptCipher(cipherType, fileIV);
        String fileName = fileToDecrypt.getName();
        File decryptedFile = new File(fileName.substring(0, (fileName.length() - AES_ENCRYPTED_FILE_EXTENSION.length())));
        try(FileInputStream fileInputStream = new FileInputStream(fileToDecrypt);
            FileOutputStream fileOutputStream = new FileOutputStream(decryptedFile);){
            byte[] inBuffor = new byte[1024];
            int length;
            long fileSize = fileToDecrypt.length();
            long totalLength = 0;
            encrypter.initializeProgressBar("AES Decrypting");
            while((length = fileInputStream.read(inBuffor)) != -1){
                totalLength += length;
                int n = (int)(((double)totalLength/fileSize)*100);
                encrypter.updateProgressBar(n);
                byte[] outBuffor = cipher.update(inBuffor, 0, length);
                if (outBuffor != null) fileOutputStream.write(outBuffor);
            }
            byte[] outBuffor = cipher.doFinal();
            if (outBuffor != null) fileOutputStream.write(outBuffor);
        } catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return decryptedFile;
    }

    private void initializeDecryptCipher(String cipherType, File fileIV) {
        try {
            System.out.println("Szyfrowanie: " + cipherType);
            if(cipherType.equals(ENCRYPTION_TYPE_ECB)){
                cipher = Cipher.getInstance(cipherType);
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            } else {
                loadIV(fileIV);
                cipher = Cipher.getInstance(cipherType);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private void initializeEncryptCipher(String cipherType) {
        try {
            System.out.println("Szyfrowanie: " + cipherType);
            if(cipherType.equals(ENCRYPTION_TYPE_ECB)){
                cipher = Cipher.getInstance(cipherType);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } else {
                createIV();
                cipher = Cipher.getInstance(cipherType);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

}

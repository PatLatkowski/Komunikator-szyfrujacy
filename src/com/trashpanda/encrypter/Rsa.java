package com.trashpanda.encrypter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Rsa {
    private final String PRIVATE_KEY_EXTENSION = ".key";
    private final String PUBLIC_KEY_EXTENSION = ".pub";

    private PublicKey publicKey;
    private PublicKey publicKeyRecived;
    private PrivateKey privateKey;
    private String publicKeyName="public\\" + Encrypter.ID + "testKey";
    private String privateKeyName="private\\" + Encrypter.ID + "testKey";
    private Aes localAES;

    private boolean wrongPassword = false;
    public boolean isWrongPassword() {
        return wrongPassword;
    }

    public void setWrongPassword(boolean wrongPassword) {
        this.wrongPassword = wrongPassword;
    }

    public Rsa(Aes aes){
        try {
            localAES = aes;
            initializeKeys();
            //System.err.println("Private key format: " + privateKey.getFormat());
            //System.err.println("Public key format: " + publicKey.getFormat());

        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    public File encryptFile(File fileToEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyRecived);
        String encrFileName = fileToEncrypt.getName().replaceFirst("[.][^.]+$", "");
        encrFileName += ("_RSA_Encrypted" + PUBLIC_KEY_EXTENSION);
        File encryptedFile =  new File(encrFileName);
        try (FileInputStream fileInputStream = new FileInputStream(fileToEncrypt);
            FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile);){
            byte[] inBuffor = new byte[1024];
            int length;
            while((length = fileInputStream.read(inBuffor)) != -1){
                byte[] outBuffor = cipher.update(inBuffor, 0, length);
                if (outBuffor != null) fileOutputStream.write(outBuffor);
            }
            byte[] outBuffor = cipher.doFinal();
            if (outBuffor != null) fileOutputStream.write(outBuffor);
        }
        return encryptedFile;
    }

    public File decryptFile(File fileToDecrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        File decryptedFile =  new File(Aes.AES_KEY_NAME);
        try (FileInputStream fileInputStream = new FileInputStream(fileToDecrypt);
             FileOutputStream fileOutputStream = new FileOutputStream(decryptedFile);){
            byte[] inBuffor = new byte[1024];
            int length;
            while((length = fileInputStream.read(inBuffor)) != -1){
                byte[] outBuffor = cipher.update(inBuffor, 0, length);
                if (outBuffor != null) fileOutputStream.write(outBuffor);
            }
            byte[] outBuffor = cipher.doFinal();
            if (outBuffor != null) fileOutputStream.write(outBuffor);
        }
        return decryptedFile;
    }

    private void initializeKeys() throws NoSuchAlgorithmException, IOException{
        if(checkIfKeysExists()) {
            System.out.println("Laduje klucze RSA");
            try {
                privateKey = loadPrivateKey();
                publicKey = loadPublicKey();
            } catch (InvalidKeySpecException e) {
                wrongPassword = true;
                privateKey = createFakePrivateKey();
            }
        } else {
            createKeys();
        }
    }

    public PrivateKey createFakePrivateKey(){
        PrivateKey privateKey = null;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        System.out.println("Stworzono falszywy klucz");
        return privateKey;
    }

    private void createKeys() throws NoSuchAlgorithmException, IOException {
        System.out.println("Tworze klucze RSA");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        savePublicKey();
        savePrivateKey();
    }

    private boolean checkIfKeysExists(){
        File tmpDir = new File(privateKeyName + PRIVATE_KEY_EXTENSION + Aes.AES_ENCRYPTED_FILE_EXTENSION);
        if(!tmpDir.exists()) return false;
        tmpDir = new File(publicKeyName + PUBLIC_KEY_EXTENSION);
        if(!tmpDir.exists()) return false;
        return true;
    }

    private PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File decryptedPvtKey = localAES.decryptPrivateKey( "private\\", Encrypter.ID + "testKey" + PRIVATE_KEY_EXTENSION);
        if(decryptedPvtKey == null){
            wrongPassword = true;
            return createFakePrivateKey();
        }
        Path path = decryptedPvtKey.toPath();
        byte[] privateKeyBytes = Files.readAllBytes(path);
        decryptedPvtKey.delete();


        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey loadPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(publicKeyName + PUBLIC_KEY_EXTENSION);
        byte[] publicKeyBytes = Files.readAllBytes(path);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public void loadPublicKeyReceved(File recivedKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Files.readAllBytes(recivedKey.toPath());

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKeyRecived = keyFactory.generatePublic(keySpec);
        System.out.println("Zaladowany klucz publiczny drugiej strony");
    }

    private void savePublicKey() throws IOException {
        File file = new File(publicKeyName + PUBLIC_KEY_EXTENSION);
        file.getParentFile().mkdir();
        FileOutputStream outputStream = new FileOutputStream(file);
        outputStream.write(publicKey.getEncoded());
        outputStream.close();
    }

    private void savePrivateKey() throws IOException {
        File pvtKeyFile = new File(privateKeyName + PRIVATE_KEY_EXTENSION);
        pvtKeyFile.getParentFile().mkdir();
        FileOutputStream outputStream = new FileOutputStream(pvtKeyFile);
        outputStream.write(privateKey.getEncoded());
        outputStream.close();
        localAES.encryptPrivateKey(pvtKeyFile, "private\\");
    }

    public void generateDigitalSignature(String dataFile) throws NoSuchAlgorithmException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        try(InputStream inputStream = new FileInputStream(dataFile)){
            byte[] buffor = new byte[2048];
            int len;
            while ((len = inputStream.read(buffor)) != -1){
                signature.update(buffor, 0, len);
            }
        } catch (IOException | SignatureException e) {
            e.printStackTrace();
        }
    }

    public void setPublicKeyRecived(PublicKey publicKeyRecived) {
        this.publicKeyRecived = publicKeyRecived;
    }

    public Key getPublicKey() {
        return publicKey;
    }

    /*public Key getPrivateKey() {
        return privateKey;
    }*/

    public File getPublicKeyFile(){
        return new File(publicKeyName + PUBLIC_KEY_EXTENSION);
    }
}

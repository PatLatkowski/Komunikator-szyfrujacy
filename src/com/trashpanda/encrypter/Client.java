package com.trashpanda.encrypter;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

public class Client  extends SocketBaseComponent{
    private Socket serverSocket;
    private String serverAddress;
    private Encrypter encrypter;
    private DataInputStream inputStream;
    private DataOutputStream outputStream;
    private int port;
    private volatile boolean stop = false;
    private String pathToSaveRecivedFile = "";
    private String fileName = "";

    private Rsa rsa;
    private Aes aes;

    public Client(String serverAddress, Encrypter encrypter, int port, Rsa rsa){
        this.serverAddress = serverAddress;
        this.encrypter = encrypter;
        this.port = port;
        this.rsa = rsa;
        this.aes = new Aes(encrypter);
    }

    public void run() {
        while(true) {
            try {
                establishConnection();
                keysExchange();
            } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException | NoSuchPaddingException e) {
                e.printStackTrace();
            }
            while(!stop){
                checkIncomingData();
            }
            closeConnection();
        }
    }

    public void sendInfo(String info){
        try {
            outputStream.writeUTF(info);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void prepareFileToSend(File fileToSend){
        File encryptedFile = aes.encryptFile(fileToSend, encrypter.getCipherTypeFromRadioButtons());
        sendInfo(MSG_TYPE_FILE);

        sendFile(aes.getIvFile());
        sendFile(encryptedFile);
    }

    public void prepareStringToSend(String stringToSend){
        File encryptedString = aes.encryptString(stringToSend, encrypter.getCipherTypeFromRadioButtons());
        sendInfo(MSG_TYPE_TEXT);
        sendInfo(encrypter.getCipherTypeFromRadioButtons());
        sendFile(aes.getIvFile());
        sendFile(encryptedString);
    }

    private void keysExchange() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        File publicKeyRecevedFile = reciveFile();
        sendFile(rsa.getPublicKeyFile());
        rsa.loadPublicKeyReceved(publicKeyRecevedFile);
        File encryptedAESkey = reciveFile();
        File decryptedAESkey = rsa.decryptFile(encryptedAESkey);
        aes.loadKey(decryptedAESkey);
    }

    public void sendFile(File file) {
        try {
            outputStream.writeUTF(Long.toString(file.length()));
            outputStream.writeUTF(file.getName());
            FileInputStream fileInputStream = new FileInputStream(file);
            byte[] buffer = new byte[128];
            int count;
            while((count = fileInputStream.read(buffer)) > 0){
                outputStream.write(buffer, 0, count);
            }
            fileInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        encrypter.printInfoForUser("File sent: " + file.getName());
    }

    public File reciveFile() throws IOException {
        long fileSize = Long.parseLong(inputStream.readUTF());
        fileName = inputStream.readUTF();
        File recivedFile = new File(fileName);
        FileOutputStream fileOutputStream = new FileOutputStream(recivedFile);
        byte[] buffer = new byte[128];
        int read = 0;
        int totalRead = 0;
        long remaining = fileSize;
        while((read = inputStream.read(buffer, 0, Math.toIntExact(Math.min(buffer.length, remaining)))) > 0){
            totalRead += read;
            remaining -= read;
            fileOutputStream.write(buffer, 0, read);
        }
        fileOutputStream.close();
        encrypter.printInfoForUser("File recived: " + recivedFile.getName());
        return recivedFile;
    }

    public File reciveFakeFile() throws IOException {
        long fileSize = Long.parseLong(inputStream.readUTF());
        fileName = inputStream.readUTF();
        File recivedFile = new File(fileName);
        FileOutputStream fileOutputStream = new FileOutputStream(recivedFile);
        Random random = new Random();
        byte[] buffer = new byte[128];
        int read = 0;
        int totalRead = 0;
        long remaining = fileSize;
        while((read = inputStream.read(buffer, 0, Math.toIntExact(Math.min(buffer.length, remaining)))) > 0){
            totalRead += read;
            remaining -= read;
            random.nextBytes(buffer);
            fileOutputStream.write(buffer, 0, read);
        }
        fileOutputStream.close();
        encrypter.printInfoForUser("File recived: " + recivedFile.getName());
        return recivedFile;
    }

    private void checkIncomingData(){
        try {
            if (inputStream.available() > 0){
                String typeOfMsg = inputStream.readUTF();
                String typeOfCipher = inputStream.readUTF();
                if(rsa.isWrongPassword()){
                    reciveFakeFile();
                    File fileToPrint = reciveFakeFile();
                    if(typeOfMsg.equals(MSG_TYPE_TEXT))
                        printFakeText(fileToPrint);
                } else{
                    if(typeOfMsg.equals(MSG_TYPE_FILE)){
                        File ivFile = reciveFile();
                        File fileToDecrypt = reciveFile();
                        aes.decryptFile(fileToDecrypt, ivFile, typeOfCipher);
                    } else if (typeOfMsg.equals(MSG_TYPE_TEXT)){
                        File ivFile = reciveFile();
                        File textFile = reciveFile();
                        String decryptedString = aes.decryptString(textFile, ivFile, typeOfCipher);
                        encrypter.printInfoForUser("Client: " + decryptedString);
                    } else
                        encrypter.printInfoForUser("unidentified type of message");
                }
                inputStream.skipBytes(inputStream.available());
                Thread.sleep(100);
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    private void printFakeText(File fileToPrint) {
        try {
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                            new FileInputStream(fileToPrint), "UTF8"));
            String str;
            while ((str = in.readLine()) != null) {
                encrypter.printInfoForUser("Client: " + str);
            }
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void establishConnection(){
        try {
            encrypter.printInfoForUser("Server: Connecting...");
            serverSocket = new Socket(serverAddress, port);
            encrypter.changeServerStatus(Encrypter.ServerStatus.CONNECTED);
            encrypter.printInfoForUser("Server: Connected to: " + serverSocket.getRemoteSocketAddress());
            inputStream = new DataInputStream(serverSocket.getInputStream());
            outputStream = new DataOutputStream(serverSocket.getOutputStream());
        } catch (IOException e){
            e.printStackTrace();
        }
        //createTargetDirectiory("Pobrane");
    }

    private void closeConnection(){
        try {
            inputStream.close();
            outputStream.close();
            serverSocket.close();
            encrypter.changeServerStatus(Encrypter.ServerStatus.OFFLINE);
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    public void sendMessage(String message){
        encrypter.printInfoForUser("Me: " + message);
        try {
            outputStream.writeUTF(MSG_TYPE_TEXT);
            outputStream.writeUTF(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void stopInstance(){
        stop = true;
    }

}

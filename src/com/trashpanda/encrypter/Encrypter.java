package com.trashpanda.encrypter;

import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Encrypter {
    private JPanel mainPanel;
    private JButton buttonConnect;
    private JTextArea textAreaInfo;
    private JButton buttonSendText;
    private JButton buttonChooseFile;
    private JTextField textFieldInput;
    private JLabel labelServerStatus;
    private JTextField textFieldIP;
    private JTextField textFieldFile;
    private JProgressBar progressBar;
    private JRadioButton ECBRadioButton;
    private JRadioButton CBCRadioButton;
    private JRadioButton CFBRadioButton;
    private JRadioButton OFBRadioButton;

    private ServerStatus currentStatus;
    private Thread connectionThread;
    private SocketBaseComponent connectionInstance;
    private Rsa rsa;
    private Aes localAES;

    public static final String ID = "inst1_";
    private static final int PORT = 55555;

    enum ServerStatus {
        READY,
        CONNECTED,
        OFFLINE
    }


    public Encrypter(){
        changeServerStatus(ServerStatus.OFFLINE);
        this.localAES = new Aes(this);
        this.rsa = new Rsa(localAES);
        initListener();


        buttonSendText.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                    connectionInstance.prepareStringToSend(textFieldInput.getText());
            }
        });
        buttonConnect.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                connect(textFieldIP.getText());
            }
        });
        buttonChooseFile.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                File file = chooseFile();
                if(file != null)
                    new Thread(){
                    public void run(){
                        connectionInstance.prepareFileToSend(file);
                        }
                    }.start();
                else System.out.println("Choosing File Error");
            }
        });
    }

    public String getCipherTypeFromRadioButtons(){
        if(ECBRadioButton.isSelected()) return Aes.ENCRYPTION_TYPE_ECB;
        if(CBCRadioButton.isSelected()) return Aes.ENCRYPTION_TYPE_CBC;
        if(CFBRadioButton.isSelected()) return Aes.ENCRYPTION_TYPE_CFB;
        if(OFBRadioButton.isSelected()) return Aes.ENCRYPTION_TYPE_OFB;
        return null;
    }

    public void initializeProgressBar(String nameOfProcess){
        progressBar.setString(nameOfProcess);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
    }

    public void updateProgressBar(int value){
        progressBar.setValue(value);
    }

    public void resetProgressBar(){
        progressBar.setString("");
        progressBar.setValue(0);
    }

    public File chooseFile(){
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File("D:\\_Projekty\\Komunikator_szyfrujacy"));
        int result = fileChooser.showOpenDialog(mainPanel);
        if(result == JFileChooser.APPROVE_OPTION){
            File selectedFile = fileChooser.getSelectedFile();
            printInfoForUser("File selected: " + selectedFile.getAbsolutePath());
            textFieldFile.setText(selectedFile.getAbsolutePath());
            return selectedFile;
        }
        printInfoForUser("File selection failed");
        return null;
    }

    public void changeServerStatus(ServerStatus status){
        if(status != currentStatus){
            if(status == ServerStatus.READY){
                labelServerStatus.setText("READY");
                currentStatus = ServerStatus.READY;
                buttonConnect.setEnabled(true);
            } else if (status == ServerStatus.CONNECTED){
                labelServerStatus.setText("CONNECTED");
                currentStatus = ServerStatus.CONNECTED;
                buttonConnect.setEnabled(false);
            } else if (status == ServerStatus.OFFLINE){
                labelServerStatus.setText("OFFLINE");
                currentStatus = ServerStatus.OFFLINE;
                buttonConnect.setEnabled(true);
            }
        }
    }

    private void connect(String serverName){
        connectionInstance.stopInstance();
        try {
            connectionThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
            printInfoForUser("Server: InterruptedException");
        }
        connectionInstance = new Client(serverName, this, PORT, rsa);
        connectionThread = new Thread(connectionInstance);
        connectionThread.start();
    }

    public void printInfoForUser(String string){
        textAreaInfo.append(string + "\n");
    }

    private static JFrame initialize(String title){
        JFrame frame = new JFrame(title);
        frame.setContentPane(new Encrypter().mainPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1000,400);
        frame.setResizable(false);
        frame.setVisible(true);


        return frame;
    }

    private void initListener(){
        // check port
        connectionInstance = new Server(PORT ,this, rsa);
        connectionThread = new Thread(connectionInstance);
        connectionThread.start();
    }

    public static void main(String[] args)
    {
        JFrame frame = initialize("Encrypter");
    }
}

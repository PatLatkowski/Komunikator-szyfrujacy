package com.trashpanda.encrypter;

import java.io.File;

public class SocketBaseComponent extends Thread{

    public static final String MSG_TYPE_TEXT = "text";
    public static final String MSG_TYPE_FILE = "file";

    private int counter = 0;

    public void run(){
        System.out.println("SocketBaseComponent: running");
    }

    public void sendMessage(String message){
        System.out.println("SocketBaseComponent: sending msg");
    }

    public void sendFile(File file){
        System.out.println("SocketBaseComponent: sending file");
    }

    public void stopInstance(){
        System.out.println("SocketBaseComponent: stopping");
    }

    public void prepareFileToSend(File fileToSend){}

    public void prepareStringToSend(String stringToSend){}

}

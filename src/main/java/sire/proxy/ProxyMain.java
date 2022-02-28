package sire.proxy;

import sire.serverProxyUtils.SireException;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ProxyMain {
    public static void main(String[] args) {
        try {
            ServerSocket ss = new ServerSocket(2500 + Integer.parseInt(args[0]));
            while(true) {
                Socket s = ss.accept();
                new SireProxy(Integer.valueOf(args[0]), s).start();
                System.out.println("Connection accepted");
            }
        } catch (IOException | SireException e) {
            e.printStackTrace();
        }
    }
}

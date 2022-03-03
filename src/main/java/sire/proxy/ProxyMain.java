package sire.proxy;

import sire.serverProxyUtils.SireException;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ProxyMain {
    public static void main(String[] args) {
        try {
            ServerSocket ss = new ServerSocket(2500 + Integer.parseInt(args[0]));
            Socket s;
            Object socketLock = new Object();
            while(true) {
                synchronized (socketLock) {
                    s = ss.accept();
                }
                System.out.println("New client!");
                new SireProxy(Integer.valueOf(args[0]), s).run();
                System.out.println("Connection accepted");
            }
        } catch (IOException | SireException e) {
            e.printStackTrace();
        }
    }
}

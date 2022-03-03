package sire.proxy;

import sire.serverProxyUtils.SireException;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ProxyMain {
/*    public static void main(String[] args) {
        try {
            ServerSocket ss = new ServerSocket(2500 + Integer.parseInt(args[0]));
            Socket s;
            Object socketLock = new Object();
            while(true) {
                synchronized (socketLock) {
                    s = ss.accept();
                }
                System.out.println("New client!");
                new SireProxy(Integer.valueOf(args[0]), s).start();
                System.out.println("Connection accepted");
            }
        } catch (IOException | SireException e) {
            e.printStackTrace();
        }
    }*/

    public static void main(String[] args) {
        SireProxy proxy = null;
        try {
            proxy = new SireProxy(Integer.parseInt(args[0]));
        } catch (SireException e) {
            e.printStackTrace();
        }
        proxy.run();
    }
}

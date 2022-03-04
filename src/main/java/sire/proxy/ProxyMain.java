package sire.proxy;

import sire.serverProxyUtils.SireException;


public class ProxyMain {
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

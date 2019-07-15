package org.apache.hadoop.yarn.util;


public class ClientIp {

    private static ThreadLocal<String> clientIp = new ThreadLocal<String>();

    public static String getClientIp(){
        String ip = clientIp.get();
        clientIp.set("");
        return ip;
    }

    public static void setClientIp(String ip){
        clientIp.set( ip );
    }

}

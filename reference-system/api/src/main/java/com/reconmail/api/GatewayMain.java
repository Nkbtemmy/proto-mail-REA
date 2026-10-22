package com.reconmail.api;

/** Standalone API gateway. Config: PORT (8080), AUTH_URL, KEY_URL, MAIL_URL. */
public final class GatewayMain {

    public static void main(String[] args) throws Exception {
        int port = Env.getInt("PORT", 8080);
        String authUrl = Env.get("AUTH_URL", "http://localhost:8081");
        String keyUrl = Env.get("KEY_URL", "http://localhost:8082");
        String mailUrl = Env.get("MAIL_URL", "http://localhost:8083");
        Gateway gateway = new Gateway(port, authUrl, keyUrl, mailUrl);
        gateway.start();
        System.out.println("gateway listening on :" + gateway.port()
                + " → auth=" + authUrl + " keys=" + keyUrl + " mail=" + mailUrl);
        Runtime.getRuntime().addShutdownHook(new Thread(gateway::stop));
    }
}

package ca.ciralabs;

import java.util.Date;

class Token {

    private String token;
    private boolean success;
    private Date expiry;

    Token(String token, boolean success, Date expiry) {
        this.token = token;
        this.success = success;
        this.expiry = expiry;
    }

    String getToken() {
        return token;
    }

    boolean isSuccess() {
        return success;
    }

    Date getExpiry() {
        return expiry;
    }

}

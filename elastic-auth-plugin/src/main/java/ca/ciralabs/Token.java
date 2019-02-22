package ca.ciralabs;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

class Token {

    private String token;
    private boolean success;
    private boolean authorized;
    private String expiry;
    private int userType;

    Token(String token, boolean success, boolean authorized, Date expiry, int userType) {
        this.token = token;
        this.success = success;
        this.authorized = authorized;
        this.expiry = expiry != null ? DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.ofInstant(expiry.toInstant(), ZoneOffset.UTC)) : "";
        this.userType = userType;
    }

    String getToken() {
        return token;
    }

    boolean isSuccessful() {
        return success;
    }

    boolean isAuthorized() {
        return authorized;
    }

    String getExpiry() {
        return expiry;
    }

    int getUserType() {
        return userType;
    }

}

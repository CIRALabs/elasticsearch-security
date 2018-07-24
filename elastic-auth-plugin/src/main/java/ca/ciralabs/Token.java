package ca.ciralabs;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

class Token {

    private String token;
    private boolean success;
    private String expiry;

    Token(String token, boolean success, Date expiry) {
        this.token = token;
        this.success = success;
        this.expiry = expiry != null ? DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.ofInstant(expiry.toInstant(), ZoneOffset.UTC)) : "";
    }

    String getToken() {
        return token;
    }

    boolean isSuccessful() {
        return success;
    }

    String getExpiry() {
        return expiry;
    }

}

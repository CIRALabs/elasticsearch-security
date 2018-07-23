package ca.ciralabs;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.rest.RestRequest;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import static org.elasticsearch.rest.RestRequest.Method;

class Bouncer {

    private static final int MASTER = 7;
    // private static final int DEVELOPER = 6;
    // private static final int USER = 4;

    // Using these as placeholders until schema definition
    private static final String ELASTIC_USER_TYPE_ATTRIBUTE = "destinationindicator";
    private static final String ELASTIC_INDEX_PERM_ATTRIBUTE = "description";
    private static final String[] LDAP_ATTRIBUTES_BASIC = {"userpassword", ELASTIC_USER_TYPE_ATTRIBUTE, ELASTIC_INDEX_PERM_ATTRIBUTE};
    private static final String[] LDAP_ATTRIBUTES_BEARER = {ELASTIC_USER_TYPE_ATTRIBUTE, ELASTIC_INDEX_PERM_ATTRIBUTE};

    private static final Logger logger = ESLoggerFactory.getLogger(Bouncer.class);

    private static final Charset ASCII_CHARSET = Charset.forName("US-ASCII");
    private static final String USER_CLAIM = "user";
    private static final String ISSUER = "ciralabs";
    private static final Algorithm ALGORITHM = Algorithm.HMAC256("KeepItSecret,KeepItSafe");
    private static final JWTVerifier VERIFIER = JWT.require(ALGORITHM).withIssuer(ISSUER).build();

    private class MalformedAuthHeaderException extends Throwable {}
    private static class Credentials {
        private CharBuffer buffer;
        private boolean isBasicAuth;
        private Credentials(CharBuffer buffer, boolean isBasicAuth) {
            this.buffer = buffer;
            this.isBasicAuth = isBasicAuth;
        }
        private CharBuffer getBuffer() { return buffer; }
        private boolean isBasicAuth() { return isBasicAuth; }
    }

    boolean requestIsAllowed(RestRequest request) {
        try {
            Credentials credentials = extractCredentialsFromRequest(request);
            return credentials.isBasicAuth() ? handleBasicAuth(request, credentials.getBuffer()) : handleBearerAuth(request, credentials.getBuffer());
        }
        catch (MalformedAuthHeaderException e) {
            logger.error("RestRequest did not have valid Authorization Header!");
            return false;
        }
    }

    private boolean handleBasicAuth(RestRequest request, CharBuffer credentials) {
        int endOfUsernameIndex = -1;
        for (int i = 0; i < credentials.length(); i++) {
            if (credentials.get(i) == ':') {
                endOfUsernameIndex = i;
            }
        }
        // Ensure that username:password was found in header
        if (endOfUsernameIndex == -1) {
            return false;
        }
        CharBuffer username = credentials.subSequence(0, endOfUsernameIndex);
        CharBuffer password = credentials.subSequence(endOfUsernameIndex + 1, credentials.length());
        SearchResult searchResult = queryLdap(username.toString(), LDAP_ATTRIBUTES_BASIC);
        if (searchResult == null || searchResult.getEntryCount() == 0) {
            return false;
        }
        else {
            SearchResultEntry entry = searchResult.getSearchEntries().get(0);
            CharBuffer ldapPassword = ASCII_CHARSET.decode(ByteBuffer.wrap(entry.getAttributeValueBytes("userpassword")));
            if (password.equals(ldapPassword)) {
                clearBuffer(credentials);
                clearBuffer(ldapPassword);
                int userType = entry.getAttributeValueAsInteger(ELASTIC_USER_TYPE_ATTRIBUTE);
                String[] permissions = entry.getAttributeValues(ELASTIC_INDEX_PERM_ATTRIBUTE);
                return handlePermission(userType, permissions, request);
            }
            else {
                clearBuffer(credentials);
                clearBuffer(ldapPassword);
                return false;
            }
        }
    }

    private String generateJwt(String username) {
        Calendar cal = Calendar.getInstance();
        Date now = cal.getTime();
        cal.add(Calendar.DAY_OF_YEAR, 1);
        Date tomorrow = cal.getTime();
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        return AccessController.doPrivileged((PrivilegedAction<String>) () ->
            JWT.create()
                .withIssuer(ISSUER)
                .withIssuedAt(now)
                .withExpiresAt(tomorrow)
                .withClaim(USER_CLAIM, username)
                .sign(ALGORITHM)
        );
    }

    private boolean handleBearerAuth(RestRequest request, CharBuffer credentials) {
        try {
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }
            DecodedJWT jwt = AccessController.doPrivileged((PrivilegedAction<DecodedJWT>) () -> VERIFIER.verify(credentials.toString()));
            Claim userClaim = jwt.getClaim(USER_CLAIM);
            if (userClaim != null) {
                SearchResult searchResult = queryLdap(userClaim.asString(), LDAP_ATTRIBUTES_BEARER);
                if (searchResult != null && searchResult.getEntryCount() != 0) {
                    SearchResultEntry entry = searchResult.getSearchEntries().get(0);
                    int userType = entry.getAttributeValueAsInteger(ELASTIC_USER_TYPE_ATTRIBUTE);
                    String[] permissions = entry.getAttributeValues(ELASTIC_INDEX_PERM_ATTRIBUTE);
                    return handlePermission(userType, permissions, request);
                }
            }
            return false;
        }
        catch (JWTVerificationException e) {
            logger.error("Failed to authenticate JWT token", e);
            return false;
        }
    }

    private boolean handlePermission(int userType, String[] permissions, RestRequest request) {
        // Being a master overrides any set permissions
        if (userType != MASTER && permissions.length > 0) {
            // Special permissions are set, check them first
            String index = request.param("index");
            for (String specialPermission : permissions) {
                String[] indexToPerm = specialPermission.split(":");
                if (index.startsWith(indexToPerm[0])) {
                    // This rule matches the request, so is it allowed?
                    return evaluatePermissionOctal(request.method(), Integer.valueOf(indexToPerm[1]));
                }
            }
            // If no special permission matches, fall through to user type permissions
        }
        return evaluatePermissionOctal(request.method(), userType);
    }

    private boolean evaluatePermissionOctal(Method method, int octal) {
        switch (octal) {
            case 4:
                return method == Method.GET || method == Method.HEAD;
            case 6:
                return method != Method.DELETE;
            case 7:
                return true;
            default:
                return false;
        }
    }

    private Credentials extractCredentialsFromRequest(RestRequest request) throws MalformedAuthHeaderException {
        String authHeader = request.header("Authorization");
        if (authHeader.contains("Basic")) {
            return new Credentials(ASCII_CHARSET.decode(ByteBuffer.wrap(Base64.getDecoder().decode(authHeader.replaceFirst("Basic ", "")))), true);
        }
        else if (authHeader.contains("Bearer")) {
            return new Credentials(CharBuffer.wrap(authHeader.replaceFirst("Bearer ", "")), false);
        }
        else {
            throw new MalformedAuthHeaderException();
        }
    }

    private void clearBuffer(CharBuffer buffer) {
        for (int i = 0; i < buffer.length(); i++) {
            buffer.put(i, (char) 0);
        }
    }

    private SearchResult queryLdap(String username, String... attributes) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        return AccessController.doPrivileged((PrivilegedAction<SearchResult>) () -> {
            try (LDAPConnection cnxn = new LDAPConnection("127.0.0.1", 389, "cn=admin,dc=localhost", "password")) {
                Filter filter = Filter.create(String.format("(cn=%s)", username));
                return cnxn.search(new SearchRequest("ou=users,dc=localhost", SearchScope.SUB, filter, attributes));
            }
            catch (LDAPException e) {
                logger.error("Something failed in the LDAP lookup", e);
                return null;
            }
        });
    }

}

package ca.ciralabs;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
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
    private static final String ACCESS_COUNT_CLAIM = "access_count";
    private static final String ISSUER = "ciralabs.ca";
    //TODO This should be read from config, and be a better key
    private static final byte[] SIGNING_KEY = "supersecret".getBytes(ASCII_CHARSET);

    private static final Token FAILURE_TOKEN = new Token(null, false, null);

    private class MalformedAuthHeaderException extends Throwable {}

    Token handleBasicAuth(RestRequest request) {
        CharBuffer credentials;
        try {
            credentials = extractCredentialsFromRequest(request);
        } catch (MalformedAuthHeaderException e) {
            return FAILURE_TOKEN;
        }
        int endOfUsernameIndex = -1;
        int i = 0;
        do {
            if (credentials.get(i) == ':') {
                endOfUsernameIndex = i;
            }
        } while (endOfUsernameIndex == -1 && i++ < credentials.length());
        // Ensure that username:password was found in header
        if (endOfUsernameIndex == -1) {
            return FAILURE_TOKEN;
        }
        String username = credentials.subSequence(0, endOfUsernameIndex).toString();
        CharBuffer password = credentials.subSequence(endOfUsernameIndex + 1, credentials.length());
        SearchResult searchResult = queryLdap(username, LDAP_ATTRIBUTES_BASIC);
        if (searchResult == null || searchResult.getEntryCount() == 0) {
            return FAILURE_TOKEN;
        }
        else {
            SearchResultEntry entry = searchResult.getSearchEntries().get(0);
            CharBuffer ldapPassword = ASCII_CHARSET.decode(ByteBuffer.wrap(entry.getAttributeValueBytes("userpassword")));
            boolean success = password.equals(ldapPassword);
            clearBuffer(credentials);
            clearBuffer(ldapPassword);
            return success ? generateJwt(username, 1) : FAILURE_TOKEN;
        }
    }

    private Token generateJwt(String username, int accessCount) {
        Calendar cal = Calendar.getInstance();
        Date now = cal.getTime();
        cal.add(Calendar.HOUR_OF_DAY, 2);
        Date expiryTime = cal.getTime();
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        return AccessController.doPrivileged((PrivilegedAction<Token>) () ->
            new Token(Jwts.builder()
                    .setIssuer(ISSUER)
                    .setIssuedAt(now)
                    .setExpiration(expiryTime)
                    .claim(USER_CLAIM, username)
                    .claim(ACCESS_COUNT_CLAIM, accessCount)
                    .signWith(SignatureAlgorithm.HS256, SIGNING_KEY)
                .compact(), true, expiryTime)
        );
    }

    Token handleBearerAuth(RestRequest request) {
        try {
            CharBuffer credentials = extractCredentialsFromRequest(request);
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }
            Jws<Claims> jwt = AccessController.doPrivileged((PrivilegedAction<Jws<Claims>>) () ->
                    Jwts.parser().setSigningKey(SIGNING_KEY).parseClaimsJws(credentials.toString())
            );
            String username = (String) jwt.getBody().get(USER_CLAIM);
            int accessCount = (Integer) jwt.getBody().get(ACCESS_COUNT_CLAIM);
            if (username != null) {
                SearchResult searchResult = queryLdap(username, LDAP_ATTRIBUTES_BEARER);
                if (searchResult != null && searchResult.getEntryCount() != 0) {
                    SearchResultEntry entry = searchResult.getSearchEntries().get(0);
                    int userType = entry.getAttributeValueAsInteger(ELASTIC_USER_TYPE_ATTRIBUTE);
                    String[] permissions = entry.getAttributeValues(ELASTIC_INDEX_PERM_ATTRIBUTE);
                    //FIXME dont need to handle permissions if not trying to access an index
                    if (handlePermission(userType, permissions, request)) {
                        return generateJwt(username, accessCount + 1);
                    }
                }
            }
            return FAILURE_TOKEN;
        }
        catch (MalformedAuthHeaderException | SignatureException | MalformedJwtException e) {
            return FAILURE_TOKEN;
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

    private CharBuffer extractCredentialsFromRequest(RestRequest request) throws MalformedAuthHeaderException {
        String authHeader = request.header("Authorization");
        if (authHeader != null) {
            if (authHeader.contains("Basic")) {
                /* TODO will need to hash/salt the pw to match whatever the LDAP setup is
                 * TODO or does this happen at the browser? Probably should happen at the browser */
                return ASCII_CHARSET.decode(ByteBuffer.wrap(Base64.getDecoder().decode(authHeader.replaceFirst("Basic ", ""))));
            } else if (authHeader.contains("Bearer")) {
                return CharBuffer.wrap(authHeader.replaceFirst("Bearer ", ""));
            }
        }
        throw new MalformedAuthHeaderException();
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
            //TODO move to config
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

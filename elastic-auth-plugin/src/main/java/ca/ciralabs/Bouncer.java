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
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import static ca.ciralabs.PluginSettings.ELASTIC_INDEX_PERM_ATTRIBUTE_SETTING;
import static ca.ciralabs.PluginSettings.ELASTIC_USER_TYPE_ATTRIBUTE_SETTING;
import static ca.ciralabs.PluginSettings.JWT_ISSUER_SETTING;
import static ca.ciralabs.PluginSettings.JWT_SIGNING_KEY_SETTING;
import static ca.ciralabs.PluginSettings.KIBANA_PASSWORD_SETTING;
import static ca.ciralabs.PluginSettings.KIBANA_USER_SETTING;
import static ca.ciralabs.PluginSettings.LDAP_BASE_DN_SETTING;
import static ca.ciralabs.PluginSettings.LDAP_BIND_SETTING;
import static ca.ciralabs.PluginSettings.LDAP_HOST_SETTING;
import static ca.ciralabs.PluginSettings.LDAP_PASSWORD_SETTING;
import static ca.ciralabs.PluginSettings.LDAP_PORT_SETTING;
import static ca.ciralabs.PluginSettings.WHITELISTED_PATHS_SETTING;
import static org.elasticsearch.rest.RestRequest.Method;

class Bouncer {

    private static final int MASTER = 7;
    private static final int DEVELOPER = 6;
    private static final int USER = 4;

    private static final String INDEX = "index";
    private static final String[] EMPTY_PERMISSIONS = new String[0];
    private static final Token FAILURE_TOKEN = new Token(null, false, null, 0);
    private static final String USER_CLAIM = "user";
    private static final Charset ASCII_CHARSET = Charset.forName("US-ASCII");

    private static final Logger logger = ESLoggerFactory.getLogger(Bouncer.class);

    private final String ELASTIC_USER_TYPE_ATTRIBUTE;
    private final String ELASTIC_INDEX_PERM_ATTRIBUTE;
    private final String ISSUER;
    private final byte[] SIGNING_KEY;
    private final String KIBANA_USER;
    private final CharBuffer KIBANA_PASSWORD;
    private final String[] WHITELISTED_PATHS;
    private final String LDAP_HOST;
    private final int LDAP_PORT;
    private final String LDAP_BIND;
    private final String LDAP_PASSWORD;
    private final String LDAP_BASE_DN;
    private final String[] LDAP_ATTRIBUTES_BASIC;
    private final String[] LDAP_ATTRIBUTES_BEARER;

    private class MalformedAuthHeaderException extends Throwable {}

    Bouncer(Settings settings) {
        ELASTIC_USER_TYPE_ATTRIBUTE = ELASTIC_USER_TYPE_ATTRIBUTE_SETTING.get(settings);
        ELASTIC_INDEX_PERM_ATTRIBUTE = ELASTIC_INDEX_PERM_ATTRIBUTE_SETTING.get(settings);
        KIBANA_USER = KIBANA_USER_SETTING.get(settings);
        KIBANA_PASSWORD = CharBuffer.wrap(KIBANA_PASSWORD_SETTING.get(settings));
        WHITELISTED_PATHS = WHITELISTED_PATHS_SETTING.get(settings).toArray(new String[0]);
        ISSUER = JWT_ISSUER_SETTING.get(settings);
        SIGNING_KEY = JWT_SIGNING_KEY_SETTING.get(settings).getBytes(ASCII_CHARSET);
        LDAP_HOST = LDAP_HOST_SETTING.get(settings);
        LDAP_PORT = LDAP_PORT_SETTING.get(settings);
        LDAP_BIND = LDAP_BIND_SETTING.get(settings);
        LDAP_PASSWORD = LDAP_PASSWORD_SETTING.get(settings);
        LDAP_BASE_DN = LDAP_BASE_DN_SETTING.get(settings);
        LDAP_ATTRIBUTES_BASIC = new String[] {"userpassword", ELASTIC_USER_TYPE_ATTRIBUTE, ELASTIC_INDEX_PERM_ATTRIBUTE};
        LDAP_ATTRIBUTES_BEARER = new String[] {ELASTIC_USER_TYPE_ATTRIBUTE, ELASTIC_INDEX_PERM_ATTRIBUTE};
    }

    Token handleBasicAuth(RestRequest request, boolean isKibana) {
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
        if (isKibana) {
            // Kibana is controlled by Labs, so read the password from config, not from LDAP
            return password.equals(KIBANA_PASSWORD) ? new Token(null, true, null, MASTER) : FAILURE_TOKEN;
        }
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
            int userType = entry.getAttributeValueAsInteger(ELASTIC_USER_TYPE_ATTRIBUTE) != null ?
                    entry.getAttributeValueAsInteger(ELASTIC_USER_TYPE_ATTRIBUTE) :
                    // Default to user if no permissions granted
                    USER;
            return success ? generateJwt(username, userType) : FAILURE_TOKEN;
        }
    }

    /**
     * Kibana is the only user allowed to access all of ES via Basic auth. Verify that the credentials are from a user
     * <i>claiming</i> to be Kibana before allowing the request for further processing.
     */
    boolean isKibana(String authHeader) {
        try {
            CharBuffer decoded = ASCII_CHARSET.decode(ByteBuffer.wrap(Base64.getDecoder().decode(authHeader.replaceFirst("Basic ", ""))));
            int i = 0;
            for (; i < KIBANA_USER.length(); i++) {
                if (decoded.get(i) != KIBANA_USER.charAt(i)) {
                    return false;
                }
            }
            return decoded.get(i) == ':';
        }
        catch (Exception e) {
            return false;
        }
    }

    /**
     * The generated tokens aren't presently updated, in the future we want to record access counts
     * as the tokens are passed back and forth.
     */
    private Token generateJwt(String username, int userType) {
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
                    .signWith(SignatureAlgorithm.HS256, SIGNING_KEY)
                .compact(), true, expiryTime, userType)
        );
    }

    Token handleBearerAuth(RestRequest request) {
        boolean success = false;
        String username = null;
        int userType = 0;
        try {
            CharBuffer credentials = extractCredentialsFromRequest(request);
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }
            Jws<Claims> jwt = AccessController.doPrivileged((PrivilegedAction<Jws<Claims>>) () ->
                    Jwts.parser().setSigningKey(SIGNING_KEY).parseClaimsJws(credentials.toString())
            );
            username = (String) jwt.getBody().get(USER_CLAIM);
            if (username != null) {
                SearchResult searchResult = queryLdap(username, LDAP_ATTRIBUTES_BEARER);
                if (searchResult != null && searchResult.getEntryCount() != 0) {
                    SearchResultEntry entry = searchResult.getSearchEntries().get(0);
                    userType = entry.getAttributeValueAsInteger(ELASTIC_USER_TYPE_ATTRIBUTE) != null ?
                            entry.getAttributeValueAsInteger(ELASTIC_USER_TYPE_ATTRIBUTE) :
                            // Default to user if no permissions granted
                            USER;
                    String[] permissions = entry.getAttributeValues(ELASTIC_INDEX_PERM_ATTRIBUTE) != null ?
                            entry.getAttributeValues(ELASTIC_INDEX_PERM_ATTRIBUTE) :
                            EMPTY_PERMISSIONS;
                    String index = extractIndexOrNull(request);
                    success = handlePermission(userType, permissions, index, request);
                }
            }
        }
        catch (MalformedAuthHeaderException | SignatureException | MalformedJwtException e) {
            logger.debug(e);
        }
        return success ? generateJwt(username, userType) : FAILURE_TOKEN;
    }

    private String extractIndexOrNull(RestRequest request) {
        try {
            if (request.param(INDEX) != null) {
                return request.param(INDEX);
            }
            if (request.hasContent()) {
                Map<String, String> contentMap = request.contentParser().mapStrings();
                if (contentMap.containsKey(INDEX)) {
                    return contentMap.get(INDEX);
                }
            }
        } catch (IOException e) {
            logger.error("Something went wrong parsing content", e);
        } catch (IllegalStateException e) {
            // This exception is annoying, but not fatal
            logger.debug("Something went wrong parsing content", e);
            logger.debug("Content: " + request.content().utf8ToString(), e);
        }
        return null;
    }

    private boolean isWhitelisted(String path) {
        for (String goodPath : WHITELISTED_PATHS) {
            if (path.startsWith(goodPath)) {
                return true;
            }
        }
        return false;
    }

    private boolean handlePermission(int userType, String[] permissions, String index, RestRequest request) {
        // Being a master overrides any set permissions
        if (userType != MASTER && permissions.length > 0) {
            // Special permissions are set, check them first
            for (String specialPermission : permissions) {
                String[] indexToPerm = specialPermission.split(":");
                if (index.startsWith(indexToPerm[0])) {
                    // This rule matches the request, so is it allowed?
                    return evaluatePermissionOctal(request, Integer.valueOf(indexToPerm[1]));
                }
            }
            // If no special permission matches, fall through to user type permissions
        }
        return evaluatePermissionOctal(request, userType);
    }

    private boolean evaluatePermissionOctal(RestRequest request, int octal) {
        switch (octal) {
            case USER:
                return request.method() == Method.GET || request.method() == Method.HEAD || isWhitelisted(request.path());
            case DEVELOPER:
                return request.method() != Method.DELETE;
            case MASTER:
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
            /* FIXME This connection is not secured! All info is in plaintext
             * FIXME See creating SSL-Based connections here: https://docs.ldap.com/ldap-sdk/docs/getting-started/connections.html
             */
            try (LDAPConnection cnxn = new LDAPConnection(LDAP_HOST, LDAP_PORT, LDAP_BIND, LDAP_PASSWORD)) {
                Filter filter = Filter.create(String.format("(cn=%s)", username));
                return cnxn.search(new SearchRequest(LDAP_BASE_DN, SearchScope.SUB, filter, attributes));
            }
            catch (LDAPException e) {
                logger.error("Something failed in the LDAP lookup", e);
                return null;
            }
        });
    }

}

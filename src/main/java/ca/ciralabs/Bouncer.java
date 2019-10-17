package ca.ciralabs;

import ca.ciralabs.UserInfo.UserType;
import com.unboundid.ldap.sdk.*;
import com.unboundid.util.ssl.SSLUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static ca.ciralabs.PluginSettings.*;
import static java.util.stream.Collectors.toList;
import static org.elasticsearch.rest.RestRequest.Method;

class Bouncer {

    private static final String INDEX = "index";
    private static final String[] EMPTY_PERMISSIONS = new String[0];
    private static final Token FAILURE_TOKEN = new Token(null, false, false, null, 0);
    private static final Token FORBIDDEN_TOKEN = new Token(null, true, false, null, 0);
    private static final String USER_CLAIM = "user";
    private static final Charset ASCII_CHARSET = StandardCharsets.US_ASCII;
    private static final String UNIQUE_MEMBER_ATTRIBUTE = "uniqueMember";
    private static final String USER_PASSWORD_ATTRIBUTE = "userPassword";
    /**
     * {SSHA}... so start at index 6
     */
    private static final int HASHED_INDEX_START = 6;
    private static final int SHA1_LENGTH = 20;

    private static final Logger logger = LogManager.getLogger(Bouncer.class);

    private final String ELASTIC_INDEX_PERM_ATTRIBUTE;
    private final String ISSUER;
    private final SecretKey SIGNING_KEY;
    private final String ADMIN_USER;
    private final CharBuffer ADMIN_PASSWORD;
    private final String ADMIN_BASIC_AUTH;
    /**
     * These are POST endpoints which are "safe" (read-only, mostly) for regular users.
     */
    private final List<String> WHITELISTED_PATHS = Stream.of("/_search", "/_msearch", "/_bulk_get", "/_mget",
            "/_search/scroll", "/_search/scroll/_all", "/.kibana",
            "_field_caps", "/_xpack/sql", "/_sql", "/change_password"
    ).collect(toList());
    private final List<String> MASTER_PATHS = Stream.of("/_nodes").collect(toList());
    private final List<String> DEVELOPERS_PATHS = Stream.of("/_license", "/_settings", "/_cluster", "/_cat").collect(toList());
    private final String LDAP_HOST;
    private final int LDAP_PORT;
    private final String LDAP_BASE_DN;
    private final String ELK_GROUPS_CN;
    private final String GROUP_BASE_DN;
    private final String[] LDAP_ATTRIBUTES_BASIC;
    private final String[] LDAP_ATTRIBUTES_BEARER;
    private final HashMap<String, UserType> GROUP_TO_USER_TYPE = new HashMap<>();
    private final SSLSocketFactory SSL_SOCKET_FACTORY;

    private final SecureRandom random = new SecureRandom();

    private static class MalformedAuthHeaderException extends Throwable {
    }

    Bouncer(Settings settings) {
        ELASTIC_INDEX_PERM_ATTRIBUTE = ELASTIC_INDEX_PERM_ATTRIBUTE_SETTING.get(settings);
        ADMIN_USER = ADMIN_USER_SETTING.get(settings);
        ADMIN_PASSWORD = CharBuffer.wrap(ADMIN_PASSWORD_SETTING.get(settings));
        ADMIN_BASIC_AUTH = ADMIN_BASIC_AUTH_SETTING.get(settings);
        WHITELISTED_PATHS.addAll(WHITELISTED_PATHS_SETTING.get(settings));
        ISSUER = JWT_ISSUER_SETTING.get(settings);
        SIGNING_KEY = Keys.hmacShaKeyFor(JWT_SIGNING_KEY_SETTING.get(settings).getBytes(ASCII_CHARSET));
        LDAP_HOST = LDAP_HOST_SETTING.get(settings);
        LDAP_PORT = LDAP_PORT_SETTING.get(settings);
        LDAP_BASE_DN = LDAP_BASE_DN_SETTING.get(settings);
        ELK_GROUPS_CN = LDAP_ELK_GROUPS_CN_SETTING.get(settings);
        GROUP_BASE_DN = LDAP_GROUP_BASE_DN_SETTING.get(settings);
        LDAP_ATTRIBUTES_BASIC = new String[]{USER_PASSWORD_ATTRIBUTE, ELASTIC_INDEX_PERM_ATTRIBUTE};
        LDAP_ATTRIBUTES_BEARER = new String[]{ELASTIC_INDEX_PERM_ATTRIBUTE};
        GROUP_TO_USER_TYPE.put(LDAP_ELK_GROUPS_MASTERS_CN_SETTING.get(settings), UserType.MASTER);
        GROUP_TO_USER_TYPE.put(LDAP_ELK_GROUPS_DEVELOPERS_CN_SETTING.get(settings), UserType.DEVELOPER);
        GROUP_TO_USER_TYPE.put(LDAP_ELK_GROUPS_POWER_USERS_CN_SETTING.get(settings), UserType.POWER_USER);
        GROUP_TO_USER_TYPE.put(LDAP_ELK_GROUPS_USERS_CN_SETTING.get(settings), UserType.USER);
        SSL_SOCKET_FACTORY = createSslSocketFactory();
    }

    private SSLSocketFactory createSslSocketFactory() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        return AccessController.doPrivileged((PrivilegedAction<SSLSocketFactory>) () -> {
            try {
                KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                trustStore.load(null);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                BufferedInputStream bis = new BufferedInputStream(
                        new FileInputStream(new File("plugins/elastic-auth-plugin/bundle.crt"))
                );
                while (bis.available() > 0) {
                    Certificate cert = cf.generateCertificate(bis);
                    trustStore.setCertificateEntry("cert" + bis.available(), cert);
                }
                TrustManagerFactory tmf = TrustManagerFactory.getInstance("X.509");
                tmf.init(trustStore);
                return new SSLUtil(tmf.getTrustManagers()).createSSLSocketFactory();
            } catch (Exception e) {
                logger.fatal("Failed to build SSLSocketFactory", e);
            }
            return null;
        });
    }

    Token handleBasicAuth(RestRequest request, boolean isAdminUser) {
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
        CharBuffer password = credentials.subSequence(endOfUsernameIndex + 1, credentials.length());
        if (isAdminUser) {
            // Admin is controlled by yml, so read the password from config, not from LDAP
            return password.equals(ADMIN_PASSWORD) ? new Token(null, true, true, null, UserType.MASTER.getUserLevel()) : FAILURE_TOKEN;
        } else {
            UserInfo userInfo = authenticateRequest(credentials.subSequence(0, endOfUsernameIndex).toString(), password);
            clearBuffer(credentials);
            return userInfo.isSuccessful() ? generateJwt(userInfo.getUsername(), userInfo.getUserLevel()) : FAILURE_TOKEN;
        }
    }

    private boolean verifyPassword(CharBuffer password, CharBuffer ldapPassword) {
        byte[] ldapStripAlg = ASCII_CHARSET.encode(ldapPassword.subSequence(HASHED_INDEX_START, ldapPassword.length())).array();
        byte[] decoded = Base64.getMimeDecoder().decode(ldapStripAlg);
        byte[] sha1PasswordFromLdap = Arrays.copyOfRange(decoded, 0, SHA1_LENGTH);
        byte[] salt = Arrays.copyOfRange(decoded, SHA1_LENGTH, decoded.length);
        byte[] sha1PasswordFromLogin = new byte[0];

        try {
            sha1PasswordFromLogin = hashPassword(password, salt, "SHA-1");
        } catch (NoSuchAlgorithmException e) {
            logger.debug(e);
        }

        boolean success = Arrays.equals(sha1PasswordFromLdap, sha1PasswordFromLogin);

        // Clear arrays of sensitive info
        Arrays.fill(ldapStripAlg, (byte) 0);
        Arrays.fill(decoded, (byte) 0);
        Arrays.fill(sha1PasswordFromLdap, (byte) 0);
        Arrays.fill(salt, (byte) 0);
        Arrays.fill(sha1PasswordFromLogin, (byte) 0);

        return success;
    }

    private byte[] hashPassword(CharBuffer password, byte[] salt, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(ASCII_CHARSET.encode(password));
        md.update(salt);
        return md.digest();
    }

    /**
     * An admin user, which is configured in kibana.yml and logstash.yml, is the only user allowed to access all of ES
     * via Basic auth. Verify that the credentials are from a user <i>claiming</i> to be an admin before allowing
     * the request for further processing.
     * In addition, users that begin with <code>_service.elasticsearch</code> are also allowed to use basic auth, but with
     * access defined by their LDAP attributes.
     */
    int isAllowedBasicAuth(String authHeader) {
        try {
            // It's already a string when Elasticsearch gives us the headers, so... ¯\_(ツ)_/¯
            String decoded =
                    ASCII_CHARSET.decode(ByteBuffer.wrap(Base64.getDecoder().decode(
                            authHeader.replaceFirst("Basic ", "")
                    ))).toString();
            String username = decoded.substring(0, decoded.lastIndexOf(':'));
            if (username.equals(ADMIN_USER)) {
                return 1;
            } else if (username.startsWith(ADMIN_BASIC_AUTH)) {
                return 2;
            } else {
                return 0;
            }
        } catch (Exception e) {
            return 0;
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
                        .signWith(SIGNING_KEY)
                        .compact(), true, true, expiryTime, userType)
        );
    }

    Token handleBearerAuth(RestRequest request) {
        UserInfo userInfo = getUserInfoFromJWT(request);
        return userInfo.isSuccessful() ? generateJwt(userInfo.getUsername(), userInfo.getUserLevel()) : FORBIDDEN_TOKEN;
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

    private boolean listContains(String path, List<String> list) {
        for (String goodPath : list) {
            if (path.contains(goodPath)) {
                return true;
            }
        }
        return false;
    }

    private boolean handlePermission(UserType userType, String[] permissions, String index, RestRequest request) {
        // Being a master overrides any set permissions
        if (index != null && userType != UserType.MASTER && permissions.length > 0) {
            // Special permissions are set, check them first
            for (String specialPermission : permissions) {
                String[] indexToPerm = specialPermission.split(":");
                if (index.startsWith(indexToPerm[0])) {
                    // This rule matches the request, so is it allowed?
                    return evaluatePermissionUserType(request, UserType.fromInteger(Integer.parseInt(indexToPerm[1])));
                }
            }
            // If no special permission matches, fall through to user type permissions
        }
        return evaluatePermissionUserType(request, userType);
    }

    private boolean evaluatePermissionUserType(RestRequest request, UserType userType) {
        switch (userType) {
            case USER:
                return request.method() == Method.GET || request.method() == Method.HEAD || listContains(request.path(), WHITELISTED_PATHS);
            case POWER_USER:
                return !(request.method() == Method.DELETE || listContains(request.path(), MASTER_PATHS) || listContains(request.path(), DEVELOPERS_PATHS));
            case DEVELOPER:
                return !(request.method() == Method.DELETE || listContains(request.path(), MASTER_PATHS));
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

    private SearchResult queryLdap(String cn, String baseDn, String... attributes) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        return AccessController.doPrivileged((PrivilegedAction<SearchResult>) () -> {
            try (LDAPConnection cnxn = new LDAPConnection(SSL_SOCKET_FACTORY)) {
                cnxn.connect(LDAP_HOST, LDAP_PORT);
                Filter filter = Filter.create(String.format("cn=%s", cn));
                return cnxn.search(new SearchRequest(baseDn, SearchScope.SUB, filter, attributes));
            } catch (LDAPException e) {
                logger.error("Something failed in the LDAP lookup", e);
                return null;
            }
        });
    }

    private boolean modifyLdap(String dn, CharBuffer bindPassword, String attribute, byte[] attributeValue) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        return AccessController.doPrivileged((PrivilegedAction<Boolean>) () -> {
            try (LDAPConnection cnxn = new LDAPConnection(SSL_SOCKET_FACTORY)) {
                cnxn.connect(LDAP_HOST, LDAP_PORT);
                cnxn.bind(dn, bindPassword.toString());
                return cnxn.modify(dn, new Modification(ModificationType.REPLACE, attribute, attributeValue)).getResultCode().equals(ResultCode.SUCCESS);
            } catch (LDAPException e) {
                logger.error("Something failed in the LDAP modify", e);
            }
            return false;
        });
    }

    // TODO Use memberOf attribute in the future to simplify, reduce to one LDAP call
    private UserType determineUserType(String username) {
        SearchResult sr = queryLdap(ELK_GROUPS_CN, GROUP_BASE_DN, UNIQUE_MEMBER_ATTRIBUTE);
        if (sr != null && sr.getEntryCount() != 0) {
            for (SearchResultEntry entry : sr.getSearchEntries()) {
                List<String> usernames = Arrays.stream(entry.getAttributeValues(UNIQUE_MEMBER_ATTRIBUTE))
                        .map(s -> s.substring(s.indexOf('=') + 1, s.indexOf(',')))
                        .collect(toList());
                for (String un : usernames) {
                    if (username.equals(un)) {
                        String groupname = entry.getDN();
                        groupname = groupname.substring(groupname.indexOf('=') + 1, groupname.indexOf(','));
                        UserType userType = GROUP_TO_USER_TYPE.get(groupname);
                        if (userType != null) {
                            return userType;
                        }
                    }
                }
            }
        }
        return UserType.BADUSER;
    }

    private UserInfo authenticateRequest(String username, CharBuffer password) {
        SearchResult searchResult = queryLdap(username, LDAP_BASE_DN, LDAP_ATTRIBUTES_BASIC);
        if (searchResult == null || searchResult.getEntryCount() == 0) {
            return new UserInfo();
        } else {
            SearchResultEntry entry = searchResult.getSearchEntries().get(0);
            CharBuffer ldapPassword = ASCII_CHARSET.decode(ByteBuffer.wrap(entry.getAttributeValueBytes(USER_PASSWORD_ATTRIBUTE)));
            boolean success = verifyPassword(password, ldapPassword);
            clearBuffer(ldapPassword);
            UserType userType = determineUserType(username);
            return new UserInfo(username, userType, success);
        }
    }

    private UserInfo authenticateRequest(RestRequest request, String username) {
        SearchResult searchResult = queryLdap(username, LDAP_BASE_DN, LDAP_ATTRIBUTES_BEARER);
        UserType userType = UserType.BADUSER;
        boolean success = false;
        if (searchResult != null && searchResult.getEntryCount() != 0) {
            SearchResultEntry entry = searchResult.getSearchEntries().get(0);
            userType = determineUserType(username);
            String[] permissions = entry.getAttributeValues(ELASTIC_INDEX_PERM_ATTRIBUTE) != null ?
                    entry.getAttributeValues(ELASTIC_INDEX_PERM_ATTRIBUTE) :
                    EMPTY_PERMISSIONS;
            String index = extractIndexOrNull(request);
            success = handlePermission(userType, permissions, index, request);
        }
        return new UserInfo(username, userType, success);
    }

    UserInfo getUserInfoFromJWT(RestRequest request) {
        try {
            CharBuffer credentials = extractCredentialsFromRequest(request);
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }
            Jws<Claims> jwt = AccessController.doPrivileged((PrivilegedAction<Jws<Claims>>) () ->
                    Jwts.parser().setSigningKey(SIGNING_KEY).parseClaimsJws(credentials.toString())
            );
            return authenticateRequest(request, (String) jwt.getBody().get(USER_CLAIM));
        } catch (MalformedAuthHeaderException | MalformedJwtException e) {
            logger.debug(e);
            return new UserInfo();
        }
    }

    boolean changePassword(RestRequest request) {
        Map<String, String> requestBody = Arrays.stream(request.content().utf8ToString().replaceAll("[{}\"]", "").split(","))
                .map(s -> s.split(":"))
                .collect(Collectors.toMap(a -> a[0], a -> a[1]));
        if (requestBody.containsKey("password") && requestBody.containsKey("newPassword")) {
            UserInfo userInfoJWT = getUserInfoFromJWT(request);
            UserInfo userInfoPassword = authenticateRequest(userInfoJWT.getUsername(), ASCII_CHARSET.decode(ByteBuffer.wrap(requestBody.get("password").getBytes())));
            if (userInfoJWT.isSuccessful() && userInfoPassword.isSuccessful()) {
                boolean success = false;
                byte[] salt = new byte[SHA1_LENGTH];
                random.nextBytes(salt);
                try {
                    success = modifyLdap("uid=" + userInfoJWT.getUsername() + "," + LDAP_BASE_DN, ASCII_CHARSET.decode(ByteBuffer.wrap(requestBody.get("password").getBytes())),
                            USER_PASSWORD_ATTRIBUTE, hashPassword(ASCII_CHARSET.decode(ByteBuffer.wrap(requestBody.get("newPassword").getBytes())), salt, "SHA-1"));
                } catch (NoSuchAlgorithmException e) {
                    logger.debug(e);
                }
                Arrays.fill(salt, (byte) 0);
                return success;
            }
        }
        return false;
    }
}

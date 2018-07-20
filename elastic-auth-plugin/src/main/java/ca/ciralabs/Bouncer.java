package ca.ciralabs;

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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Base64;

import static org.elasticsearch.rest.RestRequest.Method;

class Bouncer {

    private static final int MASTER = 7;
    // private static final int DEVELOPER = 6;
    // private static final int USER = 4;

    // Using these as placeholders until schema definition
    private static final String ELASTIC_USER_TYPE_ATTRIBUTE = "destinationindicator";
    private static final String ELASTIC_INDEX_PERM_ATTRIBUTE = "description";

    private static final Logger logger = ESLoggerFactory.getLogger(Bouncer.class);

    boolean requestIsAllowed(RestRequest request) {
        String[] credentials = extractCredentialsFromRequest(request).split(":");
        SearchResult searchResult = queryLdap(credentials[0]);
        if (searchResult == null || searchResult.getEntryCount() == 0) {
            return false;
        }
        else {
            SearchResultEntry entry = searchResult.getSearchEntries().get(0);
            //TODO Handle passwords better
            if (credentials[1].equals(entry.getAttributeValue("userpassword"))) {
                int userType = entry.getAttributeValueAsInteger(ELASTIC_USER_TYPE_ATTRIBUTE);
                String[] permissions = entry.getAttributeValues(ELASTIC_INDEX_PERM_ATTRIBUTE);
                // Being a master overrides any set permissions
                if (userType != MASTER && permissions.length > 1) {
                    // Special permissions are set, check them first
                    String index = request.param("index");
                    for (String specialPermission : permissions) {
                        String[] indexToPerm = specialPermission.split(":");
                        if (index.startsWith(indexToPerm[0])) {
                            // This rule matches the request, so is it allowed?
                            return decidePermission(request.method(), Integer.valueOf(indexToPerm[1]));
                        }
                    }
                    // If no special permission matches, fall through to user type permissions
                }
                return decidePermission(request.method(), userType);
            }
            else {
                return false;
            }
        }
    }

    private boolean decidePermission(Method method, int octal) {
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

    //TODO This won't actually use basic auth, or store credentials as String, but placeholder for now
    private String extractCredentialsFromRequest(RestRequest request) {
        return new String(Base64.getDecoder().decode(request.header("Authorization").replaceFirst("Basic ", "")));
    }

    private SearchResult queryLdap(String username) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        return AccessController.doPrivileged((PrivilegedAction<SearchResult>) () -> {
            try (LDAPConnection cnxn = new LDAPConnection("127.0.0.1", 389, "cn=admin,dc=localhost", "password")) {
                Filter filter = Filter.create(String.format("(cn=%s)", username));
                return cnxn.search(
                        new SearchRequest("ou=users,dc=localhost", SearchScope.SUB, filter,
                                "userpassword",
                                ELASTIC_USER_TYPE_ATTRIBUTE,
                                ELASTIC_INDEX_PERM_ATTRIBUTE
                        )
                );
            }
            catch (LDAPException e) {
                logger.error("Something failed in the LDAP lookup", e);
                return null;
            }
        });
    }

}

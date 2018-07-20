package ca.ciralabs;

import org.elasticsearch.rest.RestRequest;

import java.util.Base64;
import java.util.Map;

import static org.elasticsearch.rest.RestRequest.Method;

class Bouncer {

    private static final int MASTER = 7;
    // private static final int DEVELOPER = 6;
    // private static final int USER = 4;

    // Pretend that this is a connection to LDAP server, and retrieves permissions
    private Map<String, String> fauxLdap;

    Bouncer(Map<String, String> fauxLdap) {
        this.fauxLdap = fauxLdap;
    }

    boolean requestIsAllowed(RestRequest request) {
        String credentials = extractCredentialsFromRequest(request);
        if (!fauxLdap.containsKey(credentials)) {
            return false;
        }
        else {
            String[] permissions = fauxLdap.get(credentials).split(";");
            int userType = Integer.valueOf(permissions[0]);
            // Being a master overrides any set permissions
            if (userType != MASTER && permissions.length > 1) {
                // Special permissions are set, check them first
                String index = request.param("index");
                for (int i = 1; i < permissions.length; i++) {
                    String[] indexToPerm = permissions[i].split(":");
                    if (index.startsWith(indexToPerm[0])) {
                        // This rule matches the request, so is it allowed?
                        return decidePermission(request.method(), Integer.valueOf(indexToPerm[1]));
                    }
                }
                // If no special permission matches, fall through to user type permissions
            }
            return decidePermission(request.method(), userType);
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

}

package ca.ciralabs;

import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;

import java.util.HashMap;
import java.util.function.UnaryOperator;

public class ElasticAuthPlugin extends Plugin implements ActionPlugin {

    // Pretend that this is a connection to LDAP server, and retrieves permissions
    private static HashMap<String, String> fauxLdap = new HashMap<>();
    static {
        fauxLdap.put("zachary:p@ssw0rd", "7;");
        fauxLdap.put("dev:devpassword", "6;cira-bdc-data:4;");
        fauxLdap.put("analyst:readonly", "4;cira-bdc-proxy:6;cira-bdc-gix:0;");
    }
    private static Bouncer bouncer = new Bouncer(fauxLdap);

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(ThreadContext threadContext) {
        return originalHandler -> (RestHandler) (request, channel, client) -> {
            if (request.header("Authorization") != null) {
                if (bouncer.requestIsAllowed(request)) {
                    originalHandler.handleRequest(request, channel, client);
                    return;
                }
            }
            RestResponse response = new BytesRestResponse(RestStatus.UNAUTHORIZED, "Access denied.");
            channel.sendResponse(response);
        };
    }

}

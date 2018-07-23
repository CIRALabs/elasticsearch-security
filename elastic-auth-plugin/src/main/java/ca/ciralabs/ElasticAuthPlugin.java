package ca.ciralabs;

import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;

import java.util.function.UnaryOperator;

public class ElasticAuthPlugin extends Plugin implements ActionPlugin {

    /** He checks your ID! *cymbal crash* */
    private static Bouncer bouncer = new Bouncer();

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(ThreadContext threadContext) {
        return originalHandler -> (RestHandler) (request, channel, client) -> {
            if (request.header("Authorization") != null) {
                Token token = bouncer.getOrValidateToken(request);
                if (token.isSuccess()) {
                    //TODO Make cookie expire
                    threadContext.addResponseHeader("Set-Cookie",
                            String.format("es_access_token=%s; HttpOnly;", token.getToken())
                    );
                    originalHandler.handleRequest(request, channel, client);
                    return;
                }
            }
            RestResponse response = new BytesRestResponse(RestStatus.UNAUTHORIZED, "Access denied.");
            response.addHeader("WWW-Authenticate", "Basic");
            channel.sendResponse(response);
        };
    }

}

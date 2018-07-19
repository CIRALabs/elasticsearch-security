package ca.ciralabs;

import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;

import java.util.Base64;
import java.util.function.UnaryOperator;

public class ElasticAuthPlugin extends Plugin implements ActionPlugin {

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(ThreadContext threadContext) {
        return originalHandler -> (RestHandler) (request, channel, client) -> {
            if (request.header("Authorization") != null) {
                String encoded = request.header("Authorization").replaceFirst("Basic ", "");
                String[] credentials = new String(Base64.getDecoder().decode(encoded)).split(":");
                if (credentials[0].equals("username") && credentials[1].equals("password")) {
                    originalHandler.handleRequest(request, channel, client);
                    return;
                }
            }
            RestResponse response = new BytesRestResponse(RestStatus.UNAUTHORIZED, "Access denied");
            channel.sendResponse(response);
        };
    }

}

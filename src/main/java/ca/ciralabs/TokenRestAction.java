package ca.ciralabs;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.*;

import java.io.IOException;

import static ca.ciralabs.ElasticAuthPlugin.bouncer;
import static org.elasticsearch.rest.RestRequest.Method;

public class TokenRestAction extends BaseRestHandler {

    static final String TOKEN_PATH = "_token";

    @Inject
    TokenRestAction(RestController controller) {
        controller.registerHandler(Method.POST, TOKEN_PATH, this);
    }

    @Override
    public String getName() {
        return "TokenRestAction";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return channel -> {
            Token token = bouncer.handleBasicAuth(request, false);
            if (token.isSuccessful()) {
                XContentBuilder builder = channel.newBuilder();
                builder.startObject();
                builder.field("result", token.getToken());
                builder.field("success", 1);
                builder.field("user_type", token.getUserType());
                builder.endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
            }
            else {
                XContentBuilder builder = channel.newBuilder();
                builder.startObject();
                builder.field("success", 0);
                builder.endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED, builder));
            }
        };
    }
}

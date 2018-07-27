package ca.ciralabs;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import static org.elasticsearch.rest.RestRequest.Method;

import static ca.ciralabs.ElasticAuthPlugin.bouncer;

import java.io.IOException;

public class TokenRestAction extends BaseRestHandler {

    static final String TOKEN_PATH = "_token";

    @Inject
    TokenRestAction(Settings settings, RestController controller) {
        super(settings);
        controller.registerHandler(Method.POST, TOKEN_PATH, this);
    }

    @Override
    public String getName() {
        return "TokenRestAction";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return channel -> {
            Token token = bouncer.handleBasicAuth(request);
            if (token.isSuccessful()) {
                XContentBuilder builder = channel.newBuilder();
                builder.startObject();
                builder.field("result", token.getToken());
                builder.field("success", 1);
                builder.endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
            }
            else {
                XContentBuilder builder = channel.newBuilder();
                builder.startObject();
                builder.field("result", "Failed to create token.");
                builder.field("success", 0);
                builder.endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED, builder));
            }
        };
    }
}

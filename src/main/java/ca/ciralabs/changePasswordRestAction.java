package ca.ciralabs;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.*;

import static ca.ciralabs.ElasticAuthPlugin.bouncer;
import static org.elasticsearch.rest.RestRequest.Method;

public class changePasswordRestAction extends BaseRestHandler {

    static final String CHANGE_PASSWORD_PATH = "change_password";

    @Inject
    changePasswordRestAction(Settings settings, RestController controller) {
        super(settings);
        controller.registerHandler(Method.POST, CHANGE_PASSWORD_PATH, this);
    }

    @Override
    public String getName() {
        return "changePasswordRestAction";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            boolean isSuccessful = bouncer.changePassword(request);
            if (isSuccessful) {
                XContentBuilder builder = channel.newBuilder();
                builder.startObject();
                builder.field("success", 1);
                builder.endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
            } else {
                XContentBuilder builder = channel.newBuilder();
                builder.startObject();
                builder.field("success", 0);
                builder.endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED, builder));
            }
        };
    }
}

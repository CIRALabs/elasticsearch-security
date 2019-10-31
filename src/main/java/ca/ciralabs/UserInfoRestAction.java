package ca.ciralabs;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.*;

import static ca.ciralabs.ElasticAuthPlugin.bouncer;
import static org.elasticsearch.rest.RestRequest.Method;

public class UserInfoRestAction extends BaseRestHandler {

    static final String USER_INFO_PATH = "user_info";

    @Inject
    UserInfoRestAction(RestController controller) {
        controller.registerHandler(Method.GET, USER_INFO_PATH, this);
    }

    @Override
    public String getName() {
        return "UserInfoRestAction";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            UserInfo userInfo = bouncer.getUserInfoFromJWT(request);
            if (userInfo.isSuccessful()) {
                XContentBuilder builder = channel.newBuilder();
                builder.startObject();
                builder.field("success", 1);
                builder.field("user_type", userInfo.getUserType().toString());
                builder.field("user_name", userInfo.getUsername());
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

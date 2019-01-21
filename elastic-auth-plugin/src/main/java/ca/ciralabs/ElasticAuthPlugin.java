package ca.ciralabs;

import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.IndexScopedSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsFilter;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;

import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import static ca.ciralabs.TokenRestAction.TOKEN_PATH;

public class ElasticAuthPlugin extends Plugin implements ActionPlugin {

    /** He checks your ID! <i>*cymbal crash*</i> */
    static Bouncer bouncer;

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(ThreadContext threadContext) {
        return originalHandler -> (RestHandler) (request, channel, client) -> {
            if (bouncer == null) {
                bouncer = new Bouncer(client.settings());
            }
            // Access the Token API without restriction
            if (request.path().endsWith(TOKEN_PATH)) {
                originalHandler.handleRequest(request, channel, client);
                return;
            }
            String authHeader = request.header("Authorization");
            if (authHeader != null) {
                int isAllowedBasicAuth = authHeader.contains("Basic") ? bouncer.isAllowedBasicAuth(authHeader) : 0;
                Token token = isAllowedBasicAuth > 0 ?
                        bouncer.handleBasicAuth(request, isAllowedBasicAuth == 1) : bouncer.handleBearerAuth(request);
                if (token.isSuccessful()) {
                    // TODO We want to pass these updated cookies back and forth to monitor access count
                    // threadContext.addResponseHeader("cookie", "cookie goes here");
                    originalHandler.handleRequest(request, channel, client);
                    return;
                }
            }
            RestResponse response = new BytesRestResponse(RestStatus.UNAUTHORIZED, "Access denied.");
            channel.sendResponse(response);
        };
    }

    @Override
    public List<Setting<?>> getSettings() {
        return PluginSettings.getSettings();
    }

    @Override
    public List<RestHandler> getRestHandlers(Settings settings, RestController restController, ClusterSettings clusterSettings,
                                             IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter,
                                             IndexNameExpressionResolver indexNameExpressionResolver, Supplier<DiscoveryNodes> nodesInCluster) {
        return Collections.singletonList(new TokenRestAction(settings, restController));
    }
}

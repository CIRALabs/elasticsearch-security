package ca.ciralabs;

import org.apache.logging.log4j.Logger;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.IndexScopedSettings;
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

    private static final Logger logger = ESLoggerFactory.getLogger(ElasticAuthPlugin.class);

    /** He checks your ID! *cymbal crash* */
    static Bouncer bouncer = new Bouncer();

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(ThreadContext threadContext) {
        return originalHandler -> (RestHandler) (request, channel, client) -> {
            // Access the Token API without restriction
            if (request.path().endsWith(TOKEN_PATH)) {
                originalHandler.handleRequest(request, channel, client);
                return;
            }
            String authHeader = request.header("Authorization");
            if (authHeader != null) {
                Token token = authHeader.contains("Basic") && bouncer.isKibana(authHeader) ?
                        bouncer.handleBasicAuth(request, true) : bouncer.handleBearerAuth(request);
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
    public List<RestHandler> getRestHandlers(Settings settings, RestController restController, ClusterSettings clusterSettings,
                                             IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter,
                                             IndexNameExpressionResolver indexNameExpressionResolver, Supplier<DiscoveryNodes> nodesInCluster) {
        return Collections.singletonList(new TokenRestAction(settings, restController));
    }
}

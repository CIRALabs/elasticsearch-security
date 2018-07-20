package ca.ciralabs;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.rest.RestRequest;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.elasticsearch.rest.RestRequest.Method.*;

public class BouncerTests {

    private static Bouncer bouncer;

    @BeforeClass
    public static void setup() {
        HashMap<String, String> fauxLdap = new HashMap<>();
        fauxLdap.put("zachary:p@ssw0rd", "7;");
        fauxLdap.put("dev:devpassword", "6;cira-bdc-data:4;");
        fauxLdap.put("analyst:readonly", "4;cira-bdc-proxy:6;cira-bdc-gix:0;");
        bouncer = new Bouncer(fauxLdap);
    }

    @Test
    public void testMasterUser() {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Authorization", Arrays.asList("Basic emFjaGFyeTpwQHNzdzByZA=="));
        RestRequest restRequest = new RestRequest(null, null,"/twitter/_doc/1", headers) {
            public Method method() { return DELETE; }
            public String uri() { return null; }
            public boolean hasContent() { return false; }
            public BytesReference content() { return null; }
        };
        // The request should succeed because user is a Master
        assertTrue(bouncer.requestIsAllowed(restRequest));
    }

    @Test
    public void testUserDefaultPermission() {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Authorization", Arrays.asList("Basic YW5hbHlzdDpyZWFkb25seQ=="));
        Map<String, String> params = new HashMap<>();
        params.put("index", "one-off-index-name");
        RestRequest restRequest = new RestRequest(null, params,"/twitter/_doc/1", headers) {
            public Method method() { return PUT; }
            public String uri() { return null; }
            public boolean hasContent() { return false; }
            public BytesReference content() { return null; }
        };
        // The request should fail because Users cannot PUT
        assertFalse(bouncer.requestIsAllowed(restRequest));
    }

    @Test
    public void testDevDefaultPermission() {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Authorization", Arrays.asList("Basic ZGV2OmRldnBhc3N3b3Jk"));
        Map<String, String> params = new HashMap<>();
        params.put("index", "one-off-index-name");
        RestRequest restRequest = new RestRequest(null, params,"", headers) {
            public Method method() { return DELETE; }
            public String uri() { return null; }
            public boolean hasContent() { return false; }
            public BytesReference content() { return null; }
        };
        // The request should fail because Developers cannot DELETE
        assertFalse(bouncer.requestIsAllowed(restRequest));
    }

    @Test
    public void testBannedIndex() {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Authorization", Arrays.asList("Basic YW5hbHlzdDpyZWFkb25seQ=="));
        Map<String, String> params = new HashMap<>();
        params.put("index", "cira-bdc-gix-2018.07.20");
        RestRequest restRequest = new RestRequest(null, params,"", headers) {
            public Method method() { return GET; }
            public String uri() { return null; }
            public boolean hasContent() { return false; }
            public BytesReference content() { return null; }
        };
        // The request should fail because this user has permission 0 on this index pattern
        assertFalse(bouncer.requestIsAllowed(restRequest));
    }

}

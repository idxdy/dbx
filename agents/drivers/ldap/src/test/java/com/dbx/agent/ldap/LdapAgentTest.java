package com.dbx.agent.ldap;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;

class LdapAgentTest {

    @AfterEach
    void tearDown() {
        // Ensure connection is closed between tests
        LdapAgent.handleRequest("""
            { "jsonrpc": "2.0", "id": 0, "method": "disconnect" }
            """);
    }

    // -----------------------------------------------------------------------
    // Handshake
    // -----------------------------------------------------------------------

    @Test
    void handshakeReturnsProtocolVersionAndCapabilities() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 1,
              "method": "handshake"
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        var result = payload.getAsJsonObject("result");

        assertEquals(1, result.get("protocolVersion").getAsInt());
        assertEquals(1, result.get("agentProtocolVersion").getAsInt());
        assertTrue(result.getAsJsonArray("capabilities").size() > 0);
    }

    // -----------------------------------------------------------------------
    // JSON-RPC dispatch: routing and error handling
    // -----------------------------------------------------------------------

    @Test
    void unknownMethodReturnsError() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 2,
              "method": "nonexistent_method"
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        assertEquals(-1, payload.getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    void shutdownReturnsOkAndSetsFlag() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 3,
              "method": "shutdown"
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertEquals(true, payload.getAsJsonObject("result").get("ok").getAsBoolean());
    }

    @Test
    void disconnectReturnsOk() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 4,
              "method": "disconnect"
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertEquals(true, payload.getAsJsonObject("result").get("ok").getAsBoolean());
    }

    @Test
    void searchWithoutConnectionReturnsError() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 5,
              "method": "ldap_search",
              "params": {
                "base_dn": "dc=example,dc=com",
                "filter": "(objectClass=*)"
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        assertTrue(payload.getAsJsonObject("error").get("message").getAsString()
            .contains("Not connected"));
    }

    // -----------------------------------------------------------------------
    // test_connection: routing for different security protocols
    // -----------------------------------------------------------------------

    @Test
    void testConnectionWithSimpleBindRoutesCorrectly() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 10,
              "method": "test_connection",
              "params": {
                "connection": {
                  "hostname": "ldap.example.com",
                  "port": 389,
                  "security_protocol": "simple",
                  "username": "cn=admin,dc=example,dc=com",
                  "password": "secret"
                }
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        // Will fail with connection error, but should not fail with routing error
        assertTrue(payload.has("error"));
        assertFalse(payload.getAsJsonObject("error").get("message").getAsString()
            .contains("Unsupported security protocol"));
    }

    @Test
    void testConnectionWithGssapiPasswordRoutesCorrectly() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 11,
              "method": "test_connection",
              "params": {
                "connection": {
                  "hostname": "ldap.example.com",
                  "port": 389,
                  "security_protocol": "gssapi",
                  "principal": "user@REALM.COM",
                  "password": "secret"
                }
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        // Should not be a routing error
        assertFalse(payload.getAsJsonObject("error").get("message").getAsString()
            .contains("Unsupported security protocol"));
    }

    @Test
    void testConnectionWithGssapiKeytabRoutesCorrectly() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 12,
              "method": "test_connection",
              "params": {
                "connection": {
                  "hostname": "ldap.example.com",
                  "port": 389,
                  "security_protocol": "gssapi",
                  "principal": "svc/ldap@REALM.COM",
                  "keytab_path": "/etc/krb5.keytab",
                  "krb5_conf": "[libdefaults]\\n  default_realm = REALM.COM"
                }
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        assertFalse(payload.getAsJsonObject("error").get("message").getAsString()
            .contains("Unsupported security protocol"));
    }

    @Test
    void testConnectionWithNoneProtocolRoutesCorrectly() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 13,
              "method": "test_connection",
              "params": {
                "connection": {
                  "hostname": "ldap.example.com",
                  "port": 389,
                  "security_protocol": "none"
                }
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        assertFalse(payload.getAsJsonObject("error").get("message").getAsString()
            .contains("Unsupported security protocol"));
    }

    @Test
    void testConnectionRejectsUnsupportedSecurityProtocol() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 14,
              "method": "test_connection",
              "params": {
                "connection": {
                  "hostname": "ldap.example.com",
                  "port": 389,
                  "security_protocol": "digest-md5"
                }
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        assertTrue(payload.getAsJsonObject("error").get("message").getAsString()
            .contains("Unsupported security protocol"));
    }

    // -----------------------------------------------------------------------
    // search: filter validation
    // -----------------------------------------------------------------------

    @Test
    void searchWithoutFilterReturnsError() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 20,
              "method": "ldap_search",
              "params": {
                "base_dn": "dc=example,dc=com"
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        // Should fail because not connected (connection check happens first)
        // If connected, would fail on missing filter
        assertNotNull(payload.getAsJsonObject("error").get("message"));
    }

    // -----------------------------------------------------------------------
    // connect: alternate parameter names
    // -----------------------------------------------------------------------

    @Test
    void connectAcceptsAlternateFieldNames() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 30,
              "method": "connect",
              "params": {
                "connection": {
                  "host": "ldap.example.com",
                  "port": 636,
                  "use_ssl": true,
                  "tls_skip_verify": true,
                  "security_protocol": "simple",
                  "bind_dn": "cn=admin,dc=example,dc=com",
                  "bind_password": "secret"
                }
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        // Should not complain about missing hostname — "host" should be accepted
        assertFalse(payload.getAsJsonObject("error").get("message").getAsString()
            .contains("hostname"));
    }

    // -----------------------------------------------------------------------
    // jaasValue escaping
    // -----------------------------------------------------------------------

    @Test
    void jaasValueEscapesBackslashAndQuote() {
        assertEquals("foo\\\\bar", LdapAgent.jaasValue("foo\\bar"));
        assertEquals("foo\\\"bar", LdapAgent.jaasValue("foo\"bar"));
        assertEquals("a\\\\b\\\"c", LdapAgent.jaasValue("a\\b\"c"));
    }

    @Test
    void jaasValuePreservesPlainStrings() {
        assertEquals("simple", LdapAgent.jaasValue("simple"));
        assertEquals("user@REALM.COM", LdapAgent.jaasValue("user@REALM.COM"));
    }

    // -----------------------------------------------------------------------
    // connect with default security_protocol (simple)
    // -----------------------------------------------------------------------

    @Test
    void connectDefaultsToSimpleWhenSecurityProtocolOmitted() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 40,
              "method": "test_connection",
              "params": {
                "connection": {
                  "hostname": "ldap.example.com",
                  "port": 389,
                  "username": "cn=admin,dc=example,dc=com",
                  "password": "secret"
                }
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        assertFalse(payload.getAsJsonObject("error").get("message").getAsString()
            .contains("Unsupported security protocol"));
    }

    // -----------------------------------------------------------------------
    // GSSAPI with krb5 config variants
    // -----------------------------------------------------------------------

    @Test
    void gssapiAcceptsAlternateKrb5FieldNames() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 50,
              "method": "test_connection",
              "params": {
                "connection": {
                  "hostname": "ldap.example.com",
                  "port": 389,
                  "security_protocol": "gssapi",
                  "kerberos_principal": "user@REALM.COM",
                  "kerberos_password": "secret",
                  "krb5_config": "[libdefaults]\\n  default_realm = REALM.COM"
                }
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        assertFalse(payload.getAsJsonObject("error").get("message").getAsString()
            .contains("Unsupported security protocol"));
    }

    // -----------------------------------------------------------------------
    // connect with ldaps (SSL)
    // -----------------------------------------------------------------------

    @Test
    void connectWithLdapsAndSimpleBind() {
        String response = LdapAgent.handleRequest("""
            {
              "jsonrpc": "2.0",
              "id": 60,
              "method": "test_connection",
              "params": {
                "connection": {
                  "hostname": "ldap.example.com",
                  "port": 636,
                  "use_ssl": true,
                  "tls_skip_verify": true,
                  "security_protocol": "simple",
                  "username": "cn=admin,dc=example,dc=com",
                  "password": "secret"
                }
              }
            }
            """);

        var payload = JsonParser.parseString(response).getAsJsonObject();
        assertTrue(payload.has("error"));
        assertFalse(payload.getAsJsonObject("error").get("message").getAsString()
            .contains("Unsupported security protocol"));
    }

    // =======================================================================
    // Integration tests — real LDAP server
    // =======================================================================

    private static final String LDAP_HOST = "ldap.example.com";
    private static final int LDAP_PORT = 389;
    private static final String BASE_DN = "dc=example,dc=com";
    private static final String SIMPLE_USER = "username";
    private static final String SIMPLE_PASS = "123456";

    private static String simpleBindTestConnectionRequest(int id) {
        return simpleBindRequest(id, "test_connection");
    }

    private static String simpleBindConnectRequest(int id) {
        return simpleBindRequest(id, "connect");
    }

    private static String simpleBindRequest(int id, String method) {
        JsonObject req = new JsonObject();
        req.addProperty("jsonrpc", "2.0");
        req.addProperty("id", id);
        req.addProperty("method", method);
        JsonObject params = new JsonObject();
        JsonObject conn = new JsonObject();
        conn.addProperty("hostname", LDAP_HOST);
        conn.addProperty("port", LDAP_PORT);
        conn.addProperty("security_protocol", "simple");
        conn.addProperty("username", SIMPLE_USER);
        conn.addProperty("password", SIMPLE_PASS);
        params.add("connection", conn);
        req.add("params", params);
        return req.toString();
    }

    @Test
    void integrationSimpleBindTestConnectionSucceeds() {
        String response = LdapAgent.handleRequest(simpleBindTestConnectionRequest(100));

        var payload = JsonParser.parseString(response).getAsJsonObject();
        if (payload.has("error")) {
            var err = payload.getAsJsonObject("error");
            System.err.println("Simple bind test_connection failed: " + err.get("message").getAsString());
        }
        assertTrue(payload.has("result"), "Expected result but got error: "
            + (payload.has("error") ? payload.getAsJsonObject("error").get("message").getAsString() : "unknown"));
        var result = payload.getAsJsonObject("result");
        assertTrue(result.get("ok").getAsBoolean());
        assertTrue(result.get("connected").getAsBoolean());
    }

    @Test
    void integrationSimpleBindConnectAndSearch() {
        // Step 1: connect
        String connectResp = LdapAgent.handleRequest(simpleBindConnectRequest(101));
        var connectPayload = JsonParser.parseString(connectResp).getAsJsonObject();
        assertTrue(connectPayload.has("result"),
            "Connect failed: " + connectPayload);
        assertTrue(connectPayload.getAsJsonObject("result").get("ok").getAsBoolean());

        // Step 2: search
        JsonObject searchReq = new JsonObject();
        searchReq.addProperty("jsonrpc", "2.0");
        searchReq.addProperty("id", 102);
        searchReq.addProperty("method", "ldap_search");
        JsonObject searchParams = new JsonObject();
        searchParams.addProperty("base_dn", BASE_DN);
        searchParams.addProperty("filter", "(&(objectClass=user)(sAMAccountName=username))");
        searchParams.addProperty("size_limit", 10);
        searchReq.add("params", searchParams);

        String searchResp = LdapAgent.handleRequest(searchReq.toString());
        var searchPayload = JsonParser.parseString(searchResp).getAsJsonObject();
        if (searchPayload.has("error")) {
            var err = searchPayload.getAsJsonObject("error");
            System.err.println("Search failed: " + err.get("message").getAsString());
        }
        assertTrue(searchPayload.has("result"),
            "Search failed: " + searchPayload);
        var result = searchPayload.getAsJsonObject("result");
        assertTrue(result.get("count").getAsInt() > 0, "Expected at least 1 search result");
        assertEquals(1, result.getAsJsonArray("entries").size());
        var entry = result.getAsJsonArray("entries").get(0).getAsJsonObject();
        assertNotNull(entry.get("dn"));
        assertNotNull(entry.get("attributes"));
    }

    @Test
    void integrationSimpleBindSearchWithLimit() {
        // Connect
        String connectResp = LdapAgent.handleRequest(simpleBindConnectRequest(103));
        var cp = JsonParser.parseString(connectResp).getAsJsonObject();
        assertTrue(cp.has("result"), "Connect failed: " + cp);

        // Search with limit=3
        JsonObject searchReq = new JsonObject();
        searchReq.addProperty("jsonrpc", "2.0");
        searchReq.addProperty("id", 104);
        searchReq.addProperty("method", "ldap_search");
        JsonObject searchParams = new JsonObject();
        searchParams.addProperty("base_dn", BASE_DN);
        searchParams.addProperty("filter", "(objectClass=user)");
        searchParams.addProperty("size_limit", 3);
        searchReq.add("params", searchParams);

        String searchResp = LdapAgent.handleRequest(searchReq.toString());
        var sp = JsonParser.parseString(searchResp).getAsJsonObject();
        assertTrue(sp.has("result"), "Search failed: " + sp);
        var result = sp.getAsJsonObject("result");
        assertTrue(result.get("count").getAsInt() > 0);
        // Server may truncate results when size limit is exceeded
        assertTrue(result.get("count").getAsInt() <= 3 || result.has("truncated"));
    }

    // =======================================================================
    // GSSAPI integration tests
    // =======================================================================

    private static final String GSSAPI_HOST = "dc.example.com";
    private static final String GSSAPI_PRINCIPAL = "user@example.com";
    private static final String GSSAPI_PASS = "123456";

    private static final String KRB5_CONF = """
        [libdefaults]
            default_realm = EXAMPLE.COM
            dns_lookup_realm = false
            dns_lookup_kdc = false

        [realms]
            EXAMPLE.COM = {
                kdc = dc.example.com:88
            }

        [domain_realm]
            .example.com = EXAMPLE.COM
            example.com = EXAMPLE.COM
        """;

    private static String gssapiConnectRequest(int id) {
        return gssapiRequest(id, "connect");
    }

    private static String gssapiTestConnectionRequest(int id) {
        return gssapiRequest(id, "test_connection");
    }

    private static String gssapiRequest(int id, String method) {
        JsonObject req = new JsonObject();
        req.addProperty("jsonrpc", "2.0");
        req.addProperty("id", id);
        req.addProperty("method", method);
        JsonObject params = new JsonObject();
        JsonObject conn = new JsonObject();
        conn.addProperty("hostname", GSSAPI_HOST);
        conn.addProperty("port", LDAP_PORT);
        conn.addProperty("security_protocol", "gssapi");
        conn.addProperty("principal", GSSAPI_PRINCIPAL);
        conn.addProperty("password", GSSAPI_PASS);
        conn.addProperty("krb5_conf", KRB5_CONF);
        params.add("connection", conn);
        req.add("params", params);
        return req.toString();
    }

    @Test
    void integrationGssapiPasswordTestConnectionSucceeds() {
        String response = LdapAgent.handleRequest(gssapiTestConnectionRequest(110));

        var payload = JsonParser.parseString(response).getAsJsonObject();
        if (payload.has("error")) {
            System.err.println("GSSAPI test_connection failed: "
                + payload.getAsJsonObject("error").get("message").getAsString());
        }
        assertTrue(payload.has("result"), "Expected result but got error: "
            + (payload.has("error") ? payload.getAsJsonObject("error").get("message").getAsString() : "unknown"));
        var result = payload.getAsJsonObject("result");
        assertTrue(result.get("ok").getAsBoolean());
        assertTrue(result.get("connected").getAsBoolean());
    }

    @Test
    void integrationGssapiConnectAndSearch() {
        // Step 1: connect with GSSAPI
        String connectResp = LdapAgent.handleRequest(gssapiConnectRequest(111));
        var connectPayload = JsonParser.parseString(connectResp).getAsJsonObject();
        assertTrue(connectPayload.has("result"),
            "GSSAPI connect failed: " + connectPayload);
        assertTrue(connectPayload.getAsJsonObject("result").get("ok").getAsBoolean());

        // Step 2: search
        JsonObject searchReq = new JsonObject();
        searchReq.addProperty("jsonrpc", "2.0");
        searchReq.addProperty("id", 112);
        searchReq.addProperty("method", "ldap_search");
        JsonObject searchParams = new JsonObject();
        searchParams.addProperty("base_dn", BASE_DN);
        searchParams.addProperty("filter", "(&(objectClass=user)(sAMAccountName=username))");
        searchParams.addProperty("size_limit", 10);
        searchReq.add("params", searchParams);

        String searchResp = LdapAgent.handleRequest(searchReq.toString());
        var searchPayload = JsonParser.parseString(searchResp).getAsJsonObject();
        if (searchPayload.has("error")) {
            System.err.println("GSSAPI search failed: "
                + searchPayload.getAsJsonObject("error").get("message").getAsString());
        }
        assertTrue(searchPayload.has("result"),
            "GSSAPI search failed: " + searchPayload);
        var result = searchPayload.getAsJsonObject("result");
        assertTrue(result.get("count").getAsInt() > 0);
        var entry = result.getAsJsonArray("entries").get(0).getAsJsonObject();
        assertNotNull(entry.get("dn"));
        assertNotNull(entry.get("attributes").getAsJsonObject().get("sAMAccountName"));
    }

    @Test
    void integrationGssapiSearchAllAttributes() {
        // Connect
        String connectResp = LdapAgent.handleRequest(gssapiConnectRequest(113));
        var cp = JsonParser.parseString(connectResp).getAsJsonObject();
        assertTrue(cp.has("result"), "GSSAPI connect failed: " + cp);

        // Search without specifying attributes → returns all
        JsonObject searchReq = new JsonObject();
        searchReq.addProperty("jsonrpc", "2.0");
        searchReq.addProperty("id", 114);
        searchReq.addProperty("method", "ldap_search");
        JsonObject searchParams = new JsonObject();
        searchParams.addProperty("base_dn", BASE_DN);
        searchParams.addProperty("filter", "(&(objectClass=user)(sAMAccountName=username))");
        searchParams.addProperty("size_limit", 1);
        searchReq.add("params", searchParams);

        String searchResp = LdapAgent.handleRequest(searchReq.toString());
        var sp = JsonParser.parseString(searchResp).getAsJsonObject();
        assertTrue(sp.has("result"), "Search failed: " + sp);
        var result = sp.getAsJsonObject("result");
        assertEquals(1, result.get("count").getAsInt());
        var entry = result.getAsJsonArray("entries").get(0).getAsJsonObject();
        var attrs = entry.getAsJsonObject("attributes");
        assertNotNull(attrs.get("cn"));
        assertNotNull(attrs.get("sAMAccountName"));
    }
}

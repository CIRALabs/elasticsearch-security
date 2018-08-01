The following settings must be set in elasticsearch.yml:

```yaml
xpack.security.enabled: false
elastic-auth-plugin:
    ldap:
        host: 127.0.0.1
        port: 389
        bind: cn=admin,dc=localhost
        password: password
        base-dn: ou=users,dc=localhost
        attribute:
            user-type: destinationindicator
            index-perm: description
    jwt:
        issuer: ciralabs.ca
        signing-key: supersecret
    kibana:
        user: kibana
        password: kibana
    perm.whitelisted:
      - /.kibana
      - /_msearch
```

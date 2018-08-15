The following settings must be set in elasticsearch.yml:

```yaml
xpack.security.enabled: false
elastic-auth-plugin:
    ldap:
        host: hostname
        port: 636
        base-dn: ou=People,dc=hostname,dc=ca
        attribute.index-perm: esIndexPermission
        elk-groups-cn: ELK*
        elk-groups-masters-cn: ELKMasters
        elk-groups-developers-cn: ELKDevelopers
        elk-groups-users-cn: ELKUsers
        group-base-dn: ou=Groups,dc=hostname,dc=ca
    jwt:
        issuer: ciralabs.ca
        signing-key: supersecretkey
    admin:
        user: adminuser
        password: adminpassword
    perm.whitelisted:
      - /.kibana
      - /_msearch
```

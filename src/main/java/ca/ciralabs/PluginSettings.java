package ca.ciralabs;

import org.elasticsearch.common.settings.Setting;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

class PluginSettings {

    static final Setting<String> LDAP_HOST_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.host", Setting.Property.NodeScope);
    static final Setting<Integer> LDAP_PORT_SETTING =
            Setting.intSetting("elastic-auth-plugin.ldap.port", 389, 0, 65535, Setting.Property.NodeScope);
    static final Setting<String> LDAP_BASE_DN_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.base-dn", Setting.Property.NodeScope);
    static final Setting<String> LDAP_ELK_GROUPS_CN_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.elk-groups-cn", Setting.Property.NodeScope);
    static final Setting<String> LDAP_ELK_GROUPS_MASTERS_CN_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.elk-groups-masters-cn", Setting.Property.NodeScope);
    static final Setting<String> LDAP_ELK_GROUPS_DEVELOPERS_CN_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.elk-groups-developers-cn", Setting.Property.NodeScope);
    static final Setting<String> LDAP_ELK_GROUPS_POWER_USERS_CN_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.elk-groups-power-users-cn", Setting.Property.NodeScope);
    static final Setting<String> LDAP_ELK_GROUPS_USERS_CN_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.elk-groups-users-cn", Setting.Property.NodeScope);
    static final Setting<String> LDAP_GROUP_BASE_DN_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.group-base-dn", Setting.Property.NodeScope);
    static final Setting<String> LDAP_MODIFICATION_DN_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.modification-dn", Setting.Property.NodeScope);
    static final Setting<String> LDAP_MODIFICATION_DN_PASSWORD_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.modification-dn-password", Setting.Property.NodeScope);
    static final Setting<String> ELASTIC_INDEX_PERM_ATTRIBUTE_SETTING =
            Setting.simpleString("elastic-auth-plugin.ldap.attribute.index-perm", Setting.Property.NodeScope);
    static final Setting<String> JWT_ISSUER_SETTING =
            Setting.simpleString("elastic-auth-plugin.jwt.issuer", Setting.Property.NodeScope);
    static final Setting<String> JWT_SIGNING_KEY_SETTING =
            Setting.simpleString("elastic-auth-plugin.jwt.signing-key", Setting.Property.NodeScope);
    static final Setting<String> ADMIN_USER_SETTING =
            Setting.simpleString("elastic-auth-plugin.admin.user", Setting.Property.NodeScope);
    static final Setting<String> ADMIN_PASSWORD_SETTING =
            Setting.simpleString("elastic-auth-plugin.admin.password", Setting.Property.NodeScope);
    static final Setting<String> ADMIN_BASIC_AUTH_SETTING =
            Setting.simpleString("elastic-auth-plugin.admin.basic-auth", Setting.Property.NodeScope);
    static final Setting<List<String>> WHITELISTED_PATHS_SETTING =
            Setting.listSetting("elastic-auth-plugin.perm.whitelisted", Collections.emptyList(), s -> s, Setting.Property.NodeScope);

    static List<Setting<?>> getSettings() {
        return Arrays.asList(
                LDAP_HOST_SETTING, LDAP_PORT_SETTING, LDAP_BASE_DN_SETTING, LDAP_ELK_GROUPS_CN_SETTING,
                LDAP_ELK_GROUPS_MASTERS_CN_SETTING, LDAP_ELK_GROUPS_DEVELOPERS_CN_SETTING, LDAP_ELK_GROUPS_POWER_USERS_CN_SETTING,
                LDAP_ELK_GROUPS_USERS_CN_SETTING, LDAP_GROUP_BASE_DN_SETTING, LDAP_MODIFICATION_DN_SETTING,
                LDAP_MODIFICATION_DN_PASSWORD_SETTING, ELASTIC_INDEX_PERM_ATTRIBUTE_SETTING, JWT_ISSUER_SETTING,
                JWT_SIGNING_KEY_SETTING, ADMIN_USER_SETTING, ADMIN_PASSWORD_SETTING,
                ADMIN_BASIC_AUTH_SETTING, WHITELISTED_PATHS_SETTING
        );
    }

}

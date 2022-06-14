package com.upb.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.saml.mappers.AbstractSAMLProtocolMapper;
import org.keycloak.protocol.saml.mappers.SAMLNameIdMapper;
import org.keycloak.protocol.saml.mappers.NameIdMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.scripting.EvaluatableScriptAdapter;
import org.keycloak.scripting.ScriptCompilationException;
import org.keycloak.scripting.ScriptingProvider;

import java.util.List;
import java.util.ArrayList;

public class NameIdScriptBasedMapper extends AbstractSAMLProtocolMapper implements SAMLNameIdMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    public static final String PROVIDER_ID = "saml-javascript-nameid-mapper";
    private static final Logger LOGGER = Logger.getLogger(NameIdScriptBasedMapper.class);

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setType(ProviderConfigProperty.SCRIPT_TYPE);
        property.setLabel(ProviderConfigProperty.SCRIPT_TYPE);
        property.setName(ProviderConfigProperty.SCRIPT_TYPE);
        property.setHelpText(
                "Script to compute the attribute value. \n" + //
                        " Available variables: \n" + //
                        " 'user' - the current user.\n" + //
                        " 'realm' - the current realm.\n" + //
                        " 'clientSession' - the current clientSession.\n" + //
                        " 'userSession' - the current userSession.\n" + //
                        " 'keycloakSession' - the current keycloakSession.\n\n" +
                        "To use: the last statement is the value returned to Java.\n" +
                        "The result will be tested if it can be iterated upon (e.g. an array or a collection).\n" +
                        " - If it is not, toString() will be called on the object to get the value of the attribute\n" +
                        " - If it is, toString() will be called on all elements to return multiple attribute values.\n"//
        );
        property.setDefaultValue("/**\n" + //
                " * Available variables: \n" + //
                " * user - the current user\n" + //
                " * realm - the current realm\n" + //
                " * clientSession - the current clientSession\n" + //
                " * userSession - the current userSession\n" + //
                " * keycloakSession - the current keycloakSession\n" + //
                " */\n\n\n//insert your code here..." //
        );
        configProperties.add(property);
        NameIdMapperHelper.setConfigProperties(configProperties);
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Javascript Mapper for NameID";
    }

    @Override
    public String getDisplayCategory() {
        return NameIdMapperHelper.NAMEID_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Evaluates a JavaScript function to produce a NameID value based on context information.";
    }

    @Override
    public String mapperNameId(String nameIdFormat, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        UserModel user = userSession.getUser();
        String scriptSource = mappingModel.getConfig().get(ProviderConfigProperty.SCRIPT_TYPE);
        RealmModel realm = userSession.getRealm();

        ScriptingProvider scripting = session.getProvider(ScriptingProvider.class);
        ScriptModel scriptModel = scripting.createScript(realm.getId(), ScriptModel.TEXT_JAVASCRIPT, "nameid-mapper-script_" + mappingModel.getName(), scriptSource, null);

        EvaluatableScriptAdapter script = scripting.prepareEvaluatableScript(scriptModel);
        Object attributeValue;
        try {
            attributeValue = script.eval((bindings) -> {
                bindings.put("user", user);
                bindings.put("realm", realm);
                bindings.put("clientSession", clientSession);
                bindings.put("userSession", userSession);
                bindings.put("keycloakSession", session);
            });
                   
            return String.valueOf(attributeValue);
        } catch (Exception ex) {
            LOGGER.error("Error during execution of ProtocolMapper script", ex);
            return "";
        }
    }

    @Override
    public void validateConfig(KeycloakSession session, RealmModel realm, ProtocolMapperContainerModel client, ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {

        String scriptCode = mapperModel.getConfig().get(ProviderConfigProperty.SCRIPT_TYPE);
        if (scriptCode == null) {
            return;
        }

        ScriptingProvider scripting = session.getProvider(ScriptingProvider.class);
        ScriptModel scriptModel = scripting.createScript(realm.getId(), ScriptModel.TEXT_JAVASCRIPT, mapperModel.getName() + "-script", scriptCode, "");

        try {
            scripting.prepareEvaluatableScript(scriptModel);
        } catch (ScriptCompilationException ex) {
            throw new ProtocolMapperConfigException("error", "{0}", ex.getMessage());
        }
    }
}

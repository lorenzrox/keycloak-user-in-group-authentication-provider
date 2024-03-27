package org.keycloak.authentication.authenticators.browser;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class GroupUsernamePassowrdFormFactory implements AuthenticatorFactory {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    public static final String PROVIDER_ID = "auth-group-username-password-form";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    static {
        ProviderConfigProperty noteNameProperty = new ProviderConfigProperty();
        noteNameProperty.setName(GroupUsernamePasswordForm.NOTE_NAME);
        noteNameProperty.setLabel("User session note name");
        noteNameProperty.setType(ProviderConfigProperty.STRING_TYPE);
        noteNameProperty.setDefaultValue("group");
        noteNameProperty.setHelpText(
                "User session note name where to put the group name");
        configProperties.add(noteNameProperty);

        ProviderConfigProperty fullPathProperty = new ProviderConfigProperty();
        fullPathProperty.setName(GroupUsernamePasswordForm.FULL_PATH);
        fullPathProperty.setLabel("Full group path");
        fullPathProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        fullPathProperty.setDefaultValue("true");
        fullPathProperty.setHelpText(
                "Include full path to group i.e. /top/level1/level2, false will just specify the group name");
        configProperties.add(fullPathProperty);
    }

    @Override
    public String getHelpText() {
        return "Validates a group, username and password from login form.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "Group Username Password Form";
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return GroupUsernamePasswordForm.SINGLETON;
    }
}
package org.keycloak.authentication.authenticators.browser;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.model.GroupLoginBean;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class GroupUsernamePasswordForm extends AbstractUsernameFormAuthenticator {
    private static final String GROUP = "group";

    public static final String NOTE_NAME = "noteName";
    public static final String FULL_PATH = "fullPath";

    public static final GroupUsernamePasswordForm SINGLETON = new GroupUsernamePasswordForm();

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        if (!validateForm(context, formData)) {
            return;
        }

        context.success();
    }

    @Override
    public boolean validatePassword(AuthenticationFlowContext context, UserModel user,
            MultivaluedMap<String, String> inputData, boolean clearUser) {
        return super.validatePassword(context, user, inputData, clearUser)
                && validateGroup(context, user, inputData, clearUser);
    }

    protected boolean validateGroup(AuthenticationFlowContext context, UserModel user,
            MultivaluedMap<String, String> inputData, boolean clearUser) {
        String groupName = inputData.getFirst(GROUP);
        if (groupName == null || groupName.isEmpty()) {
            return badGroupHandler(context, user, clearUser);
        }

        AuthenticatorConfigModel autheticatorModel = context.getAuthenticatorConfig();
        String membership = user.getGroupsStream()
                .filter(g -> g.getName().equalsIgnoreCase(groupName))
                .map(useFullPath(autheticatorModel)
                        ? ModelToRepresentation::buildGroupPath
                        : GroupModel::getName)
                .findFirst().orElse(null);

        if (membership == null) {
            return badGroupHandler(context, user, clearUser);
        }

        String noteName = autheticatorModel == null ? "group" : autheticatorModel.getConfig().get(NOTE_NAME);
        if (!(noteName == null || noteName.isEmpty())) {
            context.getAuthenticationSession().setUserSessionNote(noteName, membership);
        }

        return true;
    }

    private boolean badGroupHandler(AuthenticationFlowContext context, UserModel user, boolean clearUser) {
        context.getEvent().error(Errors.USER_NOT_FOUND);
        Response challengeResponse = challenge(context, getDefaultChallengeMessage(context), GROUP);
        context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);

        if (clearUser) {
            context.clearUser();
        }

        return false;
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateUserAndPassword(context, formData);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getSession());

        context.getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);

        if (loginHint != null || rememberMeUsername != null) {
            if (loginHint != null) {
                formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
            } else {
                formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                formData.add("rememberMe", "on");
            }
        }

        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider forms) {
        forms.setAttribute("login", new GroupLoginBean(null));
        return forms.createForm("login-group.ftl");
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0)
            forms.setFormData(formData);

        forms.setAttribute("login", new GroupLoginBean(formData));
        return createLoginForm(forms);
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    @Override
    public void close() {

    }

    @Override
    protected final String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        return Messages.INVALID_USER;
    }

    @Override
    protected final boolean isUserAlreadySetBeforeUsernamePasswordAuth(AuthenticationFlowContext context) {
        return false;
    }

    private static boolean useFullPath(AuthenticatorConfigModel autheticatorModel) {
        return autheticatorModel == null || "true".equals(autheticatorModel.getConfig().get(FULL_PATH));
    }
}

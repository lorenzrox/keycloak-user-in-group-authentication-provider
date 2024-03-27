package org.keycloak.forms.login.freemarker.model;

import jakarta.ws.rs.core.MultivaluedMap;

public class GroupLoginBean extends LoginBean {
    private String group;

    public GroupLoginBean(MultivaluedMap<String, String> formData) {
        super(formData);

        if (formData != null) {
            group = formData.getFirst("group");
        }
    }

    public String getGroup() {
        return group;
    }
}

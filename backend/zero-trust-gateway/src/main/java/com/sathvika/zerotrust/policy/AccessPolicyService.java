package com.sathvika.zerotrust.policy;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

@Service
public class AccessPolicyService {

    public boolean isAllowed(
            Authentication authentication,
            String method,
            String path) {

        // Deny requests without an authenticated identity.
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication.getAuthorities() == null) {
            return false;
        }

        boolean isUser = hasRole(authentication, "ROLE_USER");
        boolean isAdmin = hasRole(authentication, "ROLE_ADMIN");

        // Explicit policy: regular authenticated resources.
        if ("GET".equalsIgnoreCase(method)
                && "/api/secure/me".equals(path)) {
            return isUser || isAdmin;
        }

        // Explicit policy: administrative dashboard.
        if ("GET".equalsIgnoreCase(method)
                && "/api/admin/dashboard".equals(path)) {
            return isAdmin;
        }

        // Default deny: no matching policy means no access.
        return false;
    }

    private boolean hasRole(
            Authentication authentication,
            String requiredRole) {

        for (GrantedAuthority authority
                : authentication.getAuthorities()) {
            if (requiredRole.equals(authority.getAuthority())) {
                return true;
            }
        }

        return false;
    }
}
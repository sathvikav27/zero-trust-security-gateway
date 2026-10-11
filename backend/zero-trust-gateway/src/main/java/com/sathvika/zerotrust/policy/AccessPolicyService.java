
package com.sathvika.zerotrust.policy;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

@Service
public class AccessPolicyService {

    public record PolicyDecision(boolean allowed, String reason) {
    }

    public PolicyDecision evaluate(
            Authentication authentication,
            String method,
            String path) {

        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication.getAuthorities() == null) {
            return new PolicyDecision(false, "UNAUTHENTICATED");
        }

        boolean isUser = hasRole(authentication, "ROLE_USER");
        boolean isAdmin = hasRole(authentication, "ROLE_ADMIN");

        // Allow users and admins to access their secure profile.
        if ("GET".equalsIgnoreCase(method)
                && "/api/secure/me".equals(path)) {
            if (isUser || isAdmin) {
                return new PolicyDecision(
                        true, "SECURE_PROFILE_POLICY_MATCHED");
            }
            return new PolicyDecision(false, "INSUFFICIENT_ROLE");
        }

        // Only admins can access the admin dashboard.
        if ("GET".equalsIgnoreCase(method)
                && "/api/admin/dashboard".equals(path)) {
            if (isAdmin) {
                return new PolicyDecision(true, "ADMIN_POLICY_MATCHED");
            }
            return new PolicyDecision(false, "INSUFFICIENT_ROLE");
        }

        // Only admins can view persisted security audit events.
        if ("GET".equalsIgnoreCase(method)
                && "/api/admin/audit-events".equals(path)) {
            if (isAdmin) {
                return new PolicyDecision(
                        true, "AUDIT_EVENTS_POLICY_MATCHED");
            }
            return new PolicyDecision(false, "INSUFFICIENT_ROLE");
        }

        // Default deny: all unmatched routes and methods are rejected.
        return new PolicyDecision(false, "NO_MATCHING_POLICY");
    }

    public boolean isAllowed(
            Authentication authentication,
            String method,
            String path) {

        return evaluate(authentication, method, path).allowed();
    }

    private boolean hasRole(
            Authentication authentication,
            String requiredRole) {

        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if (requiredRole.equals(authority.getAuthority())) {
                return true;
            }
        }

        return false;
    }
}

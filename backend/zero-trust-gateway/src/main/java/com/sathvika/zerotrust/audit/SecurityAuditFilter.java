package com.sathvika.zerotrust.audit;

import com.sathvika.zerotrust.policy.AccessPolicyService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityAuditFilter extends OncePerRequestFilter {

    private static final Logger log =
            LoggerFactory.getLogger(SecurityAuditFilter.class);

    private final AccessPolicyService policyService;

    public SecurityAuditFilter(AccessPolicyService policyService) {
        this.policyService = policyService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        boolean protectedPath = path.startsWith("/api/secure/")
                || path.startsWith("/api/admin/");

        try {
            filterChain.doFilter(request, response);
        } finally {
            if (protectedPath) {
                Authentication authentication =
                        SecurityContextHolder.getContext()
                                .getAuthentication();

                String actor = authentication != null
                        && authentication.isAuthenticated()
                        && !"anonymousUser".equals(authentication.getName())
                        ? authentication.getName()
                        : "ANONYMOUS";

                String role = "NONE";

                if (authentication != null
                        && authentication.isAuthenticated()
                        && !"anonymousUser".equals(authentication.getName())) {
                    role = authentication.getAuthorities().stream()
                            .map(authority -> authority.getAuthority())
                            .sorted()
                            .findFirst()
                            .orElse("NONE");
                }

                AccessPolicyService.PolicyDecision decision =
                        policyService.evaluate(
                                authentication,
                                request.getMethod(),
                                path);

                String outcome = response.getStatus() >= 400
                        ? "DENY"
                        : decision.allowed() ? "ALLOW" : "DENY";

                log.info(
                        "SECURITY_AUDIT actor={} role={} method={} path={} "
                                + "decision={} reason={} status={}",
                        actor,
                        role,
                        request.getMethod(),
                        path,
                        outcome,
                        decision.reason(),
                        response.getStatus()
                );
            }
        }
    }
}

package com.sathvika.zerotrust.audit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityAuditFilter extends OncePerRequestFilter {

    private static final Logger log =
            LoggerFactory.getLogger(SecurityAuditFilter.class);

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        } finally {
            String path = request.getRequestURI();

            if (path.startsWith("/api/secure/")
                    || path.startsWith("/api/admin/")) {

                var authentication = org.springframework.security.core
                        .context.SecurityContextHolder.getContext()
                        .getAuthentication();

                String actor = authentication != null
                        && authentication.isAuthenticated()
                        ? authentication.getName()
                        : "ANONYMOUS";

                log.info(
                        "SECURITY_AUDIT actor={} method={} path={} status={}",
                        actor,
                        request.getMethod(),
                        path,
                        response.getStatus()
                );
            }
        }
    }
}

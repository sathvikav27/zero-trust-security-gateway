

package com.sathvika.zerotrust.audit;

import java.time.Instant;

public record AuditEventResponse(
        Long id,
        String actor,
        String role,
        String method,
        String path,
        String decision,
        String reason,
        int statusCode,
        Instant createdAt) {

    public static AuditEventResponse from(AuditEvent event) {
        return new AuditEventResponse(
                event.getId(),
                event.getActor(),
                event.getRole(),
                event.getMethod(),
                event.getPath(),
                event.getDecision(),
                event.getReason(),
                event.getStatusCode(),
                event.getCreatedAt());
    }
}

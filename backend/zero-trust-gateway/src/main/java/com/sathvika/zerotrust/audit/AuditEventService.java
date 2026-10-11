
package com.sathvika.zerotrust.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AuditEventService {

    private static final Logger log =
            LoggerFactory.getLogger(AuditEventService.class);

    private final AuditEventWriter writer;

    public AuditEventService(AuditEventWriter writer) {
        this.writer = writer;
    }

    public void recordSafely(AuditEvent event) {
        try {
            writer.write(event);
        } catch (RuntimeException exception) {
            log.error(
                    "SECURITY_AUDIT_PERSISTENCE_FAILURE "
                            + "event could not be stored; "
                            + "actor={} method={} path={} status={}",
                    event.getActor(),
                    event.getMethod(),
                    event.getPath(),
                    event.getStatusCode()
            );
        }
    }
}

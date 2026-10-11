
package com.sathvika.zerotrust.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(name = "audit_events")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 254)
    private String actor;

    @Column(nullable = false, length = 100)
    private String role;

    @Column(nullable = false, length = 10)
    private String method;

    @Column(nullable = false, length = 500)
    private String path;

    @Column(nullable = false, length = 10)
    private String decision;

    @Column(nullable = false, length = 100)
    private String reason;

    @Column(nullable = false)
    private int statusCode;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    protected AuditEvent() {
    }

    public AuditEvent(
            String actor,
            String role,
            String method,
            String path,
            String decision,
            String reason,
            int statusCode) {
        this.actor = actor;
        this.role = role;
        this.method = method;
        this.path = path;
        this.decision = decision;
        this.reason = reason;
        this.statusCode = statusCode;
    }

    public Long getId() {
        return id;
    }

    public String getActor() {
        return actor;
    }

    public String getRole() {
        return role;
    }

    public String getMethod() {
        return method;
    }

    public String getPath() {
        return path;
    }

    public String getDecision() {
        return decision;
    }

    public String getReason() {
        return reason;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}

# Zero-Trust Security Gateway

A security-focused backend application designed to protect REST APIs through authentication and role-based access control, built with Java and Spring Boot.

## Tech Stack

- **Backend:** Java 17, Spring Boot, Spring Security
- **Authentication:** JSON Web Tokens (JWT)
- **Database:** PostgreSQL
- **Testing:** JUnit, Spring Boot Test, H2
- **Build Tool:** Maven

## Implemented Features

- **JWT Authentication:** User login with Bearer tokens for accessing protected endpoints.
- **Role-Based Access Control (RBAC):** Separate permissions for USER and ADMIN roles.
- **Protected REST APIs:** Restricts access to authenticated users and authorized roles.
- **User Registration and Login:** Supports account registration, authentication, and credential validation.
- **Audit Endpoint Authorization:** Restricts access to audit-event endpoints based on user permissions.
- **Automated Testing:** Includes a test suite with 20 passing tests.
- **Environment-Based Configuration:** Uses environment variables for sensitive configuration, including JWT and database credentials.
- **Isolated Test Database:** Uses an in-memory H2 database for automated tests.

## Security Behavior

| Scenario | Expected response |
|---|---|
| Access a protected endpoint without authentication | `401 Unauthorized` |
| Access an admin-restricted endpoint as a USER | `403 Forbidden` |
| Submit invalid login credentials | `401 Unauthorized` |
| Attempt duplicate registration | `409 Conflict` |

## Planned Features

- Policy-based authorization with default-deny behavior
- Rate limiting and brute-force protection
- Token revocation and session lifecycle controls
- Centralized security audit logging
- React-based security monitoring dashboard
- Docker Compose deployment
- Expanded security and integration tests

## Running Tests

From the backend module directory, run:

```bash
./mvnw test
```

On Windows PowerShell:

```powershell
.\mvnw.cmd test
```

The project currently has **20 passing automated tests** in the latest verified run.

## Project Status

Core authentication and authorization functionality is implemented. Advanced security controls, the frontend dashboard, and containerized deployment are planned for subsequent development.

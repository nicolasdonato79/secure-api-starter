# secure-api-starter

Backend Spring Boot listo para producción con:
- JWT asimétrico RS512 (RSA + SHA-512)
- RBAC (ROLE_ADMIN / ROLE_USER)
- PostgreSQL + Flyway
- Actuator health/info
- Docker compose para DB

## Requisitos
- Java 17
- Maven (o ./mvnw)
- Docker

## Levantar DB
```bash
docker compose -f docker/docker-compose.yml up -d

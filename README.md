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
```

## Zona horaria del host (TZ)
Si la zona horaria del host no coincide con la del contenedor, PostgreSQL puede comportarse diferente.
Esta configuración permite que el contenedor use la misma zona horaria del servidor pasando la variable de entorno `TZ`.

- Linux (bash): exporta `TZ` antes de levantar el compose:

```bash
export TZ="$(cat /etc/timezone 2>/dev/null || echo UTC)"
docker compose -f docker/docker-compose.yml up -d
```

- systemd (ejecución en un servicio): asegúrate de exportar la variable en el entorno del servicio o usar `Environment=TZ=America/Argentina/Buenos_Aires`.

- Windows (cmd.exe): puedes definirla para la sesión actual o de forma persistente:

```bat
:: Sesión actual (solo esta ventana)
set TZ=America/Argentina/Buenos_Aires
docker compose -f docker/docker-compose.yml up -d

:: Persistente (requiere reinicio de la sesión o del sistema)
setx TZ "America/Argentina/Buenos_Aires"
```

Notas:
- En hosts Linux reales puedes montar `/etc/localtime` y `/etc/timezone` en el contenedor para forzar una coincidencia exacta (ver `docker/docker-compose.yml`):
  - /etc/localtime:/etc/localtime:ro
  - /etc/timezone:/etc/timezone:ro
- En Docker Desktop (Windows/Mac) no siempre existe `/etc/localtime`, por eso la opción portable es usar `TZ`.

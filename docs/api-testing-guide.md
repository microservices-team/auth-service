# Guía de prueba — auth-service API Keys

> **Stack:** curl / Postman / HTTPie  
> **Base URL:** `http://localhost:8080` (via api-gateway)

---

## Credenciales de prueba

| Usuario | Email | Password | API Key | Rol |
|---|---|---|---|---|
| Admin | admin@diegoanyosa.com | Admin2024! | `da-adm001-diegoanyosa-admin-key-2024` | ADMIN |
| User | user@diegoanyosa.com | User2024! | `da-usr002-diegoanyosa-user-key-2024` | USER |
| Service | svc@diegoanyosa.com | Svc2024! | `da-svc003-diegoanyosa-service-key-2024` | USER |

---

## 1. Login con JWT (obtener token)

```bash
# Admin login
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@diegoanyosa.com","password":"Admin2024!"}' | jq .

# Guardar token en variable
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@diegoanyosa.com","password":"Admin2024!"}' \
  | jq -r '.data.accessToken')

echo "Token: $TOKEN"
```

**Respuesta esperada:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
    "tokenType": "Bearer",
    "expiresIn": 3600,
    "email": "admin@diegoanyosa.com",
    "roles": ["ADMIN"]
  }
}
```

---

## 2. GET /api/auth/me — Con JWT Bearer Token

```bash
curl -s http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Respuesta esperada:**
```json
{
  "success": true,
  "message": "User info",
  "data": {
    "userId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "email": "admin@diegoanyosa.com",
    "roles": "ADMIN"
  }
}
```

---

## 3. GET /api/auth/me — Con API Key (sin JWT)

El header `X-API-Key` es procesado por el `ApiKeyAuthFilter` **antes** del JWT filter.

```bash
# API Key del admin
curl -s http://localhost:8080/api/auth/me \
  -H "X-API-Key: da-adm001-diegoanyosa-admin-key-2024" | jq .

# API Key del user
curl -s http://localhost:8080/api/auth/me \
  -H "X-API-Key: da-usr002-diegoanyosa-user-key-2024" | jq .

# API Key del service account
curl -s http://localhost:8080/api/auth/me \
  -H "X-API-Key: da-svc003-diegoanyosa-service-key-2024" | jq .
```

**Respuesta esperada con API Key:**
```json
{
  "success": true,
  "message": "User info",
  "data": {
    "userId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "email": "admin@diegoanyosa.com",
    "roles": "API"
  }
}
```

> **Nota:** Con API Key el rol es `API` (no `ADMIN`/`USER`). Para operaciones que requieren rol `ADMIN`, usa JWT.

---

## 4. POST /api/auth/logout — Revocar tokens

El logout revoca todos los refresh tokens del usuario. Requiere JWT.

```bash
# Logout con JWT Bearer
curl -s -X POST http://localhost:8080/api/auth/logout \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Respuesta esperada:**
```json
{
  "success": true,
  "message": "Logged out",
  "data": null
}
```

**Verificar que el refresh token ya no funciona:**
```bash
# Guardar refresh token antes del logout
REFRESH=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@diegoanyosa.com","password":"User2024!"}' \
  | jq -r '.data.refreshToken')

# Logout
curl -s -X POST http://localhost:8080/api/auth/logout \
  -H "Authorization: Bearer $TOKEN" | jq .

# Intentar refresh — debe retornar 401
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}" | jq .
# → {"success":false,"message":"Refresh token expired or revoked"}
```

---

## 5. Gestión de API Keys — CRUD

```bash
# Listar mis API Keys (requiere JWT)
curl -s http://localhost:8080/api/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" | jq .

# Crear nueva API Key
curl -s -X POST "http://localhost:8080/api/auth/api-keys?name=mi-nueva-key" \
  -H "Authorization: Bearer $TOKEN" | jq .
# ⚠️ Guarda el rawKey — solo se muestra una vez

# Revocar una API Key por ID
curl -s -X DELETE "http://localhost:8080/api/auth/api-keys/{keyId}" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## 6. Probar Account Lockout (3 intentos)

```bash
# Intentar 4 veces con contraseña incorrecta
for i in 1 2 3 4; do
  echo "Intento $i:"
  curl -s -X POST http://localhost:8080/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"user@diegoanyosa.com","password":"WrongPassword!"}' | jq .message
done

# Intento 4 → respuesta 423 Locked:
# "Account locked until 2024-XX-XX. Too many failed attempts."
```

---

## 7. Postman Collection (importar como JSON)

Guarda como `diegoanyosa-auth.postman_collection.json`:

```json
{
  "info": { "name": "diegoanyosa auth-service", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
  "variable": [
    { "key": "base_url", "value": "http://localhost:8080" },
    { "key": "token",    "value": "" },
    { "key": "refresh",  "value": "" }
  ],
  "item": [
    {
      "name": "Login Admin",
      "event": [{ "listen": "test", "script": { "exec": [
        "var r = pm.response.json();",
        "pm.collectionVariables.set('token',   r.data.accessToken);",
        "pm.collectionVariables.set('refresh', r.data.refreshToken);"
      ]}}],
      "request": {
        "method": "POST", "url": "{{base_url}}/api/auth/login",
        "header": [{ "key": "Content-Type", "value": "application/json" }],
        "body": { "mode": "raw", "raw": "{\"email\":\"admin@diegoanyosa.com\",\"password\":\"Admin2024!\"}" }
      }
    },
    {
      "name": "GET /me — JWT",
      "request": {
        "method": "GET", "url": "{{base_url}}/api/auth/me",
        "header": [{ "key": "Authorization", "value": "Bearer {{token}}" }]
      }
    },
    {
      "name": "GET /me — API Key Admin",
      "request": {
        "method": "GET", "url": "{{base_url}}/api/auth/me",
        "header": [{ "key": "X-API-Key", "value": "da-adm001-diegoanyosa-admin-key-2024" }]
      }
    },
    {
      "name": "GET /me — API Key User",
      "request": {
        "method": "GET", "url": "{{base_url}}/api/auth/me",
        "header": [{ "key": "X-API-Key", "value": "da-usr002-diegoanyosa-user-key-2024" }]
      }
    },
    {
      "name": "Logout",
      "request": {
        "method": "POST", "url": "{{base_url}}/api/auth/logout",
        "header": [{ "key": "Authorization", "value": "Bearer {{token}}" }]
      }
    },
    {
      "name": "List API Keys",
      "request": {
        "method": "GET", "url": "{{base_url}}/api/auth/api-keys",
        "header": [{ "key": "Authorization", "value": "Bearer {{token}}" }]
      }
    }
  ]
}
```

---

## 8. Verificar directamente en PostgreSQL

```bash
# Conectar a la BD
docker exec -it da-postgres psql -U dauser -d diegoanyosa_db

# Ver usuarios creados
SELECT id, email, name, active, failed_attempts FROM auth.users;

# Ver API Keys
SELECT ak.key_prefix, ak.name, ak.active, u.email
FROM auth.api_keys ak
JOIN auth.users u ON ak.user_id = u.id
ORDER BY ak.created_at;

# Ver refresh tokens activos
SELECT u.email, rt.token, rt.expires_at, rt.revoked
FROM auth.refresh_tokens rt
JOIN auth.users u ON rt.user_id = u.id
WHERE rt.revoked = false;

# Salir
\q
```

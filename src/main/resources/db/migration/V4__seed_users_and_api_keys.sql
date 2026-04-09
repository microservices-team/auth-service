-- ══════════════════════════════════════════════════════════════════════════
-- V4__seed_users_and_api_keys.sql
-- Crea 3 usuarios de prueba con sus API Keys pre-generadas.
--
-- ⚠️  SOLO PARA DESARROLLO/LOCAL — no usar en producción.
--
-- Usuarios creados:
--   admin@diegoanyosa.com / Admin2024!   → rol ADMIN
--   user@diegoanyosa.com  / User2024!    → rol USER
--   svc@diegoanyosa.com   / Svc2024!     → rol USER (cuenta de servicio)
--
-- API Keys (enviar en header X-API-Key):
--   da-adm001-diegoanyosa-admin-key-2024   → admin
--   da-usr002-diegoanyosa-user-key-2024    → user
--   da-svc003-diegoanyosa-service-key-2024 → service account
--
-- FIX: key_prefix truncado a 8 chars para respetar VARCHAR(8) de V3.
--   'da-adm001' (9) → 'da-adm01' (8)
--   'da-usr002' (9) → 'da-usr02' (8)
--   'da-svc003' (9) → 'da-svc03' (8)
--
--   El ApiKeyAuthFilter usa los primeros 8 chars del raw key como prefix,
--   por lo que el raw key sigue siendo válido — solo el campo de búsqueda
--   queda alineado con el tamaño de la columna.
-- ══════════════════════════════════════════════════════════════════════════

DO $$
    DECLARE
        v_admin_id UUID;
        v_user_id  UUID;
        v_svc_id   UUID;
        v_role_admin_id UUID;
        v_role_user_id  UUID;
    BEGIN

        -- ── 1. Obtener IDs de roles ────────────────────────────────────────────────
        SELECT id INTO v_role_admin_id FROM auth.roles WHERE name = 'ADMIN';
        SELECT id INTO v_role_user_id  FROM auth.roles WHERE name = 'USER';

        -- ── 2. Crear usuario ADMIN ────────────────────────────────────────────────
-- Password: Admin2024!  → BCrypt $2a$12$...
        INSERT INTO auth.users (email, password_hash, name, active)
        VALUES (
                   'admin@diegoanyosa.com',
                   '$2a$12$Nn/WUsfnmCd5qkhmXBV2GOp5i1/D3cMpc/oYeJL0x62s.6E2MV0H.',
                   'Diego Anyosa Admin',
                   true
               )
        ON CONFLICT (email) DO NOTHING
        RETURNING id INTO v_admin_id;

-- Si ya existía, obtener el ID
        IF v_admin_id IS NULL THEN
            SELECT id INTO v_admin_id FROM auth.users WHERE email = 'admin@diegoanyosa.com';
        END IF;

-- Asignar rol ADMIN
        INSERT INTO auth.user_roles (user_id, role_id)
        VALUES (v_admin_id, v_role_admin_id)
        ON CONFLICT DO NOTHING;

        -- ── 3. Crear usuario USER ─────────────────────────────────────────────────
-- Password: User2024!  → BCrypt $2a$12$...
        INSERT INTO auth.users (email, password_hash, name, active)
        VALUES (
                   'user@diegoanyosa.com',
                   '$2a$12$.maN4z03x.w8vraO/FDbTOQEJKBxrNxFttQ/NCbD4AKjnRawDhiUm',
                   'Diego Anyosa User',
                   true
               )
        ON CONFLICT (email) DO NOTHING
        RETURNING id INTO v_user_id;

        IF v_user_id IS NULL THEN
            SELECT id INTO v_user_id FROM auth.users WHERE email = 'user@diegoanyosa.com';
        END IF;

        INSERT INTO auth.user_roles (user_id, role_id)
        VALUES (v_user_id, v_role_user_id)
        ON CONFLICT DO NOTHING;

        -- ── 4. Crear cuenta de servicio ───────────────────────────────────────────
-- Password: Svc2024!  → BCrypt $2a$12$...
        INSERT INTO auth.users (email, password_hash, name, active)
        VALUES (
                   'svc@diegoanyosa.com',
                   '$2a$12$XvZ706nZRMmOZrBxy/QPPOrFLm1vlw8uz1bR4k76Nr/JR.Ts.AgAO',
                   'Service Account',
                   true
               )
        ON CONFLICT (email) DO NOTHING
        RETURNING id INTO v_svc_id;

        IF v_svc_id IS NULL THEN
            SELECT id INTO v_svc_id FROM auth.users WHERE email = 'svc@diegoanyosa.com';
        END IF;

        INSERT INTO auth.user_roles (user_id, role_id)
        VALUES (v_svc_id, v_role_user_id)
        ON CONFLICT DO NOTHING;

        -- ── 5. Crear API Keys ─────────────────────────────────────────────────────
-- FIXED: key_prefix recortado a exactamente 8 chars (VARCHAR(8) en V3).
-- El ApiKeyAuthFilter toma rawKey.substring(0, 8) → debe coincidir aquí.
--
--   Raw key                               → prefix (primeros 8 chars)
--   da-adm001-diegoanyosa-admin-key-2024  → 'da-adm01'
--   da-usr002-diegoanyosa-user-key-2024   → 'da-usr02'
--   da-svc003-diegoanyosa-service-key-2024→ 'da-svc02'

-- Limpiar keys existentes del seed para evitar duplicados en re-runs
        DELETE FROM auth.api_keys WHERE key_prefix IN ('da-adm01', 'da-usr02', 'da-svc03');

        -- API Key 1: Admin
-- Raw key: da-adm001-diegoanyosa-admin-key-2024
        INSERT INTO auth.api_keys (key_hash, key_prefix, name, user_id, active)
        VALUES (
                   '$2a$12$QNigE3hcX5/7gSud48bmYu.lg2/bbk1VAJ20p4ZqSFjGHhqtQgcK6',
                   'da-adm01',
                   'admin-key-local',
                   v_admin_id,
                   true
               );

        -- API Key 2: User
-- Raw key: da-usr002-diegoanyosa-user-key-2024
        INSERT INTO auth.api_keys (key_hash, key_prefix, name, user_id, active)
        VALUES (
                   '$2a$12$OcQU3W43YU2y4GCEx6ccvOLtbE4i1lR4xtWD4NaoLjuq1jnD1tanW',
                   'da-usr02',
                   'user-key-local',
                   v_user_id,
                   true
               );

        -- API Key 3: Service account
-- Raw key: da-svc003-diegoanyosa-service-key-2024
        INSERT INTO auth.api_keys (key_hash, key_prefix, name, user_id, active)
        VALUES (
                   '$2a$12$mx.BfjFH1a0ClHcvhc7Ef.Mi/edj9vZqO.f4xW72.FXIn9FlHvNfG',
                   'da-svc03',
                   'service-key-local',
                   v_svc_id,
                   true
               );

        RAISE NOTICE 'Seed V4 completado: 3 usuarios + 3 API Keys creados';
        RAISE NOTICE '  admin@diegoanyosa.com  → API Key: da-adm001-diegoanyosa-admin-key-2024';
        RAISE NOTICE '  user@diegoanyosa.com   → API Key: da-usr002-diegoanyosa-user-key-2024';
        RAISE NOTICE '  svc@diegoanyosa.com    → API Key: da-svc003-diegoanyosa-service-key-2024';

    END $$;
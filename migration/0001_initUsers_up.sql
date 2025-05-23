
CREATE TABLE users (
  id             UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
  email          TEXT      NOT NULL UNIQUE,
  password_hash  TEXT      NOT NULL,
  created_at     TIMESTAMP WITH TIME ZONE DEFAULT now()
);
CREATE INDEX ON users(email);

CREATE TABLE roles (
  id   SERIAL    PRIMARY KEY,
  name TEXT      NOT NULL UNIQUE      
);

CREATE TABLE user_roles (
  user_id UUID REFERENCES users(id)    ON DELETE CASCADE,
  role_id INT  REFERENCES roles(id)    ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE refresh_tokens (
  id           UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   TEXT      NOT NULL,                  -- bcrypt‑хеш чистого токена
  user_agent   TEXT      NOT NULL,
  created_at   TIMESTAMP WITH TIME ZONE DEFAULT now(),
  used_at      TIMESTAMP WITH TIME ZONE,            -- время первого использования
  revoked      BOOLEAN   DEFAULT FALSE
);
CREATE INDEX ON refresh_tokens(user_id);

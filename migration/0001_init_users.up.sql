
CREATE TABLE users (
  id             UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
  email          TEXT      NOT NULL UNIQUE,
  password_hash  TEXT      NOT NULL,
  created_at     TIMESTAMP WITH TIME ZONE DEFAULT now(),
  user_role     TEXT DEFAULT 'member' 
);
CREATE INDEX ON users(email);


CREATE TABLE refresh_tokens (
  id           UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   TEXT      NOT NULL,     
  user_agent   TEXT      NOT NULL,
  created_at   TIMESTAMP WITH TIME ZONE DEFAULT now(),
  used_at      TIMESTAMP WITH TIME ZONE, 
  revoked      BOOLEAN   DEFAULT FALSE
);
CREATE INDEX ON refresh_tokens(user_id);

package models

import (
	"time"

	"github.com/gofrs/uuid"
)

type Credentials struct {
	UserID       uuid.UUID
	PasswordHash string // bcrypt‑хэш
}

type User struct {
	ID        uuid.UUID
	Email     string
	CreatedAt time.Time
	Roles     []string
}

type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	UserAgent string
	CreatedAt time.Time
	UsedAt    *time.Time
	Revoked   bool
}

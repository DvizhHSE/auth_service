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
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	CreatedAt time.Time
	Role      string `json:"role"`
}

type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	UserAgent string
	CreatedAt time.Time
	UsedAt    *time.Time
	Revoked   bool

	Token string `json:"token,omitempty"`
}

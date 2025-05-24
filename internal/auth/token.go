package auth

import (
	"auth_service/internal/models"
	"auth_service/internal/storage"
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("qwerty1234")

type Claims struct {
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
	Email  string    `json:"email"`
	jwt.RegisteredClaims
}

func GenerateJWT(userID uuid.UUID, role string, email string, ttl time.Duration) (string, error) {
	expirationTime := time.Now().Add(ttl)
	claims := &Claims{
		UserID: userID,
		Role:   role,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodPS512, claims)
	return token.SignedString(jwtKey)
}

func GenerateAndStoreRefreshToken(ctx context.Context, st storage.Storage, userID uuid.UUID) (models.RefreshToken, error) {
	const op = "auth.GenerateAndStoreRefreshToken"

	refreshToken := models.RefreshToken{}

	tokenID, err := uuid.NewV4()
	if err != nil {
		return refreshToken, fmt.Errorf("%s: %w", op, err)
	}

	secret, err := RandomString(32)
	if err != nil {
		return refreshToken, fmt.Errorf("%s: %w", op, err)
	}

	raw := tokenID.String() + ":" + secret
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	hashed, err := HashRefresh(secret)
	if err != nil {
		return refreshToken, fmt.Errorf("%s: %w", op, err)
	}

	refreshToken = models.RefreshToken{
		ID:        tokenID,
		UserID:    userID,
		TokenHash: hashed,
		CreatedAt: time.Now().UTC(),
		Revoked:   false,
	}

	if err := st.CreateRefreshToken(ctx, refreshToken); err != nil {
		return models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	refreshToken.Token = encoded

	return refreshToken, nil
}

func CheckRefreshToken(secret, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	return err == nil
}

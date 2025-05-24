package service

import (
	"auth_service/internal/auth"
	"auth_service/internal/models"
	"auth_service/internal/storage"
	"context"
	"fmt"
	"time"

	"github.com/gofrs/uuid"
)

const (
	jwtTokenTTL     = 5  //minutes if jwt token expirationTime
	refreshTokenTTL = 10 //days of refresh token ttl
)

type Service interface {
	CreateUser(ctx context.Context, email, password string) (models.User, error)
	Login(ctx context.Context, email, password string) (string, models.RefreshToken, error)
	ListUsers(ctx context.Context) ([]models.User, error)

	AssignRole(ctx context.Context, userID uuid.UUID, role string) error
	RemoveRole(ctx context.Context, userID uuid.UUID, role string) error
	GetUserRole(ctx context.Context, userID uuid.UUID) (string, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (models.User, error)

	RefreshTokens(ctx context.Context, refreshTokenID uuid.UUID, secret string) (string, models.RefreshToken, error)
	RemoveAllTokens(ctx context.Context, userID uuid.UUID) error

	Close()
}

type service struct {
	storage storage.Storage
}

func NewService(st storage.Storage) *service {
	return &service{
		storage: st,
	}
}

func (s *service) CreateUser(ctx context.Context, email, password string) (models.User, error) {
	const op = "service.CreateUser"

	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	id, err := s.storage.CreateUser(ctx, email, passwordHash)
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	user, err := s.storage.GetUserByID(ctx, id)
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *service) Login(ctx context.Context, email, password string) (string, models.RefreshToken, error) {
	const op = "service.Login"

	userCredentials, err := s.storage.GetCredentialsByEmail(ctx, email)
	if err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	if ok := auth.CheckPasswordHash(password, userCredentials.PasswordHash); !ok {
		return "", models.RefreshToken{}, fmt.Errorf("%s: wrong password", op)
	}

	user, err := s.storage.GetUserByID(ctx, userCredentials.UserID)
	if err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	jwtToken, err := auth.GenerateJWT(user.ID, user.Role, user.Email, time.Minute*jwtTokenTTL)
	if err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	refreshToken, err := auth.GenerateAndStoreRefreshToken(ctx, s.storage, user.ID)
	if err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	return jwtToken, refreshToken, nil

}

func (s *service) ListUsers(ctx context.Context) ([]models.User, error) {
	return s.storage.ListUsers(ctx)
}

func (s *service) AssignRole(ctx context.Context, userID uuid.UUID, role string) error {
	return s.storage.AssignRole(ctx, userID, role)
}

func (s *service) RemoveRole(ctx context.Context, userID uuid.UUID, role string) error {
	return s.storage.RemoveRole(ctx, userID, role)
}

func (s *service) GetUserRole(ctx context.Context, userID uuid.UUID) (string, error) {
	return s.storage.GetUserRole(ctx, userID)
}

func (s *service) RefreshTokens(ctx context.Context, refreshTokenID uuid.UUID, secret string) (string, models.RefreshToken, error) {
	const op = "service.RefreshTokens"

	rt, err := s.storage.GetLatestRefreshToken(ctx, refreshTokenID)
	if err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	if time.Since(rt.CreatedAt) > 24*time.Hour*refreshTokenTTL {
		return "", models.RefreshToken{}, fmt.Errorf("%s: refresh token expired", op)
	}

	if ok := auth.CheckRefreshToken(secret, rt.TokenHash); !ok {
		return "", models.RefreshToken{}, fmt.Errorf("%s: invalid refresh token", op)
	}

	user, err := s.storage.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	jwtToken, err := auth.GenerateJWT(user.ID, user.Role, user.Email, time.Minute*jwtTokenTTL)
	if err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	refreshToken, err := auth.GenerateAndStoreRefreshToken(ctx, s.storage, user.ID)
	if err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	_ = s.storage.RevokeRefreshToken(ctx, rt.ID)

	return jwtToken, refreshToken, nil
}

func (s *service) RemoveAllTokens(ctx context.Context, userID uuid.UUID) error {
	return s.storage.RemoveAllRefreshTokensForUser(ctx, userID)
}

func (s *service) GetUserByID(ctx context.Context, userID uuid.UUID) (models.User, error) {
	return s.storage.GetUserByID(ctx, userID)
}

func (s *service) Close() {
	s.storage.Close()
}

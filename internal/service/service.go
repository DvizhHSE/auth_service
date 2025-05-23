package service

import (
	"auth_service/internal/auth"
	"auth_service/internal/models"
	"auth_service/internal/storage"
	"context"
	"fmt"
	"time"
)

const (
	jwtTokenTTL = 5 //minutes if jwt token expirationTime
)

type Service interface {
	CreateUser(ctx context.Context, email, passwordHash string) (models.User, error)
	Login(ctx context.Context, email, password string) (string, models.RefreshToken)
	ListUsers(ctx context.Context) ([]models.User, error)
	GetCredentialsByEmail(ctx context.Context, email string) (models.Credentials, error)
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

	if ok := auth.CheckPasswordHash(userCredentials.PasswordHash, password); !ok {
		return "", models.RefreshToken{}, fmt.Errorf("%s: wrong password", op)
	}

	user, err := s.storage.GetUserByID(ctx, userCredentials.UserID)
	if err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	jwtToken, err := auth.GenerateJWT(user.ID, time.Minute*jwtTokenTTL)
	if err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

}

func (s *service) GetCredentialsByEmail(ctx context.Context, email string) (models.Credentials, error) {
	return models.Credentials{}, nil
}

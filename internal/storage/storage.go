package storage

import (
	"auth_service/internal/models"
	"context"
	"fmt"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
)

const (
	usersTable         = "users"
	rolesTable         = "roles"
	userRolesTable     = "user_roles"
	refreshTokensTable = "refresh_tokens"
)

type Storage interface {

	// Пользователи и аутентификация
	CreateUser(ctx context.Context, email, passwordHash string) (userID uuid.UUID, err error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (models.User, error)
	ListUsers(ctx context.Context) ([]models.User, error)
	GetCredentialsByEmail(ctx context.Context, email string) (models.Credentials, error)

	// Роли и авторизация
	GetUserRole(ctx context.Context, userID uuid.UUID) (string, error)
	AssignRole(ctx context.Context, userID uuid.UUID, roleName string) error
	RemoveRole(ctx context.Context, userID uuid.UUID, roleName string) error

	// Refresh-токены
	CreateRefreshToken(ctx context.Context, token models.RefreshToken) error
	GetLatestRefreshToken(ctx context.Context, tokenID uuid.UUID) (models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenID uuid.UUID) error
	RemoveAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error

	Close()
}

type PostgresStorage struct {
	db *pgxpool.Pool
}

func NewPostgresStorage(DbURL string) (*PostgresStorage, error) {
	const op = "storage.NewPostgresStorage"

	conn, err := pgxpool.Connect(context.Background(), DbURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &PostgresStorage{
		db: conn,
	}, nil
}

func (p *PostgresStorage) CreateUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	const op = "storage.CreateUser"

	var userID uuid.UUID
	query := fmt.Sprintf("INSERT INTO %s(email, password_hash) VALUES ($1, $2) RETURNING id;", usersTable)

	err := p.db.QueryRow(ctx, query, email, passwordHash).Scan(&userID)
	if err != nil {
		return userID, fmt.Errorf("%s: %w", op, err)
	}

	return userID, nil
}

func (p *PostgresStorage) GetUserByID(ctx context.Context, userID uuid.UUID) (models.User, error) {
	const op = "storage.GetUserByID"

	var user models.User
	query := fmt.Sprintf("SELECT id, email, user_role, created_at FROM %s WHERE id=$1;", usersTable)

	err := p.db.QueryRow(ctx, query, userID).Scan(&user.ID, &user.Email, &user.Role, &user.CreatedAt)
	if err != nil {
		return user, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil

}

func (p *PostgresStorage) ListUsers(ctx context.Context) ([]models.User, error) {
	const op = "storage.ListUsers"

	var users []models.User
	query := fmt.Sprintf("SELECT id, email, user_role FROM %s;", usersTable)

	rows, err := p.db.Query(ctx, query)
	if err != nil {
		return users, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	for rows.Next() {
		var user models.User

		err := rows.Scan(&user.ID, &user.Email, &user.Role)
		if err != nil {
			return users, fmt.Errorf("%s: %w", op, err)
		}

		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s (rows): %w", op, err)
	}

	return users, nil
}

func (p *PostgresStorage) GetCredentialsByEmail(ctx context.Context, email string) (models.Credentials, error) {
	const op = "storage.GetCredentialsByEmail"

	var cred models.Credentials
	query := fmt.Sprintf("SELECT id, password_hash FROM %s WHERE email=$1", usersTable)

	err := p.db.QueryRow(ctx, query, email).Scan(&cred.UserID, &cred.PasswordHash)
	if err != nil {
		return cred, fmt.Errorf("%s: %w", op, err)
	}

	return cred, nil
}

func (p *PostgresStorage) GetUserRole(ctx context.Context, userID uuid.UUID) (string, error) {
	const op = "GetUserRole"

	var userRole string

	query := fmt.Sprintf("SELECT user_role FROM %s WHERE id=$1", usersTable)

	if err := p.db.QueryRow(ctx, query, userID).Scan(&userRole); err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return userRole, nil
}

func (p *PostgresStorage) AssignRole(ctx context.Context, userID uuid.UUID, roleName string) error {
	const op = "storage.AssignRole"

	query := fmt.Sprintf("UPDATE %s SET user_role=$1 WHERE id=$2", usersTable)
	_, err := p.db.Exec(ctx, query, roleName, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (p *PostgresStorage) RemoveRole(ctx context.Context, userID uuid.UUID, roleName string) error {
	const op = "storage.RemoveRole"

	query := fmt.Sprintf(`UPDATE %s SET user_role=$1 WHERE id=$2`, usersTable)

	_, err := p.db.Exec(ctx, query, roleName, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (p *PostgresStorage) CreateRefreshToken(ctx context.Context, token models.RefreshToken) error {
	const op = "storage.CreateRefreshToken"

	query := fmt.Sprintf(`INSERT INTO %s(id, user_id, token_hash, user_agent, created_at, used_at, revoked) 
	VALUES ($1, $2, $3, $4, $5, $6, $7)`, refreshTokensTable)

	_, err := p.db.Exec(ctx, query, token.ID, token.UserID, token.TokenHash, token.UserAgent, token.CreatedAt, token.UsedAt, token.Revoked)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (p *PostgresStorage) GetLatestRefreshToken(ctx context.Context, tokenID uuid.UUID) (models.RefreshToken, error) {
	const op = "storage.GetLatestRefreshToken"

	var refreshToken models.RefreshToken
	query := fmt.Sprintf(`SELECT 
	id, user_id, token_hash, user_agent, created_at, used_at, revoked 
	FROM %s WHERE id=$1 AND revoked=FALSE
	ORDER BY created_at DESC LIMIT 1;`, refreshTokensTable)

	err := p.db.QueryRow(ctx, query, tokenID).Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.TokenHash,
		&refreshToken.UserAgent,
		&refreshToken.CreatedAt,
		&refreshToken.UsedAt,
		&refreshToken.Revoked,
	)
	if err != nil {
		return refreshToken, fmt.Errorf("%s: %w", op, err)
	}

	return refreshToken, nil
}

func (p *PostgresStorage) RevokeRefreshToken(ctx context.Context, tokenID uuid.UUID) error {
	const op = "storage.RevokeRefreshToken"
	query := fmt.Sprintf(`
      UPDATE %s
         SET revoked = TRUE,
             used_at = now()
       WHERE id = $1
    `, refreshTokensTable)
	if _, err := p.db.Exec(ctx, query, tokenID); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (p *PostgresStorage) RemoveAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error {
	const op = "storage.RevokeAllRefreshTokensForUser"

	query := fmt.Sprintf("DELETE FROM %s  WHERE user_id = $1", refreshTokensTable)
	if _, err := p.db.Exec(ctx, query, userID); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (p *PostgresStorage) Close() {
	p.db.Close()
}

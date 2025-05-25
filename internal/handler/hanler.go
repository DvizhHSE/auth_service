package handler

import (
	"auth_service/internal/auth"
	"auth_service/internal/models"
	"auth_service/internal/service"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware(jwtKey []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			newErrorResponse(c, http.StatusUnauthorized, "empty authorization header")

			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			newErrorResponse(c, http.StatusUnauthorized, "invalid authorization header")

			return
		}

		tokenStr := parts[1]

		token, err := jwt.ParseWithClaims(tokenStr, &auth.Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			newErrorResponse(c, http.StatusUnauthorized, "invalid token")

			return
		}

		claims, ok := token.Claims.(*auth.Claims)
		if !ok {
			newErrorResponse(c, http.StatusUnauthorized, "invalid token claims")

			return
		}

		c.Set("UserID", claims.ID) // string
		c.Set("Role", claims.Role)
		c.Set("Email", claims.Email)

		c.Next()
	}
}

func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var adminAuth struct {
			Login    string `json:"login"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&adminAuth); err != nil {
			newErrorResponse(c, http.StatusBadGateway, "invalid request")

			return
		}

		if adminAuth.Login != "admin_test" || adminAuth.Password != "admin_test" {
			newErrorResponse(c, http.StatusUnauthorized, "wrong login or password")

			return
		}

		c.Next()
	}
}

type Handler struct {
	serviceLayer service.Service
	log          *slog.Logger
}

type errorResponse struct {
	Message string `json:"message"`
}

type tokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func newErrorResponse(c *gin.Context, statusCode int, errMessage string) {
	c.AbortWithStatusJSON(statusCode, errorResponse{Message: errMessage})
}

func NewHandler(srvc service.Service, lgr *slog.Logger) *Handler {
	return &Handler{
		serviceLayer: srvc,
		log:          lgr,
	}
}

func (h *Handler) InitRoutes() *gin.Engine {
	router := gin.New()

	jwtKey := []byte("qwerty1234")

	auth := router.Group("/auth")
	{
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
		auth.POST("/refresh", h.RefreshTokens)

		auth.Use(AuthMiddleware(jwtKey))
		auth.POST("/logout", h.Logout)
		auth.GET("/profile", h.GetProfile)
	}
	admin := router.Group("/admin")
	{
		admin.GET("/users", h.GetAllUsers)
		roles := admin.Group("/roles")
		roles.Use(AdminAuthMiddleware())
		{
			roles.POST("/assign", h.AssignRole)
			roles.POST("/remove", h.RemoveRole)
		}
	}

	return router
}

// POST /auth/register
func (h *Handler) Register(c *gin.Context) {
	const op = "handler.Register"

	log := h.log.With(slog.String("op", op))

	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		log.Error("failed to read request body", slog.Any("error", err))

		newErrorResponse(c, http.StatusInternalServerError, err.Error())

		return
	}

	if ok := IsValidEmail(user.Email); !ok {
		log.Error("given invalid email", slog.String("email", user.Email))

		newErrorResponse(c, http.StatusBadRequest, "not valid email")

		return
	}

	if user.Password == "" {
		log.Error("given empty password")

		newErrorResponse(c, http.StatusBadRequest, "empty password")

		return
	}

	_, err := h.serviceLayer.CreateUser(c.Request.Context(), user.Email, user.Password)
	if err != nil {
		log.Error("failed to create user", slog.Any("error", err))

		newErrorResponse(c, http.StatusInternalServerError, "failed to create user")

		return
	}

	c.JSON(http.StatusCreated, user)
}

// POST /auth/login
func (h *Handler) Login(c *gin.Context) {
	const op = "handler.Login"

	log := h.log.With(slog.String("op", op))

	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		log.Error("failed to unmarshal into user struct", slog.Any("err", err))

		newErrorResponse(c, http.StatusBadRequest, "wrong struct")

		return
	}

	jwtToken, refreshToken, err := h.serviceLayer.Login(c.Request.Context(), user.Email, user.Password)
	if err != nil {
		log.Error("failed to create tokens", slog.Any("error", err))

		newErrorResponse(c, http.StatusInternalServerError, "failed to login")

		return
	}

	resp := tokensResponse{
		AccessToken:  jwtToken,
		RefreshToken: refreshToken.Token,
	}

	c.JSON(http.StatusCreated, resp)
}

// POST /auth/refresh
func (h *Handler) RefreshTokens(c *gin.Context) {
	const op = "handler.RefreshToken"

	log := h.log.With(slog.String("op", op))

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error("not given refresh token", slog.Any("error", err))

		newErrorResponse(c, http.StatusBadRequest, "wrong request format")

		return
	}

	data, err := base64.StdEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		log.Error("not given refresh token", slog.Any("error", err))

		newErrorResponse(c, http.StatusBadRequest, "invalid token")

		return
	}

	parts := strings.SplitN(string(data), ":", 2)
	if len(parts) != 2 {
		log.Error("given invalid refresh token", slog.Any("token", parts))

		newErrorResponse(c, http.StatusUnauthorized, "invalid token structure")

		return
	}

	tokenIDStr, secret := parts[0], parts[1]

	tokenId, err := uuid.FromString(tokenIDStr)
	if err != nil {
		log.Error("failed to convert token id to uuid", slog.String("token", tokenIDStr), slog.Any("error", err))

		newErrorResponse(c, http.StatusBadRequest, "invalid token id")

		return

	}

	jwtToken, refreshToken, err := h.serviceLayer.RefreshTokens(c.Request.Context(), tokenId, secret)
	if err != nil {
		log.Error("failed to create tokens", slog.Any("error", err))

		newErrorResponse(c, http.StatusUnauthorized, err.Error())

		return
	}

	resp := tokensResponse{
		AccessToken:  jwtToken,
		RefreshToken: refreshToken.Token,
	}

	c.JSON(http.StatusCreated, resp)

}

// POST /auth/logout
func (h *Handler) Logout(c *gin.Context) {
	const op = "handler.Logout"

	log := h.log.With(slog.String("op", op))

	userID, ok := c.Get("UserID")
	if !ok {
		log.Error("failed to get user id from context")

		newErrorResponse(c, http.StatusUnauthorized, "invalid token")

		return
	}

	idStr, ok := userID.(string)
	if !ok {
		log.Error("invalid user id", slog.Any("id", userID))

		newErrorResponse(c, http.StatusUnauthorized, "invalid id")

		return
	}

	id, err := uuid.FromString(idStr)
	if err != nil {
		log.Error("failed to convert to uuid", slog.Any("error", err.Error()))

		newErrorResponse(c, http.StatusUnauthorized, err.Error())

		return
	}

	err = h.serviceLayer.RemoveAllTokens(c.Request.Context(), id)
	if err != nil {
		log.Error("failed to remove all user refresh tokens", slog.Any("error", err))

		newErrorResponse(c, http.StatusInternalServerError, "internal error")

		return
	}

	log.Info("user logout", slog.Any("user_id", id))

	c.JSON(http.StatusOK, gin.H{"message": "Logout"})
}

// GET /auth/profile
func (h *Handler) GetProfile(c *gin.Context) {
	const op = "handler.GetProfile"

	log := h.log.With(slog.String("op", op))

	userID, ok := c.Get("UserID")
	if !ok {
		log.Error("failed to get user id from context")

		newErrorResponse(c, http.StatusUnauthorized, "invalid token")

		return
	}

	idStr, ok := userID.(string)
	if !ok {
		log.Error("invalid user id", slog.Any("id", userID))

		newErrorResponse(c, http.StatusUnauthorized, "invalid id")

		return
	}

	id, err := uuid.FromString(idStr)
	if err != nil {
		log.Error("failed to convert to uuid", slog.Any("error", err.Error()))

		newErrorResponse(c, http.StatusUnauthorized, err.Error())

		return
	}

	user, err := h.serviceLayer.GetUserByID(c.Request.Context(), id)
	if err != nil {
		log.Error("failed to get user by id", slog.Any("user_id", id), slog.Any("error", err))

		newErrorResponse(c, http.StatusInternalServerError, "internal error")

		return
	}
	c.JSON(http.StatusOK, user)
}

// GET /admin/users
func (h *Handler) GetAllUsers(c *gin.Context) {
	const op = "handler.GetAllUsers"

	log := h.log.With(slog.String("op", op))

	users, err := h.serviceLayer.ListUsers(c.Request.Context())
	if err != nil {
		log.Error("failed to get all users", slog.Any("error", err))

		newErrorResponse(c, http.StatusInternalServerError, fmt.Sprint("failed to get users", err.Error()))

		return
	}

	c.JSON(http.StatusOK, users)
}

// POST /admin/roles/assign
func (h *Handler) AssignRole(c *gin.Context) {
	const op = "handler.AssignRole"

	log := h.log.With(slog.String("op", op))

	var assignUserRole struct {
		userID uuid.UUID `json:"user_id"`
		Role   string    `json:"role"`
	}

	if err := c.ShouldBindJSON(&assignUserRole); err != nil {
		log.Error("failed to bind JSON in assign role", slog.Any("error", err))

		newErrorResponse(c, http.StatusBadRequest, fmt.Sprint("failed to parse request", err.Error()))

		return
	}

	err := h.serviceLayer.AssignRole(c.Request.Context(), assignUserRole.userID, assignUserRole.Role)
	if err != nil {
		log.Error("failed to assign role to user", slog.Any("user_id", assignUserRole.userID))

		newErrorResponse(c, http.StatusInternalServerError, fmt.Sprint("failed to assign role to user", err.Error()))

		return
	}

	c.JSON(http.StatusCreated, "role changed")
}

// POST /admin/roles/remove
func (h *Handler) RemoveRole(c *gin.Context) {
	const op = "handler.RemoveRole"

	log := h.log.With(slog.String("op", op))

	var removeUserRole struct {
		userID uuid.UUID `json:"user_id"`
		role   string    `json:"role"`
	}

	if err := c.ShouldBindJSON(removeUserRole); err != nil {
		log.Error("failed to get user_id from request", slog.Any("error", err))

		newErrorResponse(c, http.StatusBadRequest, fmt.Sprint("failed to parse user id", err.Error()))

		return

	}

	err := h.serviceLayer.RemoveRole(c.Request.Context(), removeUserRole.userID, removeUserRole.role)
	if err != nil {
		log.Error("failed to remove user role", slog.Any("error", err))

		newErrorResponse(c, http.StatusInternalServerError, fmt.Sprint("failed to remove user role", err.Error()))

		return
	}

	log.Info("users role removed", slog.Any("user_id", removeUserRole.userID), slog.String("role", removeUserRole.role))

	c.JSON(http.StatusOK, "role removed")
}

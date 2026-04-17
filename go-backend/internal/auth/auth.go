package auth

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/emreozeel/pcap-analyzer/backend/internal/config"
	"github.com/emreozeel/pcap-analyzer/backend/internal/database"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// Claims represents the JWT payload used by the application.
type Claims struct {
	jwt.RegisteredClaims
	UserID uint `json:"sub"`
}

var cfg *config.Config

// Init stores a reference to the application config for token operations.
func Init(c *config.Config) {
	cfg = c
}

// HashPassword returns a bcrypt hash of the given plaintext password.
func HashPassword(plain string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// CheckPassword returns true if the plaintext password matches the hash.
func CheckPassword(plain, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// CreateToken generates a signed JWT for the given user with the specified
// expiration period in hours.
func CreateToken(user *models.User, expireHours int) (string, error) {
	if cfg == nil {
		return "", errors.New("auth package not initialised; call auth.Init first")
	}

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatUint(uint64(user.ID), 10),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expireHours) * time.Hour)),
		},
		UserID: user.ID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWTSecret))
}

// ParseToken validates and parses a JWT string, returning the embedded claims.
func ParseToken(tokenStr string) (*Claims, error) {
	if cfg == nil {
		return nil, errors.New("auth package not initialised; call auth.Init first")
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Populate UserID from Subject if it was parsed from an older token
	// that only set the standard "sub" claim.
	if claims.UserID == 0 && claims.Subject != "" {
		if id, err := strconv.ParseUint(claims.Subject, 10, 64); err == nil {
			claims.UserID = uint(id)
		}
	}

	return claims, nil
}

// Middleware returns a Gin middleware that enforces JWT authentication.
// On success it sets "user" in the Gin context to the authenticated *models.User.
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "missing authorization header"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "invalid authorization header format"})
			return
		}

		claims, err := ParseToken(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "invalid or expired token"})
			return
		}

		var user models.User
		if err := database.DB.First(&user, claims.UserID).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "user not found"})
			return
		}

		c.Set("user", &user)
		c.Next()
	}
}

// AdminOnly returns a Gin middleware that requires the authenticated user to
// be an admin. It must be used after Middleware().
func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := CurrentUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
			return
		}
		if !user.IsAdmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": "admin access required"})
			return
		}
		c.Next()
	}
}

// CurrentUser retrieves the authenticated user from the Gin context.
// Returns nil if no user is set (i.e. the request was not authenticated).
func CurrentUser(c *gin.Context) *models.User {
	v, exists := c.Get("user")
	if !exists {
		return nil
	}
	user, ok := v.(*models.User)
	if !ok {
		return nil
	}
	return user
}

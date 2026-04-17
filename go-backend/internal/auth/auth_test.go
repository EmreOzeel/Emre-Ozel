package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/emreozeel/pcap-analyzer/backend/internal/config"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

// Test 1: HashPassword + CheckPassword round trip
func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("mypassword")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if !CheckPassword("mypassword", hash) {
		t.Error("CheckPassword should return true for correct password")
	}
	if CheckPassword("wrongpassword", hash) {
		t.Error("CheckPassword should return false for wrong password")
	}
}

// Test 2: CreateToken + ParseToken round trip
func TestCreateParseToken(t *testing.T) {
	Init(&config.Config{JWTSecret: "test-secret-key-for-testing-123"})

	user := &models.User{ID: 42, Username: "testuser", IsAdmin: true}
	token, err := CreateToken(user, 24)
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	claims, err := ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("expected UserID 42, got %d", claims.UserID)
	}
}

// Test 3: Invalid token rejected
func TestInvalidTokenRejected(t *testing.T) {
	Init(&config.Config{JWTSecret: "test-secret-key-for-testing-123"})

	_, err := ParseToken("not.a.valid.token")
	if err == nil {
		t.Error("ParseToken should reject invalid token")
	}
}

// Test 4: Expired token rejected
func TestExpiredTokenRejected(t *testing.T) {
	Init(&config.Config{JWTSecret: "test-secret-key-for-testing-123"})

	// Create a token with past expiration
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
		UserID: 1,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString([]byte(cfg.JWTSecret))

	_, err := ParseToken(tokenStr)
	if err == nil {
		t.Error("ParseToken should reject expired token")
	}
}

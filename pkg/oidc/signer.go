package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	PrivateKey *rsa.PrivateKey
	KeyID      string
	IssuerURL  string
}

func getEnvInt(key string, fallback int) int {
	if raw := os.Getenv(key); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func loadPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	// Try PKCS#1 first
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Fallback to PKCS#8
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key as PKCS#1 or PKCS#8: %w", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not an RSA private key")
	}

	return rsaKey, nil
}

func NewSigner(issuerURL, keyID string) (*Signer, error) {
	var key *rsa.PrivateKey
	var err error

	// Check if a persistent key path or inline PEM is provided
	if keyPath := os.Getenv("WIF_PRIVATE_KEY_PATH"); keyPath != "" {
		log.Printf("[OIDC] Loading persistent RSA signing key from file: %s", keyPath)
		keyData, readErr := os.ReadFile(keyPath)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read private key from %s: %w", keyPath, readErr)
		}
		key, err = loadPrivateKeyFromPEM(keyData)
		if err != nil {
			return nil, fmt.Errorf("invalid private key in %s: %w", keyPath, err)
		}
	} else if keyPEM := os.Getenv("WIF_PRIVATE_KEY_PEM"); keyPEM != "" {
		log.Println("[OIDC] Loading persistent RSA signing key from WIF_PRIVATE_KEY_PEM environment variable")
		key, err = loadPrivateKeyFromPEM([]byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("invalid inline private key PEM: %w", err)
		}
	} else {
		// Fall back to ephemeral generated key
		bits := getEnvInt("WIF_RSA_KEY_BITS", 2048)
		log.Printf("[OIDC] WARNING: WIF_PRIVATE_KEY_PATH not set. Generating %d-bit in-memory ephemeral key (dev only)", bits)
		key, err = rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("failed generating RSA key: %w", err)
		}
	}

	return &Signer{
		PrivateKey: key,
		KeyID:      keyID,
		IssuerURL:  issuerURL,
	}, nil
}

func (s *Signer) MintToken(audience string, claimsMap map[string]interface{}) (string, error) {
	expiryMinutes := getEnvInt("WIF_TOKEN_EXPIRY_MINUTES", 15)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": s.IssuerURL,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(expiryMinutes) * time.Minute).Unix(),
	}

	for k, v := range claimsMap {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.KeyID

	return token.SignedString(s.PrivateKey)
}
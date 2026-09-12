package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"os"
)

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func BuildJWKS(pub *rsa.PublicKey, kid string) JWKS {
	nStr := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	alg := getEnv("WIF_JWKS_ALG", "RS256")
	use := getEnv("WIF_JWKS_USE", "sig")
	kty := getEnv("WIF_JWKS_KTY", "RSA")

	return JWKS{
		Keys: []JWK{
			{
				Kty: kty,
				Alg: alg,
				Use: use,
				Kid: kid,
				N:   nStr,
				E:   eStr,
			},
		},
	}
}
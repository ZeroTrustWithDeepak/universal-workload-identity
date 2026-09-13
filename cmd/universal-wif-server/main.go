package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"universal-wif/pkg/oidc"
)

type JWKSResponse struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		// RSA parameters
		N string `json:"n"`
		E string `json:"e"`
		// EC parameters
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"keys"`
}

type TokenRequest struct {
	AuthToken string            `json:"auth_token"`
	Audience  string            `json:"audience"`
	Context   map[string]string `json:"context"`
}

// Kubernetes TokenReview Structures
type TokenReviewSpec struct {
	Token string `json:"token"`
}

type TokenReviewStatus struct {
	Authenticated bool `json:"authenticated"`
	User          struct {
		Username string              `json:"username"`
		UID      string              `json:"uid"`
		Groups   []string            `json:"groups"`
		Extra    map[string][]string `json:"extra"`
	} `json:"user"`
	Error string `json:"error,omitempty"`
}

type TokenReviewRequest struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Spec       TokenReviewSpec   `json:"spec"`
	Status     TokenReviewStatus `json:"status,omitempty"`
}

var (
	signer    *oidc.Signer
	jwks      oidc.JWKS
	issuerURL string
)

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return strings.TrimSpace(val) // <-- Add strings.TrimSpace
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if raw := os.Getenv(key); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func main() {
	issuerURL = os.Getenv("WIF_ISSUER_URL")
	if issuerURL == "" {
		log.Fatal("WIF_ISSUER_URL environment variable is required")
	}

	keyID := getEnv("WIF_KEY_ID", "wif-root-key-1")

	var err error
	signer, err = oidc.NewSigner(issuerURL, keyID)
	if err != nil {
		log.Fatalf("Failed to initialize OIDC signer: %v", err)
	}

	jwks = oidc.BuildJWKS(&signer.PrivateKey.PublicKey, keyID)

	http.HandleFunc("/.well-known/openid-configuration", handleOpenIDConfig)
	http.HandleFunc("/.well-known/jwks.json", handleJWKS)
	http.HandleFunc("/v1/token", handleToken)

	port := getEnv("PORT", "8080")

	log.Printf("[Server] Universal WIF Authority listening on port %s", port)
	log.Printf("[Server] Issuer URL: %s", issuerURL)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"issuer":                                issuerURL,
		"jwks_uri":                              fmt.Sprintf("%s/.well-known/jwks.json", issuerURL),
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// verifyJWKSToken supports both RSA (RS256) and ECDSA (ES256) keys
func verifyJWKSToken(rawToken, jwksURL, expectedAudience string) (jwt.MapClaims, error) {
	timeout := getEnvInt("JWKS_FETCH_TIMEOUT_SECONDS", 5)
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed fetching jwks from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	var jwksResp JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwksResp); err != nil {
		return nil, fmt.Errorf("failed parsing jwks: %w", err)
	}

	token, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)

		for _, k := range jwksResp.Keys {
			if kid != "" && k.Kid != kid {
				continue
			}

			switch k.Kty {
			case "RSA":
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method for RSA: %v", token.Header["alg"])
				}
				nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
				if err != nil {
					nBytes, err = base64.URLEncoding.DecodeString(k.N)
					if err != nil {
						return nil, fmt.Errorf("failed decoding RSA N: %w", err)
					}
				}
				eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
				if err != nil {
					eBytes, err = base64.URLEncoding.DecodeString(k.E)
					if err != nil {
						return nil, fmt.Errorf("failed decoding RSA E: %w", err)
					}
				}
				var eInt int
				for _, b := range eBytes {
					eInt = (eInt << 8) | int(b)
				}
				return &rsa.PublicKey{
					N: new(big.Int).SetBytes(nBytes),
					E: eInt,
				}, nil

			case "EC":
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("unexpected signing method for EC: %v", token.Header["alg"])
				}
				xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
				if err != nil {
					xBytes, err = base64.URLEncoding.DecodeString(k.X)
					if err != nil {
						return nil, fmt.Errorf("failed decoding EC X: %w", err)
					}
				}
				yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
				if err != nil {
					yBytes, err = base64.URLEncoding.DecodeString(k.Y)
					if err != nil {
						return nil, fmt.Errorf("failed decoding EC Y: %w", err)
					}
				}

				var curve elliptic.Curve
				switch k.Crv {
			    case "P-256":
					curve = elliptic.P256()
				case "P-384":
					curve = elliptic.P384()
				case "P-521":
					curve = elliptic.P521()
				default:
					return nil, fmt.Errorf("unsupported EC curve: %s", k.Crv)
				}

				return &ecdsa.PublicKey{
					Curve: curve,
					X:     new(big.Int).SetBytes(xBytes),
					Y:     new(big.Int).SetBytes(yBytes),
				}, nil
			}
		}
		return nil, fmt.Errorf("matching key not found for kid: %s", kid)
	})

	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	var audValid bool
	switch aud := claims["aud"].(type) {
	case string:
		audValid = (aud == expectedAudience)
	case []interface{}:
		for _, v := range aud {
			if s, ok := v.(string); ok && s == expectedAudience {
				audValid = true
				break
			}
		}
	}
	if !audValid {
		return nil, fmt.Errorf("audience mismatch: expected '%s', got '%v'", expectedAudience, claims["aud"])
	}

	return claims, nil
}

// verifySpiffeToken validates an on-prem VM SPIFFE JWT-SVID
func verifySpiffeToken(rawToken string) (sub string, extraClaims map[string]interface{}, err error) {
	spireJWKSURL := getEnv("SPIRE_JWKS_URL", "http://127.0.0.1:8083/keys")
	expectedAudience := getEnv("SPIRE_EXPECTED_AUDIENCE", "universal-wif-authority")

	claims, err := verifyJWKSToken(rawToken, spireJWKSURL, expectedAudience)
	if err != nil {
		return "", nil, fmt.Errorf("spiffe validation failed: %w", err)
	}

	spiffeID, _ := claims["sub"].(string)
	if !strings.HasPrefix(spiffeID, "spiffe://") {
		return "", nil, fmt.Errorf("malformed spiffe id: %s", spiffeID)
	}

	cleanPath := strings.TrimPrefix(spiffeID, "spiffe://")
	parts := strings.Split(cleanPath, "/")
	trustDomain := parts[0]

	var relativePath string
	if len(parts) > 1 {
		relativePath = strings.Join(parts[1:], "/")
	} else {
		relativePath = trustDomain
	}

	sub = fmt.Sprintf("vm:onprem:%s", strings.ReplaceAll(relativePath, "/", ":"))

	extraClaims = make(map[string]interface{})
	extraClaims["spiffe_id"] = spiffeID
	extraClaims["trust_domain"] = trustDomain

	for i := 1; i < len(parts)-1; i += 2 {
		key := parts[i]
		val := parts[i+1]
		extraClaims[key] = val
	}

	return sub, extraClaims, nil
}

// verifyJenkinsToken validates Jenkins OIDC token
func verifyJenkinsToken(rawToken string) (sub string, extraClaims map[string]interface{}, err error) {
	jenkinsJWKSURL := getEnv("JENKINS_JWKS_URL", "http://127.0.0.1:8081/oidc/jwks")
	expectedAudience := getEnv("JENKINS_EXPECTED_AUDIENCE", "universal-wif-authority")

	claims, err := verifyJWKSToken(rawToken, jenkinsJWKSURL, expectedAudience)
	if err != nil {
		return "", nil, fmt.Errorf("jenkins verification failed: %w", err)
	}

	rawSub, _ := claims["sub"].(string)
	cleanPath := rawSub
	if idx := strings.Index(cleanPath, "/job/"); idx != -1 {
		cleanPath = cleanPath[idx+5:]
	}
	cleanPath = strings.ReplaceAll(cleanPath, "job/", "")
	cleanPath = strings.Trim(cleanPath, "/")

	if cleanPath == "" {
		cleanPath = "unknown-job"
	}

	sub = fmt.Sprintf("jenkins:path:%s", cleanPath)

	extraClaims = make(map[string]interface{})
	extraClaims["jenkins_raw_sub"] = rawSub
	extraClaims["jenkins_path"] = cleanPath

	if repo, ok := claims["repo_url"].(string); ok && repo != "" {
		extraClaims["repo_url"] = repo
	} else {
		extraClaims["repo_url"] = "none"
	}

	if branch, ok := claims["git_branch"].(string); ok && branch != "" {
		extraClaims["git_branch"] = branch
	} else {
		extraClaims["git_branch"] = "none"
	}

	return sub, extraClaims, nil
}

// verifyK8sToken validates a projected ServiceAccount token using Kubernetes TokenReview API
func verifyK8sToken(k8sToken string) (namespace string, serviceAccount string, saUID string, err error) {
	k8sHost := getEnv("KUBERNETES_API_URL", "https://kubernetes.default.svc")
	serverToken := os.Getenv("K8S_SERVER_REVIEWER_TOKEN")
	timeout := getEnvInt("K8S_CLIENT_TIMEOUT_SECONDS", 5)

	insecureSkipVerify := true
	if val := os.Getenv("K8S_TLS_INSECURE_SKIP_VERIFY"); val != "" {
		if parsed, err := strconv.ParseBool(val); err == nil {
			insecureSkipVerify = parsed
		}
	}

	reviewReq := TokenReviewRequest{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec: TokenReviewSpec{
			Token: k8sToken,
		},
	}

	payload, err := json.Marshal(reviewReq)
	if err != nil {
		return "", "", "", err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(timeout) * time.Second}

	url := strings.TrimRight(k8sHost, "/") + "/apis/authentication.k8s.io/v1/tokenreviews"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return "", "", "", err
	}

	req.Header.Set("Content-Type", "application/json")
	if serverToken != "" {
		req.Header.Set("Authorization", "Bearer "+serverToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to contact k8s api: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", "", "", fmt.Errorf("k8s api returned status %d: %s", resp.StatusCode, string(body))
	}

	var reviewResp TokenReviewRequest
	if err := json.Unmarshal(body, &reviewResp); err != nil {
		return "", "", "", fmt.Errorf("failed to decode k8s api response: %w", err)
	}

	if !reviewResp.Status.Authenticated {
		return "", "", "", fmt.Errorf("k8s token rejected: %s", reviewResp.Status.Error)
	}

	parts := strings.Split(reviewResp.Status.User.Username, ":")
	if len(parts) < 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return "", "", "", fmt.Errorf("unexpected user format: %s", reviewResp.Status.User.Username)
	}

	return parts[2], parts[3], reviewResp.Status.User.UID, nil
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Malformed JSON", http.StatusBadRequest)
		return
	}

	expectedSecret := os.Getenv("AGENT_SHARED_SECRET")
	if expectedSecret != "" && req.AuthToken != expectedSecret {
		http.Error(w, "Unauthorized runner agent", http.StatusUnauthorized)
		return
	}

	ctx := req.Context
	if ctx == nil {
		ctx = make(map[string]string)
	}

	platform := ctx["platform"]
	if platform == "" {
		platform = "generic"
	}

	var sub string
	claimsMap := map[string]interface{}{
		"platform": platform,
	}

	for k, v := range ctx {
		// Strip raw attestation tokens from GCP token claims
		if k == "k8s_token" || k == "jenkins_token" || k == "spiffe_token" {
			continue
		}
		claimsMap[k] = v
	}

	switch platform {
	case "k8s":
		k8sToken := ctx["k8s_token"]
		if k8sToken == "" {
			http.Error(w, "Missing cryptographic k8s_token", http.StatusUnauthorized)
			return
		}

		ns, sa, saUID, err := verifyK8sToken(k8sToken)
		if err != nil {
			log.Printf("[K8s TokenReview Error] %v", err)
			http.Error(w, fmt.Sprintf("K8s authentication failed: %v", err), http.StatusForbidden)
			return
		}

		sub = fmt.Sprintf("k8s:ns:%s:sa:%s", ns, sa)
		claimsMap["namespace"] = ns
		claimsMap["k8s_sa"] = sa
		claimsMap["k8s_sa_uid"] = saUID

	case "jenkins":
		jenkinsToken := ctx["jenkins_token"]
		if jenkinsToken == "" {
			http.Error(w, "Missing cryptographic jenkins_token", http.StatusUnauthorized)
			return
		}

		var extraClaims map[string]interface{}
		var err error
		sub, extraClaims, err = verifyJenkinsToken(jenkinsToken)
		if err != nil {
			log.Printf("[Jenkins OIDC Error] %v", err)
			http.Error(w, fmt.Sprintf("Jenkins verification failed: %v", err), http.StatusForbidden)
			return
		}

		for k, v := range extraClaims {
			claimsMap[k] = v
		}

	case "vm":
		spiffeToken := ctx["spiffe_token"]
		if spiffeToken != "" {
			var extraClaims map[string]interface{}
			var err error
			sub, extraClaims, err = verifySpiffeToken(spiffeToken)
			if err != nil {
				log.Printf("[SPIRE OIDC Error] %v", err)
				http.Error(w, fmt.Sprintf("SPIRE VM attestation failed: %v", err), http.StatusForbidden)
				return
			}
			for k, v := range extraClaims {
				claimsMap[k] = v
			}
		} else {
			machineID := ctx["machine_id"]
			if machineID == "" {
				machineID = ctx["hostname"]
			}
			sub = fmt.Sprintf("vm:legacy:%s", machineID)
			claimsMap["machine_id"] = machineID
			claimsMap["hostname"] = ctx["hostname"]
		}

	default:
		jobName := ctx["job_name"]
		ref := ctx["ref"]
		if ref == "" {
			ref = "default"
		}
		sub = fmt.Sprintf("job:%s:ref:%s", jobName, ref)
	}

	claimsMap["sub"] = sub

	token, err := signer.MintToken(req.Audience, claimsMap)
	if err != nil {
		log.Printf("Token mint error: %v", err)
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id_token": token,
	})
}
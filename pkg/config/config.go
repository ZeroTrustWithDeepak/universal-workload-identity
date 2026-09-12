package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type ExecutableConfig struct {
	Command       string `json:"command"`
	TimeoutMillis int    `json:"timeout_millis"`
}

type CredentialSource struct {
	Executable ExecutableConfig `json:"executable"`
}

type ExternalAccountConfig struct {
	Type                           string           `json:"type"`
	Audience                       string           `json:"audience"`
	SubjectTokenType               string           `json:"subject_token_type"`
	TokenURL                       string           `json:"token_url"`
	CredentialSource               CredentialSource `json:"credential_source"`
	ServiceAccountImpersonationURL string           `json:"service_account_impersonation_url,omitempty"`
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
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

func GenerateGCPCredentialConfig(projectNumber, poolID, providerID, serviceAccount, binaryPath, outputPath string) error {
	iamDomain := getEnv("GCP_IAM_DOMAIN", "iam.googleapis.com")
	audience := fmt.Sprintf("//%s/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		iamDomain, projectNumber, poolID, providerID)

	tokenURL := getEnv("GCP_STS_TOKEN_URL", "https://sts.googleapis.com/v1/token")
	execTimeout := getEnvInt("WIF_EXEC_TIMEOUT_MILLIS", 10000)

	cfg := ExternalAccountConfig{
		Type:             "external_account",
		Audience:         audience,
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:         tokenURL,
		CredentialSource: CredentialSource{
			Executable: ExecutableConfig{
				Command:       fmt.Sprintf("%s get-token", binaryPath),
				TimeoutMillis: execTimeout,
			},
		},
	}

	if serviceAccount != "" {
		iamBaseEndpoint := strings.TrimRight(getEnv("GCP_IAM_CREDENTIALS_ENDPOINT", "https://iamcredentials.googleapis.com"), "/")
		cfg.ServiceAccountImpersonationURL = fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:generateAccessToken", iamBaseEndpoint, serviceAccount)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize credential config: %w", err)
	}

	return os.WriteFile(outputPath, data, 0644)
}
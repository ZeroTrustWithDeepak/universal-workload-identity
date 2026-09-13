package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"universal-wif/pkg/config"
	"universal-wif/pkg/providers"
)

type ExecutableOutput struct {
	Version   int    `json:"version"`
	Success   bool   `json:"success"`
	TokenType string `json:"token_type"`
	IdToken   string `json:"id_token"`
}

func init() {
	// Send any unintended standard logs to stderr
	log.SetOutput(os.Stderr)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: universal-wif [init|get-token]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		handleInit(os.Args[2:])
	case "get-token":
		handleGetToken()
	default:
		fmt.Fprintln(os.Stderr, "Unknown command. Use 'init' or 'get-token'")
		os.Exit(1)
	}
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func handleInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)

	// Defaults check ENV first; fall back to original defaults
	defaultBinaryPath := getEnv("WIF_BINARY_PATH", "/usr/local/bin/universal-wif")
	defaultOutPath := getEnv("WIF_CONFIG_OUTPUT_PATH", "/etc/google/credentials.json")

	projectNum := fs.String("project-number", os.Getenv("WIF_PROJECT_NUMBER"), "GCP Project Number")
	poolID := fs.String("pool-id", os.Getenv("WIF_POOL_ID"), "WIF Pool ID")
	providerID := fs.String("provider-id", os.Getenv("WIF_PROVIDER_ID"), "WIF Provider ID")
	saEmail := fs.String("service-account", os.Getenv("WIF_SERVICE_ACCOUNT_EMAIL"), "Target GCP Service Account Email")
	binaryPath := fs.String("binary-path", defaultBinaryPath, "Path to universal-wif binary")
	outPath := fs.String("out", defaultOutPath, "Output file destination")

	fs.Parse(args)

	if *projectNum == "" || *poolID == "" || *providerID == "" {
		fmt.Fprintf(os.Stderr, "Error: --project-number, --pool-id, and --provider-id are required (via flags or env).\n")
		os.Exit(1)
	}

	err := config.GenerateGCPCredentialConfig(*projectNum, *poolID, *providerID, *saEmail, *binaryPath, *outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialization failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[WIF] Configuration generated at: %s\n", *outPath)
}

func handleGetToken() {
	serverURL := getEnv("WIF_SERVER_URL", "http://127.0.0.1:8080")

	// Timeout configuration with original 10s default
	timeoutSecs := 10
	if rawTimeout := os.Getenv("WIF_CLIENT_TIMEOUT_SECONDS"); rawTimeout != "" {
		if parsed, err := strconv.Atoi(rawTimeout); err == nil && parsed > 0 {
			timeoutSecs = parsed
		}
	}

	audience := os.Getenv("GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE")
	if audience == "" {
		audience = os.Getenv("WIF_AUDIENCE")
	}
	if audience == "" {
		credsPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
		if credsPath != "" {
			if data, err := os.ReadFile(credsPath); err == nil {
				var credsFile struct {
					Audience string `json:"audience"`
				}
				if json.Unmarshal(data, &credsFile) == nil {
					audience = credsFile.Audience
				}
			}
		}
	}

	claims := providers.DetectEnvironment()

	payload := map[string]interface{}{
		"auth_token": os.Getenv("AGENT_SHARED_SECRET"),
		"audience":   audience,
		"context":    claims,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fail(fmt.Sprintf("Failed to marshal request payload: %v", err))
	}

	client := &http.Client{Timeout: time.Duration(timeoutSecs) * time.Second}
	resp, err := client.Post(fmt.Sprintf("%s/v1/token", serverURL), "application/json", bytes.NewBuffer(body))
	if err != nil {
		fail(fmt.Sprintf("HTTP POST to %s/v1/token failed: %v", serverURL, err))
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fail(fmt.Sprintf("Failed to read server response body: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		fail(fmt.Sprintf("Server returned HTTP %d: %s", resp.StatusCode, string(respBytes)))
	}

	var data map[string]string
	if err = json.Unmarshal(respBytes, &data); err != nil {
		fail(fmt.Sprintf("Failed to unmarshal JSON response: %v", err))
	}

	token := strings.TrimSpace(data["id_token"])
	if token == "" {
		fail("Response missing id_token")
	}

	out := ExecutableOutput{
		Version:   1,
		Success:   true,
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		IdToken:   token,
	}

	// stdout contains strictly the final JSON response
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fail(fmt.Sprintf("Failed to encode stdout JSON: %v", err))
	}
}

func fail(msg string) {
	fmt.Fprintf(os.Stderr, "[universal-wif helper error] %s\n", msg)
	os.Exit(1)
}
package providers

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

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

// DetectEnvironment inspects the runtime environment to produce immutable claims
func DetectEnvironment() map[string]string {
	claims := make(map[string]string)

	// 1. Kubernetes: Pass the cluster's cryptographically signed token
	tokenPath := getEnv("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	if k8sTokenBytes, err := os.ReadFile(tokenPath); err == nil {
		claims["platform"] = "k8s"
		claims["k8s_token"] = strings.TrimSpace(string(k8sTokenBytes))
		return claims
	}

	// 2. Jenkins environment (Attested via OIDC token)
	jenkinsToken := os.Getenv("JENKINS_OIDC_TOKEN")
	if jenkinsToken != "" || os.Getenv("JENKINS_URL") != "" || os.Getenv("BUILD_ID") != "" {
		claims["platform"] = "jenkins"
		if jenkinsToken != "" {
			claims["jenkins_token"] = strings.TrimSpace(jenkinsToken)
		}
		if jobName := os.Getenv("JOB_NAME"); jobName != "" {
			claims["job_name"] = jobName
		}
		if gitURL := os.Getenv("GIT_URL"); gitURL != "" {
			claims["repo_url"] = gitURL
		}
		if gitBranch := os.Getenv("GIT_BRANCH"); gitBranch != "" {
			claims["git_branch"] = gitBranch
		}
		return claims
	}

	// 3. On-Premises VM via SPIFFE/SPIRE Workload API
	spireSocket := getEnv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")

	if isSpireSocketAvailable(spireSocket) {
		spireTimeout := getEnvInt("SPIRE_TIMEOUT_SECONDS", 3)
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(spireTimeout)*time.Second)
		defer cancel()

		client, err := workloadapi.New(ctx, workloadapi.WithAddr(spireSocket))
		if err == nil {
			defer client.Close()

			audience := getEnv("SPIRE_AUDIENCE", "universal-wif-authority")

			token, err := client.FetchJWTSVID(ctx, jwtsvid.Params{
				Audience: audience,
			})
			if err == nil && token != nil && token.Marshal() != "" {
				claims["platform"] = "vm"
				claims["spiffe_token"] = token.Marshal()
				return claims
			}
		}
	}

	// 4. Fallback for unmanaged/dev hosts (Legacy machine-id)
	claims["platform"] = "vm"
	hostname, _ := os.Hostname()
	claims["hostname"] = hostname

	if overrideID := os.Getenv("OVERRIDE_MACHINE_ID"); overrideID != "" {
		claims["machine_id"] = overrideID
		return claims
	}

	if midBytes, err := os.ReadFile("/etc/machine-id"); err == nil && len(strings.TrimSpace(string(midBytes))) > 0 {
		claims["machine_id"] = strings.TrimSpace(string(midBytes))
		return claims
	}

	if midBytes, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil && len(strings.TrimSpace(string(midBytes))) > 0 {
		claims["machine_id"] = strings.TrimSpace(string(midBytes))
		return claims
	}

	if mac := getPrimaryMAC(); mac != "" {
		claims["machine_id"] = mac
		return claims
	}

	claims["machine_id"] = hostname
	return claims
}

func isSpireSocketAvailable(socketAddr string) bool {
	cleanPath := strings.TrimPrefix(socketAddr, "unix://")
	info, err := os.Stat(cleanPath)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}

func getPrimaryMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) > 0 {
			return strings.ReplaceAll(iface.HardwareAddr.String(), ":", "")
		}
	}
	return ""
}
package providers

import (
	"os"
	"strings"
)

type KubernetesProvider struct{}

//func getEnv(key, fallback string) string {
//	if val := os.Getenv(key); val != "" {
//		return val
//	}
//	return fallback
//}

func (k *KubernetesProvider) Detect() bool {
	tokenPath := getEnv("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	_, err := os.Stat(tokenPath)
	return err == nil
}

func (k *KubernetesProvider) GetClaims() map[string]string {
	tokenPath := getEnv("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	tokenBytes, err := os.ReadFile(tokenPath)
	k8sToken := ""
	if err == nil {
		k8sToken = strings.TrimSpace(string(tokenBytes))
	}

	namespacePath := getEnv("K8S_NAMESPACE_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	namespace := getEnv("K8S_NAMESPACE", "default")
	if nsBytes, err := os.ReadFile(namespacePath); err == nil {
		namespace = strings.TrimSpace(string(nsBytes))
	}

	podName := os.Getenv("POD_NAME")
	if podName == "" {
		podName, _ = os.Hostname()
	}

	return map[string]string{
		"platform":  "k8s",
		"k8s_token": k8sToken,
		"namespace": namespace,
		"pod_name":  podName,
	}
}
package providers

import (
	"os"
	"strings"
)

type JenkinsProvider struct{}

func (j *JenkinsProvider) Detect() bool {
	// Active if running within Jenkins or an OIDC token has been supplied
	return os.Getenv("JENKINS_URL") != "" || os.Getenv("JENKINS_OIDC_TOKEN") != "" || os.Getenv("BUILD_ID") != ""
}

func (j *JenkinsProvider) GetClaims() map[string]string {
	claims := map[string]string{
		"platform": "jenkins",
	}

	if token := os.Getenv("JENKINS_OIDC_TOKEN"); token != "" {
		claims["jenkins_token"] = strings.TrimSpace(token)
	}
	if job := os.Getenv("JOB_NAME"); job != "" {
		claims["job_name"] = job
	}
	if branch := os.Getenv("GIT_BRANCH"); branch != "" {
		claims["git_branch"] = branch
	}
	if repo := os.Getenv("GIT_URL"); repo != "" {
		claims["repo_url"] = repo
	}

	return claims
}
# Universal Workload Identity Federation (Universal WIF)

Universal WIF is a vendor-agnostic identity broker that extends Google Cloud Workload Identity Federation (WIF) to any environment. It enables workloads running on Kubernetes, Jenkins CI, on-premises virtual machines (via SPIFFE/SPIRE), and unmanaged hosts to securely obtain short-lived Google Cloud Platform (GCP) credentials without managing static service account keys.

---

## Architecture Overview

```text
+-----------------------------------------------------------------------------+
|                             Workload Environment                            |
|                                                                             |
|   +-------------------+         Calls         +-------------------------+   |
|   |   gcloud / SDKs   | --------------------> | universal-wif (CLI)     |   |
|   +-------------------+                       +-------------------------+   |
+------------------------------------------------------------|----------------+
                                                             |
                                                             | 1. Attestation
                                                             |    (K8s Token, SPIFFE,
                                                             |     Jenkins OIDC)
                                                             v
+-----------------------------------------------------------------------------+
|                      universal-wif-server (Authority)                       |
|                                                                             |
|   - Validates incoming platform attestation (K8s TokenReview/SPIRE/Jenkins) |
|   - Signs and issues standard OIDC ID tokens (RS256)                        |
|   - Hosts OIDC Discovery: /.well-known/openid-configuration & jwks.json     |
+-----------------------------------------------------------------------------+
                                     |
                                     | Public Ingress (Tunnel / Reverse Proxy)
                                     v
+-----------------------------------------------------------------------------+
|                            Google Cloud Platform                            |
|                                                                             |
|   - Google STS fetches JWKS from public issuer URL to verify signature      |
|   - Evaluates Attribute Mappings and Attribute Condition (CEL)              |
|   - Exchanges OIDC token for short-lived Google federated access token      |
|   - Impersonates target Google Service Account (GSA)                        |
+-----------------------------------------------------------------------------+

```

---

## Features

* **Multi-Platform Attestation:**
* **Kubernetes:** Validates projected `ServiceAccount` tokens using the Kubernetes `TokenReview` API.
* **Jenkins:** Verifies build job identity using Jenkins OIDC tokens.
* **On-Premises VMs:** Attests workload identity via SPIFFE/SPIRE JWT-SVIDs or machine secrets.
* **Standalone / Bare-Metal:** Host-level attestation for static or unmanaged servers.


* **Standards-Compliant OIDC Issuer:** Exposes RFC 7517 compliant discovery and JWKS endpoints.
* **Stateless & Generic:** Zero hardcoded credentials or cloud project IDs in binaries or Docker images.
* **Secure by Design:** Completely eliminates long-lived GCP service account JSON keys.
* **Plug-and-Play Client:** Works with Google Cloud SDK (`gcloud`) and client libraries using executable credential helpers.

---

## Repository Structure

```text
.
├── cmd/
│   ├── universal-wif/          # Workload CLI client (credential helper)
│   │   └── main.go
│   └── universal-wif-server/   # Central OIDC authority server
│       └── main.go
├── pkg/
│   ├── config/                 # Google ADC credential generator
│   ├── oidc/                   # JWKS builder & RSA token signing logic
│   └── providers/              # Attestation providers (K8s, Jenkins, SPIRE)
├── k8/                         # Declarative Kubernetes deployment & test manifests
│   ├── pod-test.yaml
│   ├── rbac.yaml
│   └── wif-config.yaml
├── .env.example                # Runtime configuration template
├── go.mod
└── go.sum

```

---

## Configuration Reference

The binaries read configuration from environment variables at runtime. You can define these in a `.env` file for local development, or inject them via Kubernetes `ConfigMap`/`Secret` or system environment variables.

| Variable | Description | Default / Example |
| --- | --- | --- |
| `PORT` | Listening port for the authority server | `8080` |
| `WIF_ISSUER_URL` | Public HTTPS URL where the server's JWKS is exposed to Google STS | `https://wif.yourdomain.com` |
| `WIF_KEY_ID` | Key ID (`kid`) advertised in the JWKS and JWT header | `wif-key-v1` |
| `AGENT_SHARED_SECRET` | Shared secret between client agents and the authority server | `(Required in production)` |
| `WIF_SERVER_URL` | Endpoint where the workload client reaches the server | `http://127.0.0.1:8080` |
| `KUBERNETES_API_URL` | Target Kubernetes API endpoint for `TokenReview` | `https://kubernetes.default.svc` |
| `K8S_SERVER_REVIEWER_TOKEN` | Bearer token for K8s ServiceAccount with `system:auth-delegator` | `(Required for external server)` |
| `K8S_TLS_INSECURE_SKIP_VERIFY` | Skip TLS verification for K8s API (development only) | `false` |
| `SPIRE_JWKS_URL` | Endpoint for SPIRE OIDC keys (VM workloads) | `http://127.0.0.1:8083/keys` |
| `JENKINS_JWKS_URL` | Endpoint for Jenkins OIDC keys (CI workloads) | `http://127.0.0.1:8081/oidc/jwks` |
| `WIF_TOKEN_EXPIRY_MINUTES` | Lifetime of minted OIDC JWT in minutes | `15` |
| `WIF_PRIVATE_KEY_PATH` | Path to persistent RSA private key PEM file | `(Generates in-memory key if empty)` |

---

## Building the Binaries (Cross-Platform)

You can build the binaries for your current operating system or cross-compile for any target platform.

### Standard Build (Current OS)

```bash
# Build client CLI helper
go build -o bin/universal-wif ./cmd/universal-wif

# Build authority server
go build -o bin/universal-wif-server ./cmd/universal-wif-server

```

### Cross-Compilation Matrix

Use Go's built-in target flags (`GOOS` and `GOARCH`):

```bash
# Linux (AMD64 - standard servers, cloud VMs, Kubernetes containers)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/linux-amd64/universal-wif ./cmd/universal-wif
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/linux-amd64/universal-wif-server ./cmd/universal-wif-server

# Linux (ARM64 - AWS Graviton, Raspberry Pi, Docker on Apple Silicon)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/linux-arm64/universal-wif ./cmd/universal-wif
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/linux-arm64/universal-wif-server ./cmd/universal-wif-server

# macOS (Apple Silicon / M-series)
GOOS=darwin GOARCH=arm64 go build -o bin/darwin-arm64/universal-wif ./cmd/universal-wif

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o bin/darwin-amd64/universal-wif ./cmd/universal-wif

# Windows (AMD64)
GOOS=windows GOARCH=amd64 go build -o bin/windows-amd64/universal-wif.exe ./cmd/universal-wif

```

---

## Running the Authority Server

### 1. Create and Load the Configuration

Create your `.env` file from the provided template:

```bash
cp .env.example .env

```

Populate the `.env` file with your settings:

```bash
PORT=8080
WIF_ISSUER_URL=[https://wif.yourdomain.com](https://wif.yourdomain.com)
WIF_KEY_ID=wif-key-v1
AGENT_SHARED_SECRET=your-secure-shared-secret
KUBERNETES_API_URL=[https://kubernetes.default.svc](https://kubernetes.default.svc)
K8S_SERVER_REVIEWER_TOKEN=your-token-if-running-outside-cluster

```

Load the variables into your shell session and run the server:

```bash
# Export all non-commented variables from .env into the current shell
export $(grep -v '^#' .env | xargs)

# Run the compiled binary
./bin/universal-wif-server

```

Alternatively, run directly with Go:

```bash
go run ./cmd/universal-wif-server/main.go

```

### 2. Verify Local Endpoints

Confirm the server is up and serving discovery metadata:

```bash
curl -s [http://127.0.0.1:8080/.well-known/openid-configuration](http://127.0.0.1:8080/.well-known/openid-configuration) | jq .
curl -s [http://127.0.0.1:8080/.well-known/jwks.json](http://127.0.0.1:8080/.well-known/jwks.json) | jq .

```

---

## Public Ingress (Exposing JWKS to Google STS)

Google Cloud Security Token Service (STS) must be able to reach your `WIF_ISSUER_URL` over public HTTPS to download your public keys from `/.well-known/jwks.json`.

Depending on your environment, expose port `8080` using one of the following methods:

1. **Cloudflare Tunnel (Local Testing & Edge Deployments):**
```bash
cloudflared tunnel --url http://localhost:8080

```


Copy the assigned URL (e.g., `https://your-tunnel-name.trycloudflare.com`) and set it as `WIF_ISSUER_URL`.

2. **Kubernetes Ingress (Production Clusters):**
Create an Ingress resource with TLS managed by `cert-manager` pointing to the `universal-wif-server` Service. Set `WIF_ISSUER_URL` to your domain (e.g., `https://wif.yourcompany.com`).

3. **Reverse Proxy (Nginx, Traefik, ALB):**
Route incoming traffic for `https://wif.yourcompany.com/.well-known/*` directly to `universal-wif-server:8080`.

Verify external reachability before configuring GCP:

```bash
curl -sSL https://<YOUR-PUBLIC-URL>/.well-known/jwks.json | jq .

```

---

## Google Cloud Setup Guide

### 1. Create the Workload Identity Pool

```bash
export PROJECT_ID="your-gcp-project-id"
export PROJECT_NUMBER="your-gcp-project-number"
export POOL_ID="universal-pool"
export PROVIDER_ID="universal-jwt-provider"
export ISSUER_URL="https://<YOUR-PUBLIC-ISSUER-URL>"

gcloud iam workload-identity-pools create "${POOL_ID}" \
    --project="${PROJECT_ID}" \
    --location="global" \
    --description="Universal WIF Pool"

```

### 2. Add the OIDC Provider with Attribute Mappings & Condition

Google STS requires you to map the incoming token claims (`assertion.*`) to Google-recognized attributes (`google.subject` and custom `attribute.*`).

#### Using `gcloud` CLI:

```bash
gcloud iam workload-identity-pools providers create-oidc "${PROVIDER_ID}" \
    --project="${PROJECT_ID}" \
    --location="global" \
    --workload-identity-pool="${POOL_ID}" \
    --issuer-uri="${ISSUER_URL}" \
    --allowed-audiences="//[iam.googleapis.com/projects/$](https://iam.googleapis.com/projects/$){PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}" \
    --attribute-mapping="google.subject=assertion.sub,attribute.platform=assertion.platform,attribute.namespace=assertion.namespace,attribute.k8s_sa_uid=assertion.k8s_sa_uid,attribute.hostname=assertion.hostname,attribute.job=assertion.job_name" \
    --attribute-condition="assertion.platform in ['k8s', 'vm', 'jenkins', 'standalone']"

```

#### Using Google Cloud Console (UI):

When configuring the Provider in the GCP Console under **IAM & Admin > Workload Identity Federation > Add Provider**:

1. **Provider Details:**
* **Provider Type:** OIDC
* **Issuer (URL):** Enter your public HTTPS issuer URL (e.g., `https://wif.yourcompany.com`)
* **Allowed Audiences:** Set to default pool audience or enter:
`//iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL_ID>/providers/<PROVIDER_ID>`


2. **Attribute Mapping Table:**
| Row | Google Attribute | OIDC Token Expression (CEL) |
| --- | --- | --- |
| **1** | `google.subject` | `assertion.sub` |
| **2** | `attribute.platform` | `assertion.platform` |
| **3** | `attribute.namespace` | `assertion.namespace` |
| **4** | `attribute.k8s_sa_uid` | `assertion.k8s_sa_uid` |
| **5** | `attribute.hostname` | `assertion.hostname` |
| **6** | `attribute.job` | `assertion.job_name` |


3. **Attribute Condition (CEL Expression):**
Restrict token exchange only to recognized platforms:
```text
assertion.platform in ['k8s', 'vm', 'jenkins', 'standalone']

```



### 3. Grant Access to a Google Service Account (IAM Policy Binding)

Bind the Google Service Account (GSA) to the federated identity using your chosen attribute constraint.

#### Option A: Bind to an Immutable Kubernetes ServiceAccount UID (Recommended for K8s)

```bash
export GSA_EMAIL="workload-sa@${PROJECT_ID}.iam.gserviceaccount.com"
export K8S_SA_UID="<YOUR-K8S-SA-UID>"

gcloud iam service-accounts add-iam-policy-binding "${GSA_EMAIL}" \
    --project="${PROJECT_ID}" \
    --role="roles/iam.workloadIdentityUser" \
    --member="principalSet://[iam.googleapis.com/projects/$](https://iam.googleapis.com/projects/$){PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.k8s_sa_uid/${K8S_SA_UID}"

```

#### Option B: Bind to a Specific Subject Identity

```bash
# For Kubernetes:
--member="principal://[iam.googleapis.com/projects/$](https://iam.googleapis.com/projects/$){PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/subject/k8s:ns:default:sa:analytics-sa"

# For Jenkins:
--member="principal://[iam.googleapis.com/projects/$](https://iam.googleapis.com/projects/$){PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/subject/jenkins:job:production-deploy"

# For Bare-Metal / VM:
--member="principal://[iam.googleapis.com/projects/$](https://iam.googleapis.com/projects/$){PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/subject/vm:hostname:db-backup-host-01"

```

---

## Workload Client Setup (`universal-wif`)

The client CLI runs directly inside your workload (container, VM, or CI worker) to acquire tokens and generate Google ADC credentials.

### 1. Initialize Google ADC Configuration

Run the `init` command once in the workload runtime to produce the standard external credential configuration:

```bash
./bin/universal-wif init \
  --project-number "123456789012" \
  --pool-id "universal-pool" \
  --provider-id "universal-jwt-provider" \
  --service-account "workload-sa@my-project.iam.gserviceaccount.com" \
  --binary-path "/opt/bin/universal-wif" \
  --out "/etc/google/credentials.json"

```

### 2. Configure Runtime Environment Variables

Export the path to the generated configuration:

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/etc/google/credentials.json"
export CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE="/etc/google/credentials.json"
export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES="1"

# Endpoint and secret for reaching the authority server
export WIF_SERVER_URL="http://universal-wif-server:8080"
export AGENT_SHARED_SECRET="your-secure-shared-secret"

```

### 3. Verify Authentication

Call any GCP API using `gcloud` or standard Google Cloud SDK libraries. Credentials will be minted and exchanged on the fly:

```bash
gcloud projects list

```

---

## Security Best Practices

1. **Persistent RSA Keys:** Specify `WIF_PRIVATE_KEY_PATH` in production so the authority server retains the same signing key across restarts. Generating keys in-memory causes Google STS signature verification errors due to public key caching.
2. **Key ID (`kid`) Rotation:** When rotating RSA private keys, increment `WIF_KEY_ID` (e.g., `wif-key-v2`) to force Google STS to immediately fetch the new public key.
3. **Restrict Attributes:** Always bind GCP IAM policies to specific claims (`attribute.k8s_sa_uid`, `assertion.sub`, or `attribute.job`) rather than granting access to the entire pool.
4. **Clean Secret Management:** Ensure `.env`, `credentials.json`, and `.pem` private keys are added to `.gitignore`.

---

## License

Copyright (c) 2026. All rights reserved.

This software is made available for **personal, research, and non-commercial educational use only**. Commercial use, monetization, distribution as part of a commercial offering, or resale of this software without explicit written permission from the author is strictly prohibited.

---

## Complete KinD Local Setup & GCP Verification Guide

Follow this end-to-end guide to test keyless authentication from a local KinD cluster to Google Cloud using your workstation.

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/)
- [KinD](https://kind.sigs.k8s.io/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
- [MinIO Client (`mc`)](https://min.io/docs/minio/linux/reference/minio-mc.html)
- [gcloud CLI](https://cloud.google.com/sdk/docs/install) authenticated to your target GCP project

---

### 1. Create KinD Cluster & RBAC

```bash
# 1. Create a dedicated KinD cluster
kind create cluster --name wif-k8s-lab

# 2. Create the reviewer ServiceAccount and cluster role binding
kubectl create serviceaccount wif-token-reviewer -n default
kubectl create clusterrolebinding wif-token-reviewer-binding \
  --clusterrole=system:auth-delegator \
  --serviceaccount=default:wif-token-reviewer

# 3. Create long-lived secret for the reviewer (K8s 1.24+ compatibility)
kubectl apply -f - <<EOF ":9001" "HOST_BRIDGE_IP: "K8S_API_URL: "MINIO_ROOT_PASSWORD="password123"" "MINIO_ROOT_USER="admin"" # ### $HOST_BRIDGE_IP" $K8S_API_URL" & '{{range (Keep (Required (e.g., (host ) **Terminal *Copy --- --console-address --minify --name --restart --url -d -d) -e -f -ldflags="-s -w" -n -o -p -v ./universal-wif ./universal-wif-server .NetworkSettings.Networks}}{{.Gateway}}{{end}}' /data 1 1. 2 2. 2:** 3. 4. 9000:9000 9001:9001 API Binaries Bridge Build CGO_ENABLED="0" Cloud Cloudflare Cluster Create Docker EOF Endpoint Expose Extract GOARCH="amd64" GOOS="linux" Gateway Google HOST_BRIDGE_IP="$(docker" HTTPS IP JWKS K8S_API_URL="$(kubectl" K8S_SERVER_REVIEWER_TOKEN="$(kubectl" KinD MinIO Network Publish Reviewer STS STS) Secret Secrets Server ServiceAccount Start Token Tunnel URL Upload \ ``` ```bash `[https://your-tunnel-name.trycloudflare.com](https://your-tunnel-name.trycloudflare.com)`).* admin alias analytics-sa annotations: apiVersion: base64 binaries binary build client cloudflared cmd/universal-wif-server/main.go cmd/universal-wif/main.go config container create default docker echo endpoint export for from generated get go http://localhost:8080 http://localhost:9000 inside inspect jsonpath="{.data.token}" kind: kubectl kubernetes.io/service-account-token kubernetes.io/service-account.name: local localminio localminio/wif-binary mb mc metadata: minio minio-data:/data minted must name: namespace: over password123 pods) quay.io/minio/minio reach reachable run running):** secret server serviceaccount set the to tokens. tunnel type: unless-stopped v1 validate via view wif-k8s-lab-control-plane) wif-token-reviewer wif-token-reviewer-token workload your |>/dev/null || true
mc anonymous set download localminio/wif-binary
mc cp ./universal-wif localminio/wif-binary/v1.0.0/universal-wif

# 4. Verify anonymous download
curl -fSL -o /dev/null http://localhost:9000/wif-binary/v1.0.0/universal-wif && echo "MinIO serving OK"
```

---

### 5. Launch Authority Server

**Terminal 2:**
```bash
# Stop any existing server on 8080
sudo fuser -k 8080/tcp 2>/dev/null || true

# Set environment
export PORT=8080
export WIF_ISSUER_URL="[https://your-tunnel-name.trycloudflare.com](https://your-tunnel-name.trycloudflare.com)"
export AGENT_SHARED_SECRET="super-secret-passphrase"
export WIF_KEY_ID="wif-key-v2"
export KUBERNETES_API_URL=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
export K8S_SERVER_REVIEWER_TOKEN=$(kubectl get secret wif-token-reviewer-token -n default -o jsonpath='{.data.token}' | base64 -d)

# Start server
./universal-wif-server
```

---

### 6. Configure GCP Workload Identity Pool & IAM

Configure GCP to trust your Cloudflare issuer and bind your ServiceAccount UID:

```bash
export PROJECT_ID="YOUR_GCP_PROJECT_ID"
export PROJECT_NUMBER="YOUR_GCP_PROJECT_NUMBER"
export POOL_ID="universal-pool"
export PROVIDER_ID="universal-jwt-provider"
export GSA_EMAIL="wif-sa@${PROJECT_ID}.iam.gserviceaccount.com"
export WIF_ISSUER_URL="[https://your-tunnel-name.trycloudflare.com](https://your-tunnel-name.trycloudflare.com)"

# 1. Update/Create OIDC provider with UID mapping
gcloud iam workload-identity-pools providers update-oidc "$PROVIDER_ID" \
  --project="$PROJECT_ID" \
  --location="global" \
  --workload-identity-pool="$POOL_ID" \
  --issuer-uri="$WIF_ISSUER_URL" \
  --attribute-mapping="google.subject=assertion.sub,attribute.namespace=assertion.namespace,attribute.platform=assertion.platform,attribute.k8s_sa_uid=assertion.k8s_sa_uid" \
  --attribute-condition="assertion.platform in ['vm', 'k8s', 'jenkins', 'kubernetes']"

# 2. Extract analytics-sa UID from cluster
export SA_UID=$(kubectl get sa analytics-sa -n default -o jsonpath='{.metadata.uid}')

# 3. Bind Google Service Account impersonation to the SA UID
gcloud iam service-accounts add-iam-policy-binding "$GSA_EMAIL" \
  --project="$PROJECT_ID" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://[iam.googleapis.com/projects/$](https://iam.googleapis.com/projects/$){PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.k8s_sa_uid/${SA_UID}"
```

---

### 7. Deploy & Verify Test Pod

Update `k8/wif-config.yaml` with your GCP project details and your `HOST_BRIDGE_IP` (e.g. `172.18.0.1`):

```bash
kubectl apply -f k8/wif-config.yaml
kubectl apply -f k8/pod-test.yaml
```

Check the test results:
```bash
# Verify binary download and ADC configuration:
kubectl logs secured-k8s-workload -c setup-wif

# Verify token generation and GCP calls:
kubectl logs secured-k8s-workload -c workload
```

To inspect the generated token interactively:
```bash
kubectl exec -it secured-k8s-workload -c workload -- bash -c '
  TOKEN=$(/opt/bin/universal-wif get-token | grep -o "\"id_token\":\"[^\"]*" | cut -d"\"" -f4)
  echo "$TOKEN" | cut -d"." -f2 | base64 -d 2>/dev/null | python3 -m json.tool
'
```
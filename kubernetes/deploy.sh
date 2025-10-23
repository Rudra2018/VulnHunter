#!/bin/bash
# VulnHunter V17 Phase 2 Kubernetes Deployment Script

set -e

echo "🚀 VulnHunter V17 Phase 2 - Kubernetes Deployment"
echo "=================================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="vulnhunter"
KUBECTL="kubectl"

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ kubectl not found. Please install kubectl and configure cluster access.${NC}"
    exit 1
fi

# Check cluster connectivity
echo -e "${BLUE}🔍 Checking Kubernetes cluster connectivity...${NC}"
if ! kubectl cluster-info &> /dev/null; then
    echo -e "${RED}❌ Cannot connect to Kubernetes cluster. Please check your configuration.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Kubernetes cluster connection verified${NC}"

# Function to apply manifests with retry
apply_manifest() {
    local file=$1
    local description=$2

    echo -e "${BLUE}📦 Applying $description...${NC}"

    if kubectl apply -f "$file"; then
        echo -e "${GREEN}✅ $description applied successfully${NC}"
    else
        echo -e "${RED}❌ Failed to apply $description${NC}"
        exit 1
    fi
}

# Function to wait for deployment
wait_for_deployment() {
    local deployment=$1
    local namespace=$2

    echo -e "${YELLOW}⏳ Waiting for deployment $deployment to be ready...${NC}"

    if kubectl wait --for=condition=available --timeout=300s deployment/$deployment -n $namespace; then
        echo -e "${GREEN}✅ Deployment $deployment is ready${NC}"
    else
        echo -e "${RED}❌ Deployment $deployment failed to become ready${NC}"
        return 1
    fi
}

# Function to check if namespace exists
check_namespace() {
    if kubectl get namespace $NAMESPACE &> /dev/null; then
        echo -e "${YELLOW}⚠️  Namespace $NAMESPACE already exists${NC}"
        read -p "Do you want to continue and update existing resources? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${RED}❌ Deployment cancelled${NC}"
            exit 1
        fi
    fi
}

# Main deployment process
echo -e "${BLUE}🏗️  Starting VulnHunter V17 Phase 2 deployment...${NC}"

# Step 1: Check namespace
check_namespace

# Step 2: Apply namespace
apply_manifest "vulnhunter-namespace.yaml" "Namespace"

# Step 3: Apply RBAC (Service Account, Roles, etc.)
echo -e "${BLUE}📦 Creating RBAC resources...${NC}"
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vulnhunter-service-account
  namespace: $NAMESPACE
  labels:
    app: vulnhunter
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vulnhunter-cluster-role
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vulnhunter-cluster-role-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: vulnhunter-cluster-role
subjects:
- kind: ServiceAccount
  name: vulnhunter-service-account
  namespace: $NAMESPACE
EOF

# Step 4: Apply ConfigMaps and Secrets
apply_manifest "vulnhunter-configmap.yaml" "ConfigMap"
apply_manifest "vulnhunter-secrets.yaml" "Secrets"

# Step 5: Create Persistent Volumes
echo -e "${BLUE}📦 Creating Persistent Volume Claims...${NC}"
kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: vulnhunter-models-pvc
  namespace: $NAMESPACE
  labels:
    app: vulnhunter
    component: storage
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 50Gi
  storageClassName: efs-sc
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: vulnhunter-federated-pvc
  namespace: $NAMESPACE
  labels:
    app: vulnhunter
    component: federated-storage
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 20Gi
  storageClassName: efs-sc
EOF

# Step 6: Deploy Redis for caching
echo -e "${BLUE}📦 Deploying Redis cache...${NC}"
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnhunter-redis
  namespace: $NAMESPACE
  labels:
    app: vulnhunter
    component: redis
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnhunter
      component: redis
  template:
    metadata:
      labels:
        app: vulnhunter
        component: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: vulnhunter-secrets
              key: redis-password
        command:
        - redis-server
        - --requirepass
        - \$(REDIS_PASSWORD)
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 1Gi
        volumeMounts:
        - name: redis-data
          mountPath: /data
      volumes:
      - name: redis-data
        emptyDir: {}
EOF

# Step 7: Apply Services
apply_manifest "vulnhunter-services.yaml" "Services"

# Step 8: Apply main deployments
apply_manifest "vulnhunter-deployment.yaml" "Deployments"

# Step 9: Apply HPA and PDB
apply_manifest "vulnhunter-hpa.yaml" "Horizontal Pod Autoscaler and Pod Disruption Budget"

# Step 10: Apply Ingress
apply_manifest "vulnhunter-ingress.yaml" "Ingress and Network Policy"

# Step 11: Wait for deployments to be ready
echo -e "${BLUE}⏳ Waiting for deployments to be ready...${NC}"
wait_for_deployment "vulnhunter-api" "$NAMESPACE"
wait_for_deployment "vulnhunter-worker" "$NAMESPACE"
wait_for_deployment "vulnhunter-redis" "$NAMESPACE"

# Step 12: Display deployment status
echo -e "${BLUE}📊 Deployment Status:${NC}"
echo "===================="

kubectl get pods -n $NAMESPACE -o wide
echo

kubectl get services -n $NAMESPACE
echo

kubectl get ingress -n $NAMESPACE
echo

kubectl get hpa -n $NAMESPACE
echo

# Step 13: Get external endpoints
echo -e "${BLUE}🌐 External Endpoints:${NC}"
echo "====================="

# Get LoadBalancer IP/hostname
LB_IP=$(kubectl get service vulnhunter-api -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
LB_HOSTNAME=$(kubectl get service vulnhunter-api -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "")

if [[ -n "$LB_IP" ]]; then
    echo "🔗 API Endpoint: http://$LB_IP"
    echo "🔗 HTTPS Endpoint: https://$LB_IP"
elif [[ -n "$LB_HOSTNAME" ]]; then
    echo "🔗 API Endpoint: http://$LB_HOSTNAME"
    echo "🔗 HTTPS Endpoint: https://$LB_HOSTNAME"
else
    echo "⏳ LoadBalancer IP/hostname not yet assigned. Check again in a few minutes."
fi

echo "🔗 Health Check: http://api.vulnhunter.ai/health"
echo "🔗 Metrics: http://api.vulnhunter.ai/metrics"
echo "🔗 GitHub Webhook: https://webhook.vulnhunter.ai/webhook/github"
echo "🔗 GitLab Webhook: https://webhook.vulnhunter.ai/webhook/gitlab"

# Step 14: Display useful commands
echo
echo -e "${BLUE}📝 Useful Commands:${NC}"
echo "=================="
echo "# View logs:"
echo "kubectl logs -f deployment/vulnhunter-api -n $NAMESPACE"
echo "kubectl logs -f deployment/vulnhunter-worker -n $NAMESPACE"
echo
echo "# Scale deployments:"
echo "kubectl scale deployment vulnhunter-api --replicas=10 -n $NAMESPACE"
echo "kubectl scale deployment vulnhunter-worker --replicas=20 -n $NAMESPACE"
echo
echo "# Port forward for local testing:"
echo "kubectl port-forward service/vulnhunter-api-internal 8080:8080 -n $NAMESPACE"
echo
echo "# Delete deployment:"
echo "kubectl delete namespace $NAMESPACE"

echo
echo -e "${GREEN}🎉 VulnHunter V17 Phase 2 deployment completed successfully!${NC}"
echo -e "${GREEN}🚀 Your AI-powered vulnerability detection system is now running at scale!${NC}"

# Optional: Run smoke tests
read -p "Do you want to run smoke tests? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}🧪 Running smoke tests...${NC}"

    # Wait a bit for services to be fully ready
    sleep 10

    # Test health endpoint
    if kubectl exec -n $NAMESPACE deployment/vulnhunter-api -- curl -f localhost:8080/health; then
        echo -e "${GREEN}✅ Health check passed${NC}"
    else
        echo -e "${YELLOW}⚠️  Health check failed (services may still be starting)${NC}"
    fi

    # Test metrics endpoint
    if kubectl exec -n $NAMESPACE deployment/vulnhunter-api -- curl -f localhost:9090/metrics; then
        echo -e "${GREEN}✅ Metrics endpoint accessible${NC}"
    else
        echo -e "${YELLOW}⚠️  Metrics endpoint check failed${NC}"
    fi

    echo -e "${GREEN}🧪 Smoke tests completed${NC}"
fi

echo
echo -e "${BLUE}📚 Documentation: https://docs.vulnhunter.ai/v17/phase2${NC}"
echo -e "${BLUE}🐛 Issues: https://github.com/vulnhunter/vulnhunter/issues${NC}"
echo -e "${BLUE}💬 Support: support@vulnhunter.ai${NC}"
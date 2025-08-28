# Kong Guard AI - Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying Kong Guard AI in production environments with enterprise-grade security, monitoring, and operational excellence.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Infrastructure Deployment](#infrastructure-deployment)
3. [Application Deployment](#application-deployment)
4. [Monitoring Setup](#monitoring-setup)
5. [Security Configuration](#security-configuration)
6. [Operational Procedures](#operational-procedures)
7. [Troubleshooting](#troubleshooting)
8. [Maintenance](#maintenance)

## Prerequisites

### Required Tools

```bash
# Install required tools
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install terraform
```

### AWS Configuration

```bash
# Configure AWS CLI
aws configure
# Set region, access key, and secret key

# Verify access
aws sts get-caller-identity
aws eks list-clusters
```

### Environment Variables

```bash
# Required environment variables
export AWS_REGION="us-west-2"
export CLUSTER_NAME="kong-guard-ai-prod"
export ENVIRONMENT="production"
export PROJECT_OWNER="security-team"

# Security credentials
export AI_API_KEY="your-ai-api-key"
export SLACK_WEBHOOK_URL="your-slack-webhook"
export EMAIL_SMTP_PASSWORD="your-smtp-password"

# Terraform state
export TF_VAR_terraform_state_bucket="your-terraform-state-bucket"
export TF_VAR_terraform_lock_table="your-terraform-lock-table"
```

## Infrastructure Deployment

### Phase 1: Terraform Infrastructure

1. **Initialize Terraform Backend**

```bash
cd deployment/terraform

# Initialize Terraform
terraform init \
  -backend-config="bucket=${TF_VAR_terraform_state_bucket}" \
  -backend-config="key=kong-guard-ai/terraform.tfstate" \
  -backend-config="region=${AWS_REGION}" \
  -backend-config="dynamodb_table=${TF_VAR_terraform_lock_table}"
```

2. **Plan Infrastructure**

```bash
# Create terraform.tfvars file
cat > terraform.tfvars << EOF
aws_region = "${AWS_REGION}"
environment = "${ENVIRONMENT}"
cluster_name = "${CLUSTER_NAME}"
project_owner = "${PROJECT_OWNER}"

# Network configuration
vpc_cidr = "198.51.100.0/16"
public_subnet_cidrs = ["198.51.100.0/24", "198.51.100.0/24", "198.51.100.0/24"]
private_subnet_cidrs = ["198.51.100.0/24", "198.51.100.0/24", "198.51.100.0/24"]
database_subnet_cidrs = ["198.51.100.0/24", "198.51.100.0/24", "198.51.100.0/24"]

# EKS configuration
kubernetes_version = "1.28"
node_groups = {
  kong_guard_ai = {
    instance_types = ["m5.large", "m5.xlarge"]
    ami_type = "AL2_x86_64"
    capacity_type = "ON_DEMAND"
    disk_size = 50
    desired_size = 3
    max_size = 10
    min_size = 1
    bootstrap_arguments = "--container-runtime containerd"
  }
  monitoring = {
    instance_types = ["m5.large"]
    ami_type = "AL2_x86_64"
    capacity_type = "ON_DEMAND"
    disk_size = 100
    desired_size = 2
    max_size = 5
    min_size = 1
    bootstrap_arguments = "--container-runtime containerd"
  }
}

# Database configuration
enable_rds = true
rds_instance_class = "db.r5.large"
rds_engine_version = "15.4"
rds_allocated_storage = 100
rds_max_allocated_storage = 1000

# Security configuration
enable_cloudtrail = true
enable_guardduty = true
enable_vpc_flow_logs = true

# Monitoring configuration
enable_prometheus = true
enable_grafana = true
enable_alertmanager = true
cloudwatch_log_retention_days = 30

# Kong Guard AI configuration
kong_guard_ai_replicas = 3
kong_guard_ai_dry_run_mode = false
kong_guard_ai_threat_threshold = 7.0
kong_guard_ai_ai_gateway_enabled = true

# Secrets (will be passed via environment variables)
ai_api_key = "${AI_API_KEY}"
slack_webhook_url = "${SLACK_WEBHOOK_URL}"
email_smtp_password = "${EMAIL_SMTP_PASSWORD}"
EOF

# Plan deployment
terraform plan -var-file="terraform.tfvars"
```

3. **Deploy Infrastructure**

```bash
# Apply infrastructure changes
terraform apply -var-file="terraform.tfvars" -auto-approve

# Save outputs for later use
terraform output -json > ../terraform-outputs.json
```

### Phase 2: Post-Infrastructure Setup

1. **Configure kubectl**

```bash
# Update kubeconfig
aws eks update-kubeconfig --region ${AWS_REGION} --name ${CLUSTER_NAME}

# Verify cluster access
kubectl get nodes
kubectl get namespaces
```

2. **Install Essential Add-ons**

```bash
# Install AWS Load Balancer Controller
kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller/crds?ref=master"

helm repo add eks https://aws.github.io/eks-charts
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=${CLUSTER_NAME} \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller

# Install Cluster Autoscaler
kubectl apply -f https://raw.githubusercontent.com/kubernetes/autoscaler/master/cluster-autoscaler/cloudprovider/aws/examples/cluster-autoscaler-autodiscover.yaml
kubectl -n kube-system annotate deployment.apps/cluster-autoscaler cluster-autoscaler.kubernetes.io/safe-to-evict="false"
kubectl -n kube-system edit deployment.apps/cluster-autoscaler

# Install EBS CSI Driver
kubectl apply -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=release-1.24"
```

## Application Deployment

### Phase 1: Build and Push Docker Image

1. **Build Kong Guard AI Image**

```bash
# Navigate to project root
cd /path/to/kong-guard-ai

# Build production Docker image
docker build -f deployment/docker/Dockerfile -t kong-guard-ai:${VERSION} .

# Tag for ECR
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

docker tag kong-guard-ai:${VERSION} ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/kong-guard-ai:${VERSION}
docker push ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/kong-guard-ai:${VERSION}
```

### Phase 2: Kubernetes Deployment

1. **Using Kubernetes Manifests**

```bash
# Apply manifests in order
kubectl apply -f deployment/kubernetes/manifests/namespace.yaml
kubectl apply -f deployment/kubernetes/manifests/configmap.yaml
kubectl apply -f deployment/kubernetes/manifests/postgres.yaml
kubectl apply -f deployment/kubernetes/manifests/kong-migration.yaml

# Wait for migration to complete
kubectl wait --for=condition=complete job/kong-migration -n kong-guard-ai --timeout=300s

# Deploy Kong Gateway with Guard AI
kubectl apply -f deployment/kubernetes/manifests/kong-deployment.yaml

# Verify deployment
kubectl get pods -n kong-guard-ai
kubectl get svc -n kong-guard-ai
```

2. **Using Helm Charts (Recommended)**

```bash
# Add Helm repository
helm repo add kong-guard-ai ./deployment/helm/kong-guard-ai
helm repo update

# Create values file for production
cat > values-production.yaml << EOF
global:
  environment: production

kong:
  replicaCount: 3
  image:
    repository: ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/kong-guard-ai
    tag: "${VERSION}"
  
kongGuardAI:
  config:
    dry_run_mode: false
    threat_threshold: 7.0
    enable_auto_blocking: true
    enable_rate_limiting_response: true
    ai_gateway_enabled: true
    admin_api_enabled: true

secrets:
  aiApiKey: "${AI_API_KEY}"
  slackWebhookUrl: "${SLACK_WEBHOOK_URL}"
  emailSmtpPassword: "${EMAIL_SMTP_PASSWORD}"

postgresql:
  enabled: false
  external:
    host: "$(terraform output -raw rds_endpoint)"
    port: 5432
    database: "kong"
    username: "kong"
    password: "$(terraform output -raw rds_password)"

monitoring:
  enabled: true
  prometheus:
    enabled: true
  grafana:
    enabled: true
  alertmanager:
    enabled: true
EOF

# Install Kong Guard AI
helm install kong-guard-ai kong-guard-ai/kong-guard-ai \
  -n kong-guard-ai \
  --create-namespace \
  -f values-production.yaml

# Verify installation
helm status kong-guard-ai -n kong-guard-ai
kubectl get pods -n kong-guard-ai
```

### Phase 3: Configuration and Plugin Setup

1. **Configure Kong Guard AI Plugin**

```bash
# Get Kong Admin API endpoint
KONG_ADMIN_URL=$(kubectl get svc kong-admin -n kong-guard-ai -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'):8001

# Configure plugin globally
curl -X POST http://${KONG_ADMIN_URL}/plugins \
  --data "name=kong-guard-ai" \
  --data "config.dry_run_mode=false" \
  --data "config.threat_threshold=7.0" \
  --data "config.enable_auto_blocking=true" \
  --data "config.enable_notifications=true" \
  --data "config.ai_gateway_enabled=true"

# Verify plugin installation
curl -X GET http://${KONG_ADMIN_URL}/plugins
```

2. **Setup Services and Routes**

```bash
# Create example service
curl -X POST http://${KONG_ADMIN_URL}/services \
  --data "name=example-service" \
  --data "url=http://httpbin.org"

# Create route
curl -X POST http://${KONG_ADMIN_URL}/services/example-service/routes \
  --data "hosts[]=api.example.com" \
  --data "paths[]=/api"

# Enable Kong Guard AI on service
curl -X POST http://${KONG_ADMIN_URL}/services/example-service/plugins \
  --data "name=kong-guard-ai"
```

## Monitoring Setup

### Phase 1: Prometheus Configuration

1. **Deploy Prometheus Stack**

```bash
# Add Prometheus Helm repository
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install Prometheus stack
helm install prometheus prometheus-community/kube-prometheus-stack \
  -n monitoring \
  --create-namespace \
  -f deployment/monitoring/prometheus/values.yaml

# Verify installation
kubectl get pods -n monitoring
```

2. **Configure Kong Guard AI Metrics**

```bash
# Apply ServiceMonitor for Kong Guard AI
kubectl apply -f - << EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: kong-guard-ai
  namespace: monitoring
  labels:
    app: kong-guard-ai
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: kong-gateway
  endpoints:
  - port: status
    path: /metrics
    interval: 30s
  namespaceSelector:
    matchNames:
    - kong-guard-ai
EOF
```

### Phase 2: Grafana Dashboards

1. **Access Grafana**

```bash
# Get Grafana admin password
kubectl get secret prometheus-grafana -n monitoring -o jsonpath="{.data.admin-password}" | base64 --decode

# Port forward to access Grafana
kubectl port-forward svc/prometheus-grafana 3000:80 -n monitoring
```

2. **Import Dashboards**

```bash
# Import Kong Guard AI dashboards via API
GRAFANA_URL="http://admin:${GRAFANA_PASSWORD}@localhost:3000"

curl -X POST ${GRAFANA_URL}/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @deployment/monitoring/grafana/dashboards/kong-guard-ai-overview.json
```

### Phase 3: AlertManager Configuration

1. **Configure Alert Routes**

```bash
# Update AlertManager configuration
kubectl create secret generic alertmanager-main \
  --from-file=alertmanager.yml=deployment/monitoring/alertmanager/alertmanager.yml \
  -n monitoring \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart AlertManager to reload config
kubectl rollout restart statefulset/alertmanager-main -n monitoring
```

## Security Configuration

### Phase 1: Network Security

1. **Configure Network Policies**

```bash
# Apply network policies
kubectl apply -f - << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kong-guard-ai-network-policy
  namespace: kong-guard-ai
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
  - to:
    - namespaceSelector:
        matchLabels:
          name: monitoring
EOF
```

2. **Setup RBAC**

```bash
# Create service account with minimal permissions
kubectl apply -f - << EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kong-guard-ai
  namespace: kong-guard-ai
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: kong-guard-ai
  name: kong-guard-ai-role
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kong-guard-ai-binding
  namespace: kong-guard-ai
subjects:
- kind: ServiceAccount
  name: kong-guard-ai
  namespace: kong-guard-ai
roleRef:
  kind: Role
  name: kong-guard-ai-role
  apiGroup: rbac.authorization.k8s.io
EOF
```

### Phase 2: Secrets Management

1. **Configure External Secrets Operator**

```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets-system --create-namespace

# Configure AWS Secrets Manager integration
kubectl apply -f - << EOF
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: kong-guard-ai
spec:
  provider:
    aws:
      service: SecretsManager
      region: ${AWS_REGION}
      auth:
        jwt:
          serviceAccountRef:
            name: kong-guard-ai
EOF
```

### Phase 3: Security Scanning

1. **Setup Falco for Runtime Security**

```bash
# Install Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  -n falco-system \
  --create-namespace \
  --set falco.grpc.enabled=true \
  --set falco.grpcOutput.enabled=true
```

## Operational Procedures

### Health Checks

```bash
# Check cluster health
kubectl get nodes
kubectl get pods --all-namespaces

# Check Kong Guard AI health
kubectl get pods -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --tail=100

# Check database connectivity
kubectl exec -n kong-guard-ai deployment/kong-gateway -- kong health

# Check metrics endpoint
kubectl port-forward -n kong-guard-ai svc/kong-gateway 8100:8100
curl http://localhost:8100/metrics
```

### Backup Procedures

```bash
# Database backup
pg_dump -h $(terraform output -raw rds_endpoint) -U kong kong > kong-backup-$(date +%Y%m%d).sql

# Configuration backup
kubectl get configmap -n kong-guard-ai -o yaml > kong-config-backup-$(date +%Y%m%d).yaml
kubectl get secret -n kong-guard-ai -o yaml > kong-secrets-backup-$(date +%Y%m%d).yaml

# Upload to S3
aws s3 cp kong-backup-$(date +%Y%m%d).sql s3://$(terraform output -raw backup_bucket_id)/database/
aws s3 cp kong-config-backup-$(date +%Y%m%d).yaml s3://$(terraform output -raw backup_bucket_id)/config/
```

### Rolling Updates

```bash
# Update Kong Guard AI image
kubectl set image deployment/kong-gateway kong-gateway=${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/kong-guard-ai:${NEW_VERSION} -n kong-guard-ai

# Monitor rollout
kubectl rollout status deployment/kong-gateway -n kong-guard-ai

# Rollback if needed
kubectl rollout undo deployment/kong-gateway -n kong-guard-ai
```

## Troubleshooting

### Common Issues

1. **Plugin Not Loading**

```bash
# Check plugin installation
kubectl exec -n kong-guard-ai deployment/kong-gateway -- ls -la /usr/local/share/lua/5.1/kong/plugins/

# Check Kong logs
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway | grep -i "kong-guard-ai"

# Verify plugin configuration
curl -X GET http://${KONG_ADMIN_URL}/plugins
```

2. **High Memory Usage**

```bash
# Check memory metrics
kubectl top pods -n kong-guard-ai

# Check shared memory usage
kubectl exec -n kong-guard-ai deployment/kong-gateway -- cat /proc/meminfo

# Adjust memory limits
kubectl patch deployment kong-gateway -n kong-guard-ai -p='{"spec":{"template":{"spec":{"containers":[{"name":"kong-gateway","resources":{"limits":{"memory":"4Gi"}}}]}}}}'
```

3. **Database Connection Issues**

```bash
# Test database connectivity
kubectl exec -n kong-guard-ai deployment/kong-gateway -- pg_isready -h $(terraform output -raw rds_endpoint) -U kong

# Check database logs
aws rds describe-db-log-files --db-instance-identifier $(terraform output -raw rds_endpoint | cut -d'.' -f1)

# Verify security groups
aws ec2 describe-security-groups --group-ids $(terraform output -raw rds_security_group_id)
```

### Performance Optimization

1. **Tune Kong Configuration**

```bash
# Update Kong configuration
kubectl patch configmap kong-guard-ai-config -n kong-guard-ai --patch='
data:
  kong.conf: |
    nginx_worker_processes = auto
    nginx_worker_connections = 8192
    mem_cache_size = 256m
    upstream_keepalive_pool_size = 1024
'

# Restart Kong
kubectl rollout restart deployment/kong-gateway -n kong-guard-ai
```

2. **Optimize Database**

```bash
# Check database performance
aws rds describe-db-instances --db-instance-identifier $(terraform output -raw rds_endpoint | cut -d'.' -f1)

# Enable Performance Insights
aws rds modify-db-instance \
  --db-instance-identifier $(terraform output -raw rds_endpoint | cut -d'.' -f1) \
  --enable-performance-insights \
  --performance-insights-retention-period 7
```

## Maintenance

### Regular Tasks

1. **Weekly Health Checks**

```bash
#!/bin/bash
# Weekly health check script

echo "=== Kong Guard AI Health Check ==="
echo "Date: $(date)"

echo "1. Cluster Status:"
kubectl get nodes

echo "2. Pod Status:"
kubectl get pods -n kong-guard-ai

echo "3. Service Status:"
kubectl get svc -n kong-guard-ai

echo "4. Recent Threats:"
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=7d | grep -i "threat_detected" | wc -l

echo "5. Plugin Status:"
curl -s http://${KONG_ADMIN_URL}/plugins | jq '.data[] | select(.name=="kong-guard-ai") | .enabled'

echo "6. Database Status:"
kubectl exec -n kong-guard-ai deployment/kong-gateway -- kong health | grep database

echo "Health check completed."
```

2. **Monthly Security Review**

```bash
#!/bin/bash
# Monthly security review script

echo "=== Monthly Security Review ==="

echo "1. Security Alerts (last 30 days):"
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=720h | grep -i "threat_level.*[8-9]" | wc -l

echo "2. Failed Authentication Attempts:"
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=720h | grep -i "authentication.*failed" | wc -l

echo "3. Rate Limiting Triggers:"
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=720h | grep -i "rate_limit.*triggered" | wc -l

echo "4. AI Gateway Usage:"
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=720h | grep -i "ai_gateway.*call" | wc -l

echo "Security review completed."
```

### Version Updates

1. **Kong Gateway Updates**

```bash
# Check current version
kubectl get deployment kong-gateway -n kong-guard-ai -o jsonpath='{.spec.template.spec.containers[0].image}'

# Update to new version (test in staging first)
kubectl set image deployment/kong-gateway kong-gateway=kong:3.5.0 -n kong-guard-ai

# Monitor update
kubectl rollout status deployment/kong-gateway -n kong-guard-ai
```

2. **Plugin Updates**

```bash
# Build new plugin version
docker build -f deployment/docker/Dockerfile -t kong-guard-ai:${NEW_VERSION} .

# Update deployment
helm upgrade kong-guard-ai kong-guard-ai/kong-guard-ai \
  -n kong-guard-ai \
  -f values-production.yaml \
  --set kong.image.tag=${NEW_VERSION}
```

This production deployment guide provides comprehensive coverage of enterprise deployment, monitoring, security, and operational procedures for Kong Guard AI. Each section includes practical commands and scripts for real-world production environments.
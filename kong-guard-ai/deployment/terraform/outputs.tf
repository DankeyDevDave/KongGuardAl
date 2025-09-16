# Kong Guard AI Terraform Outputs

# Cluster Information
output "cluster_id" {
  description = "EKS cluster ID"
  value       = aws_eks_cluster.kong_guard_ai.id
}

output "cluster_arn" {
  description = "EKS cluster ARN"
  value       = aws_eks_cluster.kong_guard_ai.arn
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = aws_eks_cluster.kong_guard_ai.endpoint
  sensitive   = true
}

output "cluster_version" {
  description = "EKS cluster Kubernetes version"
  value       = aws_eks_cluster.kong_guard_ai.version
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = aws_eks_cluster.kong_guard_ai.vpc_config[0].cluster_security_group_id
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = aws_eks_cluster.kong_guard_ai.certificate_authority[0].data
  sensitive   = true
}

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster OIDC Issuer"
  value       = aws_eks_cluster.kong_guard_ai.identity[0].oidc[0].issuer
}

# Node Group Information
output "node_groups" {
  description = "EKS node groups"
  value = {
    for k, v in aws_eks_node_group.kong_guard_ai : k => {
      arn           = v.arn
      status        = v.status
      capacity_type = v.capacity_type
      instance_types = v.instance_types
      scaling_config = v.scaling_config
    }
  }
}

# Network Information
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.kong_guard_ai.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.kong_guard_ai.cidr_block
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "database_subnet_ids" {
  description = "IDs of the database subnets"
  value       = aws_subnet.database[*].id
}

output "nat_gateway_ids" {
  description = "IDs of the NAT Gateways"
  value       = aws_nat_gateway.kong_guard_ai[*].id
}

# Database Information
output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = var.enable_rds ? aws_db_instance.kong_guard_ai[0].endpoint : null
  sensitive   = true
}

output "rds_port" {
  description = "RDS instance port"
  value       = var.enable_rds ? aws_db_instance.kong_guard_ai[0].port : null
}

output "rds_database_name" {
  description = "RDS database name"
  value       = var.enable_rds ? aws_db_instance.kong_guard_ai[0].db_name : null
}

output "rds_username" {
  description = "RDS master username"
  value       = var.enable_rds ? aws_db_instance.kong_guard_ai[0].username : null
  sensitive   = true
}

output "rds_password" {
  description = "RDS master password"
  value       = var.enable_rds ? random_password.rds_password.result : null
  sensitive   = true
}

# Redis Information
output "redis_endpoint" {
  description = "ElastiCache Redis endpoint"
  value       = var.enable_redis ? aws_elasticache_replication_group.kong_guard_ai[0].primary_endpoint_address : null
  sensitive   = true
}

output "redis_port" {
  description = "ElastiCache Redis port"
  value       = var.enable_redis ? aws_elasticache_replication_group.kong_guard_ai[0].port : null
}

output "redis_auth_token" {
  description = "ElastiCache Redis auth token"
  value       = var.enable_redis ? random_password.redis_auth_token[0].result : null
  sensitive   = true
}

# Security Group Information
output "eks_cluster_security_group_id" {
  description = "EKS cluster security group ID"
  value       = aws_security_group.eks_cluster.id
}

output "eks_nodes_security_group_id" {
  description = "EKS nodes security group ID"
  value       = aws_security_group.eks_nodes.id
}

output "rds_security_group_id" {
  description = "RDS security group ID"
  value       = aws_security_group.rds.id
}

output "alb_security_group_id" {
  description = "ALB security group ID"
  value       = aws_security_group.alb.id
}

# Load Balancer Information
output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.kong_guard_ai.arn
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.kong_guard_ai.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.kong_guard_ai.zone_id
}

# IAM Role Information
output "eks_cluster_role_arn" {
  description = "EKS cluster IAM role ARN"
  value       = aws_iam_role.eks_cluster.arn
}

output "eks_node_group_role_arn" {
  description = "EKS node group IAM role ARN"
  value       = aws_iam_role.eks_node_group.arn
}

# KMS Key Information
output "eks_kms_key_id" {
  description = "EKS KMS key ID"
  value       = aws_kms_key.eks.key_id
}

output "eks_kms_key_arn" {
  description = "EKS KMS key ARN"
  value       = aws_kms_key.eks.arn
}

output "rds_kms_key_id" {
  description = "RDS KMS key ID"
  value       = aws_kms_key.rds.key_id
}

output "rds_kms_key_arn" {
  description = "RDS KMS key ARN"
  value       = aws_kms_key.rds.arn
}

# S3 Bucket Information
output "backup_bucket_id" {
  description = "S3 backup bucket ID"
  value       = aws_s3_bucket.kong_guard_ai_backups.id
}

output "backup_bucket_arn" {
  description = "S3 backup bucket ARN"
  value       = aws_s3_bucket.kong_guard_ai_backups.arn
}

# CloudWatch Information
output "cloudwatch_log_group_name" {
  description = "CloudWatch log group name for EKS cluster"
  value       = aws_cloudwatch_log_group.eks_cluster.name
}

output "cloudwatch_log_group_arn" {
  description = "CloudWatch log group ARN for EKS cluster"
  value       = aws_cloudwatch_log_group.eks_cluster.arn
}

# Configuration Information for Kubernetes Deployment
output "kubectl_config" {
  description = "kubectl config command to connect to the cluster"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.kong_guard_ai.name}"
}

output "helm_values_file" {
  description = "Helm values file content for Kong Guard AI deployment"
  value = {
    global = {
      imageRegistry = ""
      environment   = var.environment
    }
    kong = {
      replicaCount = var.kong_guard_ai_replicas
      image = {
        tag = var.kong_guard_ai_image_tag
      }
    }
    kongGuardAI = {
      config = {
        dry_run_mode         = var.kong_guard_ai_dry_run_mode
        threat_threshold     = var.kong_guard_ai_threat_threshold
        ai_gateway_enabled   = var.kong_guard_ai_ai_gateway_enabled
      }
    }
    postgresql = {
      enabled = false
      external = var.enable_rds ? {
        host     = var.enable_rds ? aws_db_instance.kong_guard_ai[0].endpoint : ""
        port     = var.enable_rds ? aws_db_instance.kong_guard_ai[0].port : 5432
        database = var.enable_rds ? aws_db_instance.kong_guard_ai[0].db_name : ""
        username = var.enable_rds ? aws_db_instance.kong_guard_ai[0].username : ""
        password = var.enable_rds ? random_password.rds_password.result : ""
      } : {}
    }
    redis = {
      enabled  = var.enable_redis
      external = var.enable_redis ? {
        host      = var.enable_redis ? aws_elasticache_replication_group.kong_guard_ai[0].primary_endpoint_address : ""
        port      = var.enable_redis ? aws_elasticache_replication_group.kong_guard_ai[0].port : 6379
        auth_token = var.enable_redis ? random_password.redis_auth_token[0].result : ""
      } : {}
    }
    monitoring = {
      enabled = var.enable_prometheus
      prometheus = {
        enabled = var.enable_prometheus
      }
      grafana = {
        enabled = var.enable_grafana
      }
      alertmanager = {
        enabled = var.enable_alertmanager
      }
    }
  }
  sensitive = true
}

# Deployment Commands
output "deployment_commands" {
  description = "Commands to deploy Kong Guard AI"
  value = {
    kubectl_config = "aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.kong_guard_ai.name}"
    namespace_create = "kubectl create namespace kong-guard-ai"
    helm_repo_add = "helm repo add kong-guard-ai ./deployment/helm/kong-guard-ai"
    helm_install = "helm install kong-guard-ai kong-guard-ai/kong-guard-ai -n kong-guard-ai -f values-${var.environment}.yaml"
    verify_deployment = "kubectl get pods -n kong-guard-ai"
  }
}

# Environment Information
output "environment_info" {
  description = "Environment deployment information"
  value = {
    environment           = var.environment
    cluster_name         = var.cluster_name
    kubernetes_version   = var.kubernetes_version
    region              = var.aws_region
    availability_zones  = data.aws_availability_zones.available.names
    deployment_timestamp = timestamp()
  }
}

# Cost Estimation Information
output "cost_estimation" {
  description = "Estimated monthly costs (approximate)"
  value = {
    eks_cluster = "~$73/month (cluster)"
    node_groups = "~$200-800/month (depending on instance types and count)"
    rds = var.enable_rds ? "~$150-500/month (depending on instance class)" : "$0 (disabled)"
    redis = var.enable_redis ? "~$100-300/month (depending on node type)" : "$0 (disabled)"
    nat_gateways = "~$135/month (3 NAT gateways)"
    load_balancer = "~$25/month (ALB)"
    data_transfer = "Variable based on usage"
    total_estimate = "~$580-1835/month (excluding data transfer)"
  }
}

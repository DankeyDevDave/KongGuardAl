# Kong Guard AI Terraform Variables

# General Configuration
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be one of: dev, staging, production."
  }
}

variable "project_owner" {
  description = "Project owner for resource tagging"
  type        = string
  default     = "kong-guard-ai-team"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "kong-guard-ai"
}

# Terraform State Configuration
variable "terraform_state_bucket" {
  description = "S3 bucket for Terraform state"
  type        = string
}

variable "terraform_lock_table" {
  description = "DynamoDB table for Terraform state locking"
  type        = string
}

# Network Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}

variable "database_subnet_cidrs" {
  description = "CIDR blocks for database subnets"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]
}

# EKS Configuration
variable "kubernetes_version" {
  description = "Kubernetes version for EKS cluster"
  type        = string
  default     = "1.28"
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "CIDR blocks that can access the EKS cluster endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "node_groups" {
  description = "EKS node group configurations"
  type = map(object({
    instance_types        = list(string)
    ami_type             = string
    capacity_type        = string
    disk_size           = number
    desired_size        = number
    max_size           = number
    min_size           = number
    bootstrap_arguments = string
  }))
  default = {
    kong_guard_ai = {
      instance_types        = ["m5.large", "m5.xlarge"]
      ami_type             = "AL2_x86_64"
      capacity_type        = "ON_DEMAND"
      disk_size           = 50
      desired_size        = 3
      max_size           = 10
      min_size           = 1
      bootstrap_arguments = "--container-runtime containerd"
    }
    monitoring = {
      instance_types        = ["m5.large"]
      ami_type             = "AL2_x86_64"
      capacity_type        = "ON_DEMAND"
      disk_size           = 100
      desired_size        = 2
      max_size           = 5
      min_size           = 1
      bootstrap_arguments = "--container-runtime containerd"
    }
  }
}

# RDS Configuration
variable "enable_rds" {
  description = "Enable RDS PostgreSQL instance"
  type        = bool
  default     = true
}

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r5.large"
}

variable "rds_engine_version" {
  description = "PostgreSQL engine version"
  type        = string
  default     = "15.4"
}

variable "rds_allocated_storage" {
  description = "Initial allocated storage in GB"
  type        = number
  default     = 100
}

variable "rds_max_allocated_storage" {
  description = "Maximum allocated storage in GB for autoscaling"
  type        = number
  default     = 1000
}

variable "rds_backup_retention_period" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

variable "rds_backup_window" {
  description = "Preferred backup window"
  type        = string
  default     = "03:00-04:00"
}

variable "rds_maintenance_window" {
  description = "Preferred maintenance window"
  type        = string
  default     = "sun:04:00-sun:05:00"
}

# Redis Configuration
variable "enable_redis" {
  description = "Enable ElastiCache Redis cluster"
  type        = bool
  default     = false
}

variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.r6g.large"
}

variable "redis_num_cache_clusters" {
  description = "Number of cache clusters"
  type        = number
  default     = 2
}

# Monitoring Configuration
variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "enable_prometheus" {
  description = "Enable Prometheus monitoring"
  type        = bool
  default     = true
}

variable "enable_grafana" {
  description = "Enable Grafana dashboards"
  type        = bool
  default     = true
}

variable "enable_alertmanager" {
  description = "Enable AlertManager"
  type        = bool
  default     = true
}

# Security Configuration
variable "enable_aws_load_balancer_controller" {
  description = "Enable AWS Load Balancer Controller"
  type        = bool
  default     = true
}

variable "enable_cluster_autoscaler" {
  description = "Enable Cluster Autoscaler"
  type        = bool
  default     = true
}

variable "enable_ebs_csi_driver" {
  description = "Enable EBS CSI Driver"
  type        = bool
  default     = true
}

variable "enable_efs_csi_driver" {
  description = "Enable EFS CSI Driver"
  type        = bool
  default     = false
}

# Kong Guard AI Configuration
variable "kong_guard_ai_image_tag" {
  description = "Kong Guard AI image tag"
  type        = string
  default     = "latest"
}

variable "kong_guard_ai_replicas" {
  description = "Number of Kong Guard AI replicas"
  type        = number
  default     = 3
}

variable "kong_guard_ai_dry_run_mode" {
  description = "Enable dry run mode for Kong Guard AI"
  type        = bool
  default     = true
}

variable "kong_guard_ai_threat_threshold" {
  description = "Threat detection threshold"
  type        = number
  default     = 8.0
}

variable "kong_guard_ai_ai_gateway_enabled" {
  description = "Enable AI Gateway integration"
  type        = bool
  default     = false
}

# Secrets Configuration
variable "ai_api_key" {
  description = "AI API key for threat analysis"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "email_smtp_password" {
  description = "SMTP password for email notifications"
  type        = string
  default     = ""
  sensitive   = true
}

# Backup Configuration
variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 30
}

variable "enable_automated_backups" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

# Cost Optimization
variable "enable_spot_instances" {
  description = "Enable spot instances for cost optimization"
  type        = bool
  default     = false
}

variable "spot_instance_pools" {
  description = "Number of spot instance pools"
  type        = number
  default     = 2
}

# Compliance and Auditing
variable "enable_cloudtrail" {
  description = "Enable CloudTrail for auditing"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config for compliance"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty for threat detection"
  type        = bool
  default     = true
}

# Network Security
variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "enable_network_policy" {
  description = "Enable Kubernetes Network Policies"
  type        = bool
  default     = true
}

# Disaster Recovery
variable "enable_cross_region_backup" {
  description = "Enable cross-region backup replication"
  type        = bool
  default     = false
}

variable "backup_region" {
  description = "Secondary region for backup replication"
  type        = string
  default     = "us-east-1"
}

# Performance Tuning
variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring for RDS"
  type        = bool
  default     = true
}

variable "enable_performance_insights" {
  description = "Enable Performance Insights for RDS"
  type        = bool
  default     = true
}

# Domain and SSL Configuration
variable "domain_name" {
  description = "Domain name for Kong Guard AI"
  type        = string
  default     = ""
}

variable "ssl_certificate_arn" {
  description = "ARN of SSL certificate in ACM"
  type        = string
  default     = ""
}

variable "enable_https_redirect" {
  description = "Enable HTTPS redirect"
  type        = bool
  default     = true
}
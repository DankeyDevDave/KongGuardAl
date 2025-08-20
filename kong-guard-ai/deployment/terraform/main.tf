# Kong Guard AI Terraform Infrastructure
# Production-ready infrastructure for AWS EKS deployment

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
  
  backend "s3" {
    bucket         = var.terraform_state_bucket
    key            = "kong-guard-ai/terraform.tfstate"
    region         = var.aws_region
    encrypt        = true
    dynamodb_table = var.terraform_lock_table
  }
}

# AWS Provider Configuration
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "kong-guard-ai"
      Environment = var.environment
      Terraform   = "true"
      Owner       = var.project_owner
    }
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# Random password for RDS
resource "random_password" "rds_password" {
  length  = 32
  special = true
}

# VPC Configuration
resource "aws_vpc" "kong_guard_ai" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name                                        = "${var.cluster_name}-vpc"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "kong_guard_ai" {
  vpc_id = aws_vpc.kong_guard_ai.id
  
  tags = {
    Name = "${var.cluster_name}-igw"
  }
}

# Public Subnets
resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)
  
  vpc_id                  = aws_vpc.kong_guard_ai.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  
  tags = {
    Name                                        = "${var.cluster_name}-public-${count.index + 1}"
    Type                                        = "public"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                   = "1"
  }
}

# Private Subnets
resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)
  
  vpc_id            = aws_vpc.kong_guard_ai.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name                                        = "${var.cluster_name}-private-${count.index + 1}"
    Type                                        = "private"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"          = "1"
  }
}

# Database Subnets
resource "aws_subnet" "database" {
  count = length(var.database_subnet_cidrs)
  
  vpc_id            = aws_vpc.kong_guard_ai.id
  cidr_block        = var.database_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name = "${var.cluster_name}-database-${count.index + 1}"
    Type = "database"
  }
}

# NAT Gateways
resource "aws_eip" "nat" {
  count = length(aws_subnet.public)
  
  domain = "vpc"
  
  tags = {
    Name = "${var.cluster_name}-nat-eip-${count.index + 1}"
  }
  
  depends_on = [aws_internet_gateway.kong_guard_ai]
}

resource "aws_nat_gateway" "kong_guard_ai" {
  count = length(aws_subnet.public)
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  tags = {
    Name = "${var.cluster_name}-nat-${count.index + 1}"
  }
  
  depends_on = [aws_internet_gateway.kong_guard_ai]
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.kong_guard_ai.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.kong_guard_ai.id
  }
  
  tags = {
    Name = "${var.cluster_name}-public-rt"
  }
}

resource "aws_route_table" "private" {
  count = length(aws_subnet.private)
  
  vpc_id = aws_vpc.kong_guard_ai.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.kong_guard_ai[count.index].id
  }
  
  tags = {
    Name = "${var.cluster_name}-private-rt-${count.index + 1}"
  }
}

resource "aws_route_table" "database" {
  vpc_id = aws_vpc.kong_guard_ai.id
  
  tags = {
    Name = "${var.cluster_name}-database-rt"
  }
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_route_table_association" "database" {
  count = length(aws_subnet.database)
  
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

# Security Groups
resource "aws_security_group" "eks_cluster" {
  name_prefix = "${var.cluster_name}-cluster-"
  vpc_id      = aws_vpc.kong_guard_ai.id
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.cluster_name}-cluster-sg"
  }
}

resource "aws_security_group" "eks_nodes" {
  name_prefix = "${var.cluster_name}-nodes-"
  vpc_id      = aws_vpc.kong_guard_ai.id
  
  ingress {
    from_port = 0
    to_port   = 65535
    protocol  = "tcp"
    self      = true
  }
  
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster.id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.cluster_name}-nodes-sg"
  }
}

resource "aws_security_group" "rds" {
  name_prefix = "${var.cluster_name}-rds-"
  vpc_id      = aws_vpc.kong_guard_ai.id
  
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
  }
  
  tags = {
    Name = "${var.cluster_name}-rds-sg"
  }
}

# EKS Cluster
resource "aws_eks_cluster" "kong_guard_ai" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.kubernetes_version
  
  vpc_config {
    subnet_ids              = concat(aws_subnet.private[*].id, aws_subnet.public[*].id)
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.cluster_endpoint_public_access_cidrs
    security_group_ids      = [aws_security_group.eks_cluster.id]
  }
  
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }
  
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  
  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.eks_cluster_AmazonEKSVPCResourceController,
    aws_cloudwatch_log_group.eks_cluster,
  ]
  
  tags = {
    Name = var.cluster_name
  }
}

# EKS Node Groups
resource "aws_eks_node_group" "kong_guard_ai" {
  for_each = var.node_groups
  
  cluster_name    = aws_eks_cluster.kong_guard_ai.name
  node_group_name = each.key
  node_role_arn   = aws_iam_role.eks_node_group.arn
  subnet_ids      = aws_subnet.private[*].id
  
  instance_types = each.value.instance_types
  ami_type       = each.value.ami_type
  capacity_type  = each.value.capacity_type
  disk_size      = each.value.disk_size
  
  scaling_config {
    desired_size = each.value.desired_size
    max_size     = each.value.max_size
    min_size     = each.value.min_size
  }
  
  update_config {
    max_unavailable_percentage = 25
  }
  
  launch_template {
    id      = aws_launch_template.eks_nodes[each.key].id
    version = aws_launch_template.eks_nodes[each.key].latest_version
  }
  
  depends_on = [
    aws_iam_role_policy_attachment.eks_node_group_AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.eks_node_group_AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.eks_node_group_AmazonEC2ContainerRegistryReadOnly,
  ]
  
  tags = {
    Name = "${var.cluster_name}-${each.key}"
  }
}

# Launch Templates for Node Groups
resource "aws_launch_template" "eks_nodes" {
  for_each = var.node_groups
  
  name_prefix = "${var.cluster_name}-${each.key}-"
  
  vpc_security_group_ids = [aws_security_group.eks_nodes.id]
  
  user_data = base64encode(templatefile("${path.module}/userdata.sh", {
    cluster_name        = var.cluster_name
    cluster_endpoint    = aws_eks_cluster.kong_guard_ai.endpoint
    cluster_ca          = aws_eks_cluster.kong_guard_ai.certificate_authority[0].data
    bootstrap_arguments = each.value.bootstrap_arguments
  }))
  
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.cluster_name}-${each.key}"
    }
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# RDS Subnet Group
resource "aws_db_subnet_group" "kong_guard_ai" {
  name       = "${var.cluster_name}-db-subnet-group"
  subnet_ids = aws_subnet.database[*].id
  
  tags = {
    Name = "${var.cluster_name}-db-subnet-group"
  }
}

# RDS Instance
resource "aws_db_instance" "kong_guard_ai" {
  count = var.enable_rds ? 1 : 0
  
  identifier             = "${var.cluster_name}-postgres"
  allocated_storage      = var.rds_allocated_storage
  max_allocated_storage  = var.rds_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.rds.arn
  
  engine         = "postgres"
  engine_version = var.rds_engine_version
  instance_class = var.rds_instance_class
  
  db_name  = "kong"
  username = "kong"
  password = random_password.rds_password.result
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.kong_guard_ai.name
  
  backup_retention_period   = var.rds_backup_retention_period
  backup_window            = var.rds_backup_window
  maintenance_window       = var.rds_maintenance_window
  auto_minor_version_upgrade = false
  
  performance_insights_enabled = true
  monitoring_interval         = 60
  monitoring_role_arn        = aws_iam_role.rds_enhanced_monitoring[0].arn
  
  deletion_protection = var.environment == "production"
  skip_final_snapshot = var.environment != "production"
  
  tags = {
    Name = "${var.cluster_name}-postgres"
  }
}

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "kong_guard_ai" {
  count = var.enable_redis ? 1 : 0
  
  name       = "${var.cluster_name}-cache-subnet"
  subnet_ids = aws_subnet.private[*].id
}

# ElastiCache Redis Cluster
resource "aws_elasticache_replication_group" "kong_guard_ai" {
  count = var.enable_redis ? 1 : 0
  
  replication_group_id         = "${var.cluster_name}-redis"
  description                  = "Redis cluster for Kong Guard AI"
  
  node_type            = var.redis_node_type
  num_cache_clusters   = var.redis_num_cache_clusters
  port                 = 6379
  parameter_group_name = "default.redis7"
  
  subnet_group_name  = aws_elasticache_subnet_group.kong_guard_ai[0].name
  security_group_ids = [aws_security_group.redis[0].id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                = random_password.redis_auth_token[0].result
  
  automatic_failover_enabled = true
  multi_az_enabled          = true
  
  snapshot_retention_limit = 3
  snapshot_window         = "03:00-05:00"
  maintenance_window      = "sun:05:00-sun:07:00"
  
  tags = {
    Name = "${var.cluster_name}-redis"
  }
}

# KMS Keys
resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Name = "${var.cluster_name}-eks"
  }
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${var.cluster_name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

resource "aws_kms_key" "rds" {
  description             = "RDS Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Name = "${var.cluster_name}-rds"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.cluster_name}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = aws_kms_key.eks.arn
  
  tags = {
    Name = "${var.cluster_name}-cluster-logs"
  }
}

# S3 Bucket for Backups and Logs
resource "aws_s3_bucket" "kong_guard_ai_backups" {
  bucket = "${var.cluster_name}-backups-${random_id.bucket_suffix.hex}"
  
  tags = {
    Name        = "${var.cluster_name}-backups"
    Purpose     = "backups"
    Environment = var.environment
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_versioning" "kong_guard_ai_backups" {
  bucket = aws_s3_bucket.kong_guard_ai_backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "kong_guard_ai_backups" {
  bucket = aws_s3_bucket.kong_guard_ai_backups.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "kong_guard_ai_backups" {
  bucket = aws_s3_bucket.kong_guard_ai_backups.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Application Load Balancer for Kong
resource "aws_lb" "kong_guard_ai" {
  name               = "${var.cluster_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
  
  enable_deletion_protection = var.environment == "production"
  
  access_logs {
    bucket  = aws_s3_bucket.kong_guard_ai_backups.id
    prefix  = "alb-logs"
    enabled = true
  }
  
  tags = {
    Name = "${var.cluster_name}-alb"
  }
}

# Security Group for ALB
resource "aws_security_group" "alb" {
  name_prefix = "${var.cluster_name}-alb-"
  vpc_id      = aws_vpc.kong_guard_ai.id
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.cluster_name}-alb-sg"
  }
}
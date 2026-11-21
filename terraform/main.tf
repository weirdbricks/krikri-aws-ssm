terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-2"
}

variable "name_prefix" {
  type    = string
  default = "krikri-ssm-live"
}

data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

resource "aws_security_group" "target" {
  name        = "${var.name_prefix}-target"
  description = "SSM-only target: no inbound rules"
  vpc_id      = data.aws_vpc.default.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-target" }
}

resource "aws_iam_role" "instance" {
  name = "${var.name_prefix}-instance"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "instance_kms" {
  name = "${var.name_prefix}-instance-kms"
  role = aws_iam_role.instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
      Resource = aws_kms_key.session.arn
    }]
  })
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name_prefix}-instance"
  role = aws_iam_role.instance.name
}

resource "aws_instance" "target" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = "t3a.micro"
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.target.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = { Name = "${var.name_prefix}-target" }
}

resource "aws_kms_key" "session" {
  description             = "${var.name_prefix} encrypted Session Manager sessions"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountRoot"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "TargetRole"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.instance.arn }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
      },
      {
        Sid       = "CallerUser"
        Effect    = "Allow"
        Principal = { AWS = data.aws_caller_identity.current.arn }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource  = "*"
      },
    ]
  })
}

resource "aws_ssm_document" "preferences" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "${var.name_prefix} preferences: require KMS encryption"
    sessionType   = "Standard_Stream"
    inputs = {
      kmsKeyId     = aws_kms_key.session.arn
      runAsEnabled = false
    }
  })
}

resource "aws_iam_role" "assumed" {
  name = "${var.name_prefix}-assumed"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = data.aws_caller_identity.current.arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "assumed_ssm" {
  role       = aws_iam_role.assumed.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"
}

resource "aws_iam_role_policy" "assumed_kms" {
  name = "${var.name_prefix}-assumed-kms"
  role = aws_iam_role.assumed.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      Resource = aws_kms_key.session.arn
    }]
  })
}

output "target_instance_id" {
  value = aws_instance.target.id
}

output "region" {
  value = var.region
}

output "assumed_role_arn" {
  value = aws_iam_role.assumed.arn
}

output "kms_key_arn" {
  value = aws_kms_key.session.arn
}

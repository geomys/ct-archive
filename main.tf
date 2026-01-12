terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-1"
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "tinyproxy" {
  name   = "spot-tinyproxy-sg"
  vpc_id = data.aws_vpc.default.id

  ingress {
    description = "SSH (optional)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "tinyproxy"
    from_port   = 8888
    to_port     = 8888
    protocol    = "tcp"
    cidr_blocks = ["54.153.102.150/32"] # IP of main EC2 instance
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_key_pair" "tinyproxy" {
  key_name   = "tinyproxy-key"
  public_key = file("~/.ssh/id_rsa.pub")
}

data "aws_ami" "ubuntu_arm" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-arm64-server-*"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}
resource "aws_launch_template" "tinyproxy" {
  name_prefix   = "spot-tinyproxy-"
  image_id      = data.aws_ami.ubuntu_arm.id
  instance_type = "t4g.nano"
  key_name      = aws_key_pair.tinyproxy.key_name

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.tinyproxy.id]
  }

  user_data = base64encode(<<EOF
#!/bin/bash
set -e

apt-get update
apt-get install -y tinyproxy

cat <<EOC >/etc/tinyproxy/tinyproxy.conf
User tinyproxy
Group tinyproxy
Port 8888
Timeout 600
LogLevel Info
Allow 0.0.0.0/0
DisableViaHeader Yes
ViaProxyName "tinyproxy"
MaxClients 100
EOC

systemctl enable tinyproxy
systemctl restart tinyproxy
EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "spot-tinyproxy"
    }
  }
}

resource "aws_autoscaling_group" "tinyproxy" {
  name             = "spot-tinyproxy-asg"
  min_size         = 32
  max_size         = 32
  desired_capacity = 32

  vpc_zone_identifier = data.aws_subnets.default.ids

  launch_template {
    id      = aws_launch_template.tinyproxy.id
    version = "$Latest"
  }

  termination_policies = ["OldestInstance"]
}

data "aws_instances" "tinyproxy" {
  filter {
    name   = "tag:Name"
    values = ["spot-tinyproxy"]
  }
}

output "proxy_ips" {
  description = "Public IPv4 addresses of tinyproxy instances"
  value       = data.aws_instances.tinyproxy.public_ips
}

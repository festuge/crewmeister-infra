terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "eu-central-1"
}

# VPC
resource "aws_vpc" "main_vpc" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "vpc"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = false

  tags = {
    Name                                       = "private_subnet"
    "kubernetes.io/role/internal-elb"          = "1"      # Tag for internal ELB
    "kubernetes.io/cluster/expert_cluster" = "shared" # Tag with your EKS cluster name
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "eu-central-1b"
  map_public_ip_on_launch = true

  tags = {
    Name                                       = "public_subnet"
    "kubernetes.io/role/elb"                   = "1"
    "kubernetes.io/role/internal-elb"          = "1"      # Tag for external ELB
    "kubernetes.io/cluster/expert_cluster" = "shared" # Tag with your EKS cluster name
  }
}


resource "aws_subnet" "public_subnet_2" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "eu-central-1c"
  map_public_ip_on_launch = true

  tags = {
    Name                                       = "public_subnet_2"
    "kubernetes.io/role/internal-elb"          = "1"
    "kubernetes.io/cluster/expert_cluster" = "shared"
  }
}


resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name = "gw"
  }
}

resource "aws_route_table" "rt_private" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateway.id
  }

  tags = {
    Name = "rt_private"
  }
}

resource "aws_route_table" "rt_public" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "rt_public"
  }
}


resource "aws_route_table" "rt_public_2" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "rt_public_2"
  }
}

resource "aws_route_table_association" "ass_private" {
  subnet_id      = aws_subnet.private_subnet.id
  route_table_id = aws_route_table.rt_private.id
}

resource "aws_route_table_association" "ass_public" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.rt_public.id
}

resource "aws_route_table_association" "ass_public_2" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.rt_public_2.id
}

resource "aws_nat_gateway" "nat_gateway" {
  allocation_id = aws_eip.lb.id
  subnet_id     = aws_subnet.public_subnet.id

  tags = {
    Name = "gwNAT"
  }

  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.gw]
}

resource "aws_eip" "lb" {
  domain = "vpc"
}

resource "aws_security_group" "master_sg" {
  name        = "master_sg"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.main_vpc.id

  tags = {
    Name = "master_sg"
  }
}


resource "aws_security_group" "worker_sg" {
  name        = "worker_sg"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.main_vpc.id

  tags = {
    Name = "worker_sg"
  }
}


resource "aws_iam_role" "eks_cluster_role" {
  name = "eksClusterRole"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    tag-key = "eks_cluster_role"
  }
}


resource "aws_iam_role" "eks_node_role" {
  name = "eksNodeRole"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    tag-key = "eks_node_role"
  }
}


resource "aws_iam_role_policy_attachment" "eks_cluster_role_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}


resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_role.name
}


resource "aws_iam_role_policy_attachment" "ec2_container_registry_read_only_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_role.name
}


resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_role.name
}


# resource "aws_iam_role_policy_attachment" "attach_alb_policy" {
#   policy_arn = aws_iam_policy.alb_ingress_controller_policy.arn
#   role       = aws_iam_role.alb_ingress_controller_role.name
# }

resource "aws_iam_role_policy_attachment" "amazon_eks_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster_role.name
}



#EKS

resource "aws_eks_cluster" "expert_cluster" {
  name     = "crewmeister-dev"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids = [aws_subnet.private_subnet.id, aws_subnet.public_subnet.id, aws_subnet.public_subnet_2.id]
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.amazon_eks_vpc_resource_controller,
    aws_iam_role_policy_attachment.eks_cluster_role_policy,
  ]
}

output "endpoint" {
  value = aws_eks_cluster.expert_cluster.endpoint
}

output "kubeconfig-certificate-authority-data" {
  value = aws_eks_cluster.expert_cluster.certificate_authority[0].data
}


resource "aws_eks_node_group" "expert_cluster_node_group" {
  cluster_name    = aws_eks_cluster.expert_cluster.name
  node_group_name = "expert_cluster_node_group"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = [aws_subnet.private_subnet.id]


  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.ec2_container_registry_read_only_policy,
  ]
}



#Ingress Configuration

# data "aws_eks_cluster_auth" "auth" {
#   name = aws_eks_cluster.expert_cluster.name
# }



# Create the IAM Policy for the ALB Ingress Controller


# resource "aws_iam_policy" "alb_ingress_controller_policy" {
#   name = "ALBIngressControllerPolicy"
#   policy = jsonencode({
#     "Version" : "2012-10-17",
#     "Statement" : [
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "iam:CreateServiceLinkedRole"
#         ],
#         "Resource" : "*",
#         "Condition" : {
#           "StringEquals" : {
#             "iam:AWSServiceName" : "elasticloadbalancing.amazonaws.com"
#           }
#         }
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "ec2:DescribeAccountAttributes",
#           "ec2:DescribeAddresses",
#           "ec2:DescribeAvailabilityZones",
#           "ec2:DescribeInternetGateways",
#           "ec2:DescribeVpcs",
#           "ec2:DescribeVpcPeeringConnections",
#           "ec2:DescribeSubnets",
#           "ec2:DescribeSecurityGroups",
#           "ec2:DescribeInstances",
#           "ec2:DescribeNetworkInterfaces",
#           "ec2:DescribeTags",
#           "ec2:GetCoipPoolUsage",
#           "ec2:DescribeCoipPools",
#           "elasticloadbalancing:DescribeLoadBalancers",
#           "elasticloadbalancing:DescribeLoadBalancerAttributes",
#           "elasticloadbalancing:DescribeListeners",
#           "elasticloadbalancing:DescribeListenerCertificates",
#           "elasticloadbalancing:DescribeSSLPolicies",
#           "elasticloadbalancing:DescribeRules",
#           "elasticloadbalancing:DescribeTargetGroups",
#           "elasticloadbalancing:DescribeTargetGroupAttributes",
#           "elasticloadbalancing:DescribeTargetHealth",
#           "elasticloadbalancing:DescribeTags",
#           "elasticloadbalancing:DescribeTrustStores",
#           "elasticloadbalancing:DescribeListenerAttributes"
#         ],
#         "Resource" : "*"
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "cognito-idp:DescribeUserPoolClient",
#           "acm:ListCertificates",
#           "acm:DescribeCertificate",
#           "iam:ListServerCertificates",
#           "iam:GetServerCertificate",
#           "waf-regional:GetWebACL",
#           "waf-regional:GetWebACLForResource",
#           "waf-regional:AssociateWebACL",
#           "waf-regional:DisassociateWebACL",
#           "wafv2:GetWebACL",
#           "wafv2:GetWebACLForResource",
#           "wafv2:AssociateWebACL",
#           "wafv2:DisassociateWebACL",
#           "shield:GetSubscriptionState",
#           "shield:DescribeProtection",
#           "shield:CreateProtection",
#           "shield:DeleteProtection"
#         ],
#         "Resource" : "*"
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "ec2:AuthorizeSecurityGroupIngress",
#           "ec2:RevokeSecurityGroupIngress"
#         ],
#         "Resource" : "*"
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "ec2:CreateSecurityGroup"
#         ],
#         "Resource" : "*"
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "ec2:CreateTags"
#         ],
#         "Resource" : "arn:aws:ec2:*:*:security-group/*",
#         "Condition" : {
#           "StringEquals" : {
#             "ec2:CreateAction" : "CreateSecurityGroup"
#           },
#           "Null" : {
#             "aws:RequestTag/elbv2.k8s.aws/cluster" : "false"
#           }
#         }
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "ec2:CreateTags",
#           "ec2:DeleteTags"
#         ],
#         "Resource" : "arn:aws:ec2:*:*:security-group/*",
#         "Condition" : {
#           "Null" : {
#             "aws:RequestTag/elbv2.k8s.aws/cluster" : "true",
#             "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
#           }
#         }
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "ec2:AuthorizeSecurityGroupIngress",
#           "ec2:RevokeSecurityGroupIngress",
#           "ec2:DeleteSecurityGroup"
#         ],
#         "Resource" : "*",
#         "Condition" : {
#           "Null" : {
#             "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
#           }
#         }
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "elasticloadbalancing:CreateLoadBalancer",
#           "elasticloadbalancing:CreateTargetGroup"
#         ],
#         "Resource" : "*",
#         "Condition" : {
#           "Null" : {
#             "aws:RequestTag/elbv2.k8s.aws/cluster" : "false"
#           }
#         }
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "elasticloadbalancing:CreateListener",
#           "elasticloadbalancing:DeleteListener",
#           "elasticloadbalancing:CreateRule",
#           "elasticloadbalancing:DeleteRule"
#         ],
#         "Resource" : "*"
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "elasticloadbalancing:AddTags",
#           "elasticloadbalancing:RemoveTags"
#         ],
#         "Resource" : [
#           "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
#           "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
#           "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
#         ],
#         "Condition" : {
#           "Null" : {
#             "aws:RequestTag/elbv2.k8s.aws/cluster" : "true",
#             "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
#           }
#         }
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "elasticloadbalancing:AddTags",
#           "elasticloadbalancing:RemoveTags"
#         ],
#         "Resource" : [
#           "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
#           "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
#           "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
#           "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
#         ]
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "elasticloadbalancing:ModifyLoadBalancerAttributes",
#           "elasticloadbalancing:SetIpAddressType",
#           "elasticloadbalancing:SetSecurityGroups",
#           "elasticloadbalancing:SetSubnets",
#           "elasticloadbalancing:DeleteLoadBalancer",
#           "elasticloadbalancing:ModifyTargetGroup",
#           "elasticloadbalancing:ModifyTargetGroupAttributes",
#           "elasticloadbalancing:DeleteTargetGroup",
#           "elasticloadbalancing:ModifyListenerAttributes"
#         ],
#         "Resource" : "*",
#         "Condition" : {
#           "Null" : {
#             "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
#           }
#         }
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "elasticloadbalancing:AddTags"
#         ],
#         "Resource" : [
#           "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
#           "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
#           "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
#         ],
#         "Condition" : {
#           "StringEquals" : {
#             "elasticloadbalancing:CreateAction" : [
#               "CreateTargetGroup",
#               "CreateLoadBalancer"
#             ]
#           },
#           "Null" : {
#             "aws:RequestTag/elbv2.k8s.aws/cluster" : "false"
#           }
#         }
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "elasticloadbalancing:RegisterTargets",
#           "elasticloadbalancing:DeregisterTargets"
#         ],
#         "Resource" : "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
#       },
#       {
#         "Effect" : "Allow",
#         "Action" : [
#           "elasticloadbalancing:SetWebAcl",
#           "elasticloadbalancing:ModifyListener",
#           "elasticloadbalancing:AddListenerCertificates",
#           "elasticloadbalancing:RemoveListenerCertificates",
#           "elasticloadbalancing:ModifyRule"
#         ],
#         "Resource" : "*"
#       }
#     ]
#   })
# }

# resource "aws_iam_role" "alb_ingress_controller_role" {
#   name = "ALBIngressControllerRole"

#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Effect = "Allow"
#         Principal = {
#           Service = "eks.amazonaws.com"
#         }
#         Action = "sts:AssumeRole"
#       }
#     ]
#   })
# }

# resource "aws_iam_role_policy_attachment" "attach_alb_policy" {
#   policy_arn = aws_iam_policy.alb_ingress_controller_policy.arn
#   role       = aws_iam_role.alb_ingress_controller_role.name
# }


# provider "kubernetes" {
#   host                   = aws_eks_cluster.expert_cluster.endpoint
#   cluster_ca_certificate = base64decode(aws_eks_cluster.expert_cluster.certificate_authority[0].data)
#   token                  = data.aws_eks_cluster_auth.auth.token
# }

# resource "kubernetes_service_account" "alb_ingress_sa" {
#   metadata {
#     name      = "nginx-sa"
#     namespace = "kube-system"
#     annotations = {
#       "eks.amazonaws.com/role-arn" = aws_iam_role.alb_ingress_controller_role.arn
#     }
#   }
# }


# provider "helm" {
#   kubernetes {
#     host                   = aws_eks_cluster.expert_cluster.endpoint
#     cluster_ca_certificate = base64decode(aws_eks_cluster.expert_cluster.certificate_authority[0].data)
#     token                  = data.aws_eks_cluster_auth.auth.token
#   }
# }

# resource "helm_release" "alb_ingress_controller" {
#   name       = "aws-load-balancer-controller"
#   namespace  = "kube-system"
#   repository = "https://aws.github.io/eks-charts"
#   chart      = "aws-load-balancer-controller"

#   set {
#     name  = "clusterName"
#     value = "expert_cluster"
#   }

#   set {
#     name  = "serviceAccount.create"
#     value = "false"
#   }

#   set {
#     name  = "serviceAccount.name"
#     value = "nginx-sa"
#   }

#   set {
#     name  = "region"
#     value = "eu-central-1"
#   }

#   set {
#     name  = "vpcId"
#     value = aws_vpc.main_vpc.id
#   }
# }
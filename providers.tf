terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.23.1"
    }
    temporary = {
      source  = "kota65535/temporary"
      version = "0.2.0"
    }
    awscc = {
      source  = "hashicorp/awscc"
      version = "0.74.0"
    }
  }
  required_version = "~> 1.5.0"
}

provider "aws" {
  region = "ap-northeast-1"
  default_tags {
    tags = {
      Project = "dmarc-monitoring"
    }
  }
}

provider "temporary" {
  base = "${path.root}/.terraform/tmp"
}

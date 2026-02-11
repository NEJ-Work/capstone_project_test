terraform {
  required_version = ">= 1.6.0"

  backend "s3" {
    bucket  = "capstone-projectadnwpj"
    key     = "state/platform/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13.0"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.0"
    }

    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

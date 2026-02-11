########################
# AWS / EKS
########################

variable "region" {
  description = "AWS region to deploy EKS into"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "capstone-cluster"
}

########################
# Argo CD
########################

variable "argocd_namespace" {
  description = "Namespace where Argo CD will be installed"
  type        = string
  default     = "argocd"
}

variable "argocd_chart_version" {
  description = "Helm chart version for Argo CD"
  type        = string
  default     = "5.51.6"
}

########################
# GitOps Repository
########################

variable "gitops_repo_url" {
  description = "Git repository containing Argo CD applications"
  type        = string
}

variable "gitops_repo_branch" {
  description = "Git branch Argo CD should track"
  type        = string
  default     = "main"
}

variable "gitops_apps_path" {
  description = "Path inside the repo where Argo CD applications live"
  type        = string
  default     = "apps"
}

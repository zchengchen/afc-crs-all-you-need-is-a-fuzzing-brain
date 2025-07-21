variable "resource_group_location" {
  type        = string
  default     = "eastus"
  description = "Location of the resource group."
}

variable "resource_group_name_prefix" {
  type        = string
  default     = "example"
  description = "Prefix of the resource group name that's combined with a random ID so name is unique in your Azure subscription."
}

variable "sys_node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 1
}

variable "usr_node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 1
}

variable "worker_node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 96
}

variable "analysis_node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 1
}

variable "username" {
  type        = string
  description = "The admin username for the new cluster."
  default     = "azureadmin"
}

variable "ARM_SUBSCRIPTION_ID" {
  type        = string
  description = "Azure subscription ID"
}

variable "ARM_TENANT_ID" {
  type        = string
  description = "Azure tenant ID"
}

variable "ARM_CLIENT_ID" {
  type        = string
  description = "Azure client ID"
}

variable "ARM_CLIENT_SECRET" {
  type        = string
  sensitive   = true
  description = "Azure client secret"
}

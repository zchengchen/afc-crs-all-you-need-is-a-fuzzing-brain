#resource for random prefixes, helps with unique names and identifiers
resource "random_pet" "ssh_key_name" {
  prefix    = "ssh"
  separator = ""
}
#azapi_resource_action resource is used to perform specific actions on an Azure resource, such as starting or stopping a virtual machine. Here we're generating ssh keys
resource "azapi_resource_action" "ssh_public_key_gen" {
  type        = "Microsoft.Compute/sshPublicKeys@2022-11-01"
  resource_id = azapi_resource.ssh_public_key.id
  action      = "generateKeyPair"
  method      = "POST"

  response_export_values = ["publicKey", "privateKey"]
}

resource "azapi_resource" "ssh_public_key" {
  type      = "Microsoft.Compute/sshPublicKeys@2022-11-01"
  name      = random_pet.ssh_key_name.id
  location  = azurerm_resource_group.rg.location
  parent_id = azurerm_resource_group.rg.id
}

output "key_data" {
  value = azapi_resource_action.ssh_public_key_gen.output.publicKey
}


# Generate random resource group name
resource "random_pet" "rg_name" {
  prefix = var.resource_group_name_prefix
}

resource "azurerm_resource_group" "rg" {
  #ts:skip=AC_AZURE_0389 Locks not required
  location = var.resource_group_location
  name     = random_pet.rg_name.id
}

# Optional: Adds resource lock to prevent deletion of the RG. Requires additional configuration
#resource "azurerm_management_lock" "resource-group-level" {
#  name       = "resource-group-cannotdelete-lock"
#  scope      = azurerm_resource_group.rg.id
#  lock_level = "CanNotDelete"
#  notes      = "This Resource Group is set to CanNotDelete to prevent accidental deletion."
#}


resource "random_pet" "azurerm_kubernetes_cluster_name" {
  prefix = "cluster"
}

resource "random_pet" "azurerm_kubernetes_cluster_dns_prefix" {
  prefix = "dns"
}

resource "azurerm_kubernetes_cluster" "primary" {
  location            = azurerm_resource_group.rg.location
  name                = random_pet.azurerm_kubernetes_cluster_name.id
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = random_pet.azurerm_kubernetes_cluster_dns_prefix.id
  sku_tier            = "Standard"

  identity {
    type = "SystemAssigned"
  }

  default_node_pool {
    name                         = "sys"
    vm_size                      = "Standard_F32as_v6"
    max_pods                     = 100
    temporary_name_for_rotation  = "tempnodepool"
    only_critical_addons_enabled = true
    node_count                   = var.sys_node_count
    upgrade_settings {
      max_surge = "10%"
    }
  }

  linux_profile {
    admin_username = var.username

    ssh_key {
      key_data = azapi_resource_action.ssh_public_key_gen.output.publicKey
    }
  }
  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
  }
  oms_agent {
    log_analytics_workspace_id      = azurerm_log_analytics_workspace.aks_logs.id
    msi_auth_for_monitoring_enabled = true
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "user" {
  name                  = "usr"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = "Standard_F64as_v6"
  max_pods              = 100
  node_count            = var.usr_node_count
  temporary_name_for_rotation = "usrtemp"
  upgrade_settings {
    max_surge = "10%"
  }
}

#Monitoring Log Anayltics
resource "azurerm_log_analytics_workspace" "aks_logs" {
  name                = "${random_pet.rg_name.id}-logs"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# Add the control node pool for task and submission nodes
resource "azurerm_kubernetes_cluster_node_pool" "control" {
  name                  = "control"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = "Standard_F64as_v6"
  node_count            = 2  # One for task node, one for submission node
  temporary_name_for_rotation = "controltemp"

  # Add taints to ensure only control workloads run on these nodes
  node_taints = ["workloadType=control:NoSchedule"]
  
  # Add labels for node selection
  node_labels = {
    "workloadType" = "control"
  }
  
  # Configure max pods per node
  max_pods = 100
  
  # Configure upgrade settings
  upgrade_settings {
    max_surge = "10%"
  }
}

# Standard_M192is_v2 Standard_D5_v2 Standard_D96ads_v5 Standard_D96als_v6 Standard_E96ads_v6 Standard_D32ads_v6 Standard_F32as_v6 Standard_F48as_v6 Standard_F64as_v6 Standard_F64als_v6 Standard_D48ads_v6
# Add the user node pool as a separate resource outside the azurerm_kubernetes_cluster resource
resource "azurerm_kubernetes_cluster_node_pool" "worker" {
  name                  = "worker"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = "Standard_F48as_v6"
  node_count            = var.worker_node_count
  
  # Add temporary_name_for_rotation to enable zero-downtime updates
  temporary_name_for_rotation = "workertemp"

  # Optional: Add taints to ensure only user workloads run on these nodes
  node_taints = ["workloadType=worker:NoSchedule"]
  
  # Optional: Add labels for node selection
  node_labels = {
    "workloadType" = "worker"
  }
  
  # Optional: Configure max pods per node if needed
  max_pods = 100
  
  # Optional: Configure upgrade settings
  upgrade_settings {
    max_surge = "10%"
  }

  # zones = ["1", "2", "3"]
}

resource "azurerm_kubernetes_cluster_node_pool" "analysis" {
  name                  = "analysis"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = "Standard_M192is_v2"
  node_count            = var.analysis_node_count
  
  # Add temporary_name_for_rotation to enable zero-downtime updates
  temporary_name_for_rotation = "analysistemp"

  # Optional: Add taints to ensure only analysis workloads run on these nodes
  node_taints = ["workloadType=analysis:NoSchedule"]
  
  # Optional: Add labels for node selection
  node_labels = {
    "workloadType" = "analysis"
  }
  
  # Optional: Configure max pods per node if needed
  max_pods = 100
  
}

locals {
  env_vars = { for tuple in regexall("(.*?)=(.*)", file("${path.module}/.env")) : tuple[0] => tuple[1] }
}

# Render the Kubernetes deployment template with the node count variable
resource "local_file" "k8s_deployment" {
  content = templatefile("${path.module}/k8s/base/crs-webservice/deployment.template", {
    NODE_COUNT = var.worker_node_count
    ANALYSIS_NODE_COUNT = var.analysis_node_count
    CRS_KEY_ID = local.env_vars["CRS_KEY_ID"]
    CRS_KEY_TOKEN = local.env_vars["CRS_KEY_TOKEN"]
    COMPETITION_API_KEY_ID = local.env_vars["COMPETITION_API_KEY_ID"]
    COMPETITION_API_KEY_TOKEN = local.env_vars["COMPETITION_API_KEY_TOKEN"]
  })
  filename = "${path.module}/k8s/base/crs-webservice/deployment.yaml"
}
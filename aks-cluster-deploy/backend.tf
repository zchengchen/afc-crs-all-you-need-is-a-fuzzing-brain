terraform {
  backend "azurerm" {
    resource_group_name  = "aixcc-tfstate-rg"
    storage_account_name = "jefftfstd20250626"
    container_name       = "tfstate"
    key                  = "terraform.tfstate"
  }
}
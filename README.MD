# Azure Container Registry (ACR) Image Importer (PowerShell)

This PowerShell script automates the process of importing a Docker image into an Azure Container Registry (ACR), with an added step of scanning the image for vulnerabilities using Trivy before import.

## Requirements

- PowerShell 5.1 or higher.
- Azure PowerShell Module.
- An Azure account with an active subscription.
- Necessary permissions to manage resources in Azure Container Registry (**AcrPush** Role).
- Internet access for downloading the Trivy container scanner.


## Setting Up Azure PowerShell

If you haven't already installed the Azure PowerShell module, run the following command in your PowerShell prompt:

```powershell
Install-Module -Name Az -AllowClobber -Scope CurrentUser
```

## Script Parameters
The script accepts the following parameters:
 - SubscriptionId: (Required) Your Azure Subscription ID.
 - ResourceGroupName: (Required) The name of the Azure resource group.
 - AcrName: (Required) The name of the Azure Container Registry.
 - SourceImageUri: (Optional) The URI of the Docker image to import. Default is 'docker.io/library/ubuntu:latest'.
 - TargetTags: (Optional) The tags to be applied to the imported image in ACR. Default is 'ubuntu:latest'. Multiple tags can be specified as a comma-separated list.

# Script Features
- **Image Scanning**: Before importing, the script scans the image for vulnerabilities using Trivy (first it downloads and extracts Trivy), ensuring only secure images are imported.
- **Flexibility**: Supports custom Docker image URIs and multiple target tags.
- **Azure Integration**: Connects and interacts with Azure services.

## Usage
Run the script with the required parameters. For example:
```powershell
.\Import-AcrImage.ps1 -SubscriptionId "your_subscription_id" -ResourceGroupName "your_resource_group" -AcrName "your_acr_name"
```
or
```powershell
.\Import-AcrImage.ps1 -SubscriptionId "id" -ResourceGroupName "group" -AcrName "name" -SourceImageUri "docker.io/library/nginx:latest" -TargetTags "nginx:latest", "latest"
```

## Example Use Case
If Trivy detects high or critical vulnerabilities in the specified image, the script will terminate and display an error message, preventing the image from being imported to ACR.

## Contributing
N/A

## License
N/A
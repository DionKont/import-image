param (
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [string]$AcrName,

    [string]$SourceImageUri = "docker.io/library/ubuntu:latest",
    [string[]]$TargetTags = @("ubuntu:latest")
)

# In the function below we are using Trivy as an example for scanning IaC; other tools like Snyk can be used instead
function Scan-ContainerImage {
    param (
        [string]$ImageUri
    )

    # Trivy latest release download
    $trivyUrl = "https://github.com/aquasecurity/trivy/releases/download/v0.47.0/trivy_0.47.0_windows-64bit.zip"
    $trivyZipPath = "trivy.zip"
    Invoke-WebRequest -Uri $trivyUrl -OutFile $trivyZipPath

    # Extract Trivy
    Expand-Archive -Path $trivyZipPath -DestinationPath ".\trivy"
    $trivyExePath = ".\trivy\trivy.exe"

    # Run Trivy scan
    Write-Host "Scanning container image for vulnerabilities: $ImageUri"
    & $trivyExePath image --severity HIGH,CRITICAL --no-progress $ImageUri
    if ($LASTEXITCODE -ne 0) {
        throw "High or critical vulnerabilities found in the image."
    }
}

function Import-AcrImage {
    param (
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$AcrName,
        [string]$SourceImageUri,
        [string[]]$TargetTags
    )
    try {
        # Scan the container image
        Scan-ContainerImage -ImageUri $SourceImageUri

        # Authenticate and set the subscription
        $null = Connect-AzAccount -ErrorAction Stop
        $null = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop

        # Import the image
        $importParams = @{
            ResourceGroupName = $ResourceGroupName
            RegistryName      = $AcrName
            SourceImage       = $SourceImageUri
            TargetTag         = $TargetTags
        }
        $null = Import-AzContainerRegistryImage @importParams -ErrorAction Stop
        Write-Host "Image imported successfully: $SourceImageUri with tags: $($TargetTags -join ', ')"
    }
    catch {
        Write-Error "Failed to import image: $_"
    }
}

Import-AcrImage -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -AcrName $AcrName -SourceImageUri $SourceImageUri -TargetTags $TargetTags

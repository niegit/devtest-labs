param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$true)]
    [string]$LabName,
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$true)]
    [securestring]$AdminPassword,
    
    [string]$AdminUsername = "labadmin",
    [string]$ServerVmName = "DC01",
    [string]$ClientVmName = "CLIENT01",
    [string]$VmSize = "Standard_D2s_v3",
    [string]$TemplateUri = "https://raw.githubusercontent.com/your-repo/ad-lab-template/main/azuredeploy.json",
    [string]$Location = "East US"
)

# Import required modules
Import-Module Az.Accounts -Force
Import-Module Az.Resources -Force
Import-Module Az.DevTestLabs -Force

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "Starting Active Directory Lab Environment Deployment..." -ForegroundColor Green
Write-Host "Lab Name: $LabName" -ForegroundColor Yellow
Write-Host "Domain Name: $DomainName" -ForegroundColor Yellow
Write-Host "Location: $Location" -ForegroundColor Yellow

try {
    # Connect to Azure
    Write-Host "Connecting to Azure..." -ForegroundColor Cyan
    $context = Get-AzContext
    if (-not $context -or $context.Subscription.Id -ne $SubscriptionId) {
        Connect-AzAccount -SubscriptionId $SubscriptionId
    }

    # Set subscription context
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    Write-Host "Connected to subscription: $SubscriptionId" -ForegroundColor Green

    # Check if resource group exists
    Write-Host "Checking resource group..." -ForegroundColor Cyan
    $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $resourceGroup) {
        Write-Host "Creating resource group: $ResourceGroupName" -ForegroundColor Yellow
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
        Write-Host "Resource group created successfully" -ForegroundColor Green
    }
    else {
        Write-Host "Resource group already exists: $ResourceGroupName" -ForegroundColor Green
    }

    # Check if DevTest Lab exists
    Write-Host "Checking DevTest Lab..." -ForegroundColor Cyan
    $lab = Get-AzDevTestLab -ResourceGroupName $ResourceGroupName -Name $LabName -ErrorAction SilentlyContinue
    if (-not $lab) {
        Write-Host "Creating DevTest Lab: $LabName" -ForegroundColor Yellow
        $labParameters = @{
            ResourceGroupName = $ResourceGroupName
            Name = $LabName
            Location = $Location
            LabStorageType = "Premium"
        }
        New-AzDevTestLab @labParameters | Out-Null
        Write-Host "DevTest Lab created successfully" -ForegroundColor Green
    }
    else {
        Write-Host "DevTest Lab already exists: $LabName" -ForegroundColor Green
    }

    # Prepare deployment parameters
    $deploymentParameters = @{
        labName = $LabName
        domainName = $DomainName
        adminUsername = $AdminUsername
        adminPassword = $AdminPassword
        serverVmName = $ServerVmName
        clientVmName = $ClientVmName
        vmSize = $VmSize
    }

    # Generate unique deployment name
    $deploymentName = "ADLabDeployment-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    Write-Host "Starting ARM template deployment..." -ForegroundColor Cyan
    Write-Host "Deployment Name: $deploymentName" -ForegroundColor Yellow

    # Deploy the ARM template
    $deployment = New-AzResourceGroupDeployment `
        -ResourceGroupName $ResourceGroupName `
        -Name $deploymentName `
        -TemplateUri $TemplateUri `
        -TemplateParameterObject $deploymentParameters `
        -Verbose

    if ($deployment.ProvisioningState -eq "Succeeded") {
        Write-Host "Deployment completed successfully!" -ForegroundColor Green
        
        # Display deployment outputs
        Write-Host "`nDeployment Results:" -ForegroundColor Green
        Write-Host "===================" -ForegroundColor Green
        foreach ($output in $deployment.Outputs.GetEnumerator()) {
            Write-Host "$($output.Key): $($output.Value.Value)" -ForegroundColor White
        }

        # Display connection information
        Write-Host "`nConnection Information:" -ForegroundColor Cyan
        Write-Host "======================" -ForegroundColor Cyan
        Write-Host "Domain Controller: $ServerVmName" -ForegroundColor White
        Write-Host "Windows 11 Client: $ClientVmName" -ForegroundColor White
        Write-Host "Domain Name: $DomainName" -ForegroundColor White
        Write-Host "Admin Username: $AdminUsername" -ForegroundColor White
        Write-Host "Lab URL: https://portal.azure.com/#@$($context.Tenant.Id)/resource/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.DevTestLab/labs/$LabName" -ForegroundColor White

        Write-Host "`nNext Steps:" -ForegroundColor Yellow
        Write-Host "1. Wait 10-15 minutes for the domain controller setup to complete" -ForegroundColor White
        Write-Host "2. Connect to VMs through the DevTest Lab portal" -ForegroundColor White
        Write-Host "3. Verify domain join by logging into the Windows 11 client with domain credentials" -ForegroundColor White
        Write-Host "4. Test users: testuser1 and testuser2 (password same as admin)" -ForegroundColor White
    }
    else {
        Write-Error "Deployment failed with state: $($deployment.ProvisioningState)"
        if ($deployment.StatusMessage) {
            Write-Error "Status Message: $($deployment.StatusMessage)"
        }
        exit 1
    }
}
catch {
    Write-Error "Deployment failed with error: $($_.Exception.Message)"
    Write-Error "Stack Trace: $($_.Exception.StackTrace)"
    exit 1
}

Write-Host "`nActive Directory Lab Environment deployment completed!" -ForegroundColor Green
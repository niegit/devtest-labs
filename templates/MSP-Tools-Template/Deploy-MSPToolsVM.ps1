param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$VmName,
    
    [Parameter(Mandatory=$true)]
    [securestring]$AdminPassword,
    
    [string]$AdminUsername = "msptech",
    [string]$VmSize = "Standard_B2ms",
    [string]$AutoShutdownTime = "1800",
    [bool]$EnableAutoShutdown = $true,
    [string]$TemplateUri = "https://raw.githubusercontent.com/niegit/devtest-labs/main/templates/MSP-Tools-Template/azuredeploy.json",
    [string]$Location = "North Central US"
)

# Import required modules
Import-Module Az.Accounts -Force
Import-Module Az.Resources -Force

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "Starting MSP Security & Tools VM Deployment..." -ForegroundColor Green
Write-Host "VM Name: $VmName" -ForegroundColor Yellow
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
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

    # Prepare deployment parameters
    $deploymentParameters = @{
        vmName = $VmName
        adminUsername = $AdminUsername
        adminPassword = $AdminPassword
        vmSize = $VmSize
        autoShutdownTime = $AutoShutdownTime
        enableAutoShutdown = $EnableAutoShutdown
        location = $Location
    }

    # Generate unique deployment name
    $deploymentName = "MSPToolsVMDeployment-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
        Write-Host "VM Name: $VmName" -ForegroundColor White
        Write-Host "Admin Username: $AdminUsername" -ForegroundColor White
        Write-Host "Public IP: $($deployment.Outputs.publicIP.Value)" -ForegroundColor White
        Write-Host "FQDN: $($deployment.Outputs.fqdn.Value)" -ForegroundColor White
        Write-Host "RDP Command: $($deployment.Outputs.rdpCommand.Value)" -ForegroundColor White
        
        if ($EnableAutoShutdown) {
            Write-Host "Auto-shutdown: Enabled at $AutoShutdownTime" -ForegroundColor White
        } else {
            Write-Host "Auto-shutdown: Disabled" -ForegroundColor White
        }

        Write-Host "`nInstalled Tools:" -ForegroundColor Yellow
        Write-Host $deployment.Outputs.installedTools.Value -ForegroundColor White

        Write-Host "`nNext Steps:" -ForegroundColor Yellow
        Write-Host "1. Wait 10-15 minutes for tool installation to complete" -ForegroundColor White
        Write-Host "2. Connect via RDP using the command above" -ForegroundColor White
        Write-Host "3. Check desktop for setup summary and tool shortcuts" -ForegroundColor White
        Write-Host "4. Set up free accounts for online analysis tools (Hybrid Analysis, VirusTotal)" -ForegroundColor White
        Write-Host "5. Test PowerShell modules: Open 'PowerShell ISE (MSP)' and run Connect-M365" -ForegroundColor White

        Write-Host "`nTool Locations:" -ForegroundColor Cyan
        Write-Host "- Main tools directory: C:\MSP-Tools" -ForegroundColor White
        Write-Host "- Network tools: C:\MSP-Tools\Network" -ForegroundColor White  
        Write-Host "- Security tools: C:\MSP-Tools\Security" -ForegroundColor White
        Write-Host "- Log analysis: C:\MSP-Tools\Logs" -ForegroundColor White
        Write-Host "- Remote access: C:\MSP-Tools\Remote" -ForegroundColor White
        Write-Host "- System utilities: C:\MSP-Tools\System" -ForegroundColor White
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

Write-Host "`nMSP Security & Tools VM deployment completed!" -ForegroundColor Green

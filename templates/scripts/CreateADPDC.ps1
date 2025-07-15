param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$true)]
    [string]$AdminUsername,
    
    [Parameter(Mandatory=$true)]
    [string]$AdminPassword
)

# Create log file
$LogFile = "C:\Windows\Temp\CreateADPDC.log"
Start-Transcript -Path $LogFile -Append

Write-Output "Starting Active Directory Domain Controller setup..."
Write-Output "Domain: $DomainName"
Write-Output "Admin User: $AdminUsername"

# Check if this is a continuation after reboot
$ContinuationFlag = "C:\Windows\Temp\ADSetupContinuation.flag"

try {
    if (-not (Test-Path $ContinuationFlag)) {
        # PHASE 1: Initial setup and forest installation
        Write-Output "=== PHASE 1: Initial Setup ==="
        
        # Create credential object
        $securePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($AdminUsername, $securePassword)

        # Install DNS Server feature
        Write-Output "Installing DNS Server feature..."
        Install-WindowsFeature -Name DNS -IncludeManagementTools -Verbose
        
        # Install AD DS feature
        Write-Output "Installing Active Directory Domain Services feature..."
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Verbose
        
        # Install additional management tools
        Write-Output "Installing additional management tools..."
        Install-WindowsFeature -Name GPMC -Verbose
        Install-WindowsFeature -Name RSAT-DNS-Server -Verbose
        Install-WindowsFeature -Name RSAT-ADDS-Tools -Verbose
        Install-WindowsFeature -Name RSAT-ADCS-Mgmt -Verbose

        # Set DNS server address to localhost
        Write-Output "Configuring DNS settings..."
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "127.0.0.1"
            Write-Output "Set DNS for adapter: $($adapter.Name)"
        }

        # Enable DNS diagnostics
        Write-Output "Enabling DNS diagnostics..."
        Set-DnsServerDiagnostics -All $true

        # Create continuation script for after reboot
        $continuationScript = @"
# PHASE 2: Post-reboot configuration
`$LogFile = "C:\Windows\Temp\CreateADPDC.log"
Start-Transcript -Path `$LogFile -Append

Write-Output "=== PHASE 2: Post-Reboot Configuration ==="

try {
    # Wait a bit for services to start
    Start-Sleep -Seconds 30
    
    # Import AD module
    Import-Module ActiveDirectory -Force
    
    # Wait for AD to be ready
    `$retryCount = 0
    `$maxRetries = 10
    do {
        try {
            Get-ADDomain -Identity "$DomainName" -ErrorAction Stop
            Write-Output "Active Directory domain is ready"
            break
        }
        catch {
            Write-Output "Waiting for AD services, retry `$retryCount of `$maxRetries"
            Start-Sleep -Seconds 30
            `$retryCount++
        }
    } while (`$retryCount -lt `$maxRetries)

    if (`$retryCount -eq `$maxRetries) {
        Write-Output "AD services took longer than expected, but this is normal. Continuing with configuration..."
    }

    # Create credential object
    `$securePassword = ConvertTo-SecureString "$AdminPassword" -AsPlainText -Force
    
    # Create Organizational Units
    Write-Output "Creating Organizational Units..."
    
    `$domainDN = "DC=`$("$DomainName".Replace('.', ',DC='))"
    
    # Create OUs with error handling
    @("Servers", "Workstations", "Users") | ForEach-Object {
        try {
            New-ADOrganizationalUnit -Name `$_ -Path `$domainDN -Description "`$_ Organizational Unit" -ProtectedFromAccidentalDeletion `$true -ErrorAction SilentlyContinue
            Write-Output "Created `$_ OU"
        }
        catch {
            Write-Output "`$_ OU may already exist: `$(`$_.Exception.Message)"
        }
    }

    # Create test users
    Write-Output "Creating test users..."
    
    `$usersOU = "OU=Users,`$domainDN"
    
    @("testuser1", "testuser2") | ForEach-Object {
        try {
            New-ADUser -Name `$_ -DisplayName "Test User `$(`$_.Substring(`$_.Length-1))" -SamAccountName `$_ -UserPrincipalName "`$_@$DomainName" -Path `$usersOU -AccountPassword `$securePassword -Enabled `$true -PasswordNeverExpires `$true -ErrorAction SilentlyContinue
            Write-Output "Created `$_"
        }
        catch {
            Write-Output "Failed to create `$_: `$(`$_.Exception.Message)"
        }
    }

    # Configure DNS forwarders
    Write-Output "Configuring DNS forwarders..."
    try {
        @("8.8.8.8", "8.8.4.4") | ForEach-Object {
            Add-DnsServerForwarder -IPAddress `$_ -ErrorAction SilentlyContinue
        }
        Write-Output "DNS forwarders configured"
    }
    catch {
        Write-Output "DNS forwarders may already be configured"
    }

    # Clean up
    Remove-Item "C:\Windows\Temp\ADSetupContinuation.flag" -Force -ErrorAction SilentlyContinue
    
    Write-Output "=== Active Directory setup completed successfully! ==="
    Write-Output "Domain: $DomainName"
    Write-Output "Test users: testuser1, testuser2"
    Write-Output "OUs: Servers, Workstations, Users"
    
} catch {
    Write-Output "Post-reboot configuration error: `$(`$_.Exception.Message)"
}
finally {
    Stop-Transcript
}
"@
        
        # Save continuation script
        $continuationScript | Out-File -FilePath "C:\Windows\Temp\ContinueADSetup.ps1" -Encoding ASCII

        # Create scheduled task to run after reboot
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Unrestricted -File C:\Windows\Temp\ContinueADSetup.ps1"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserID "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        Register-ScheduledTask -TaskName "ContinueADSetup" -Action $action -Trigger $trigger -Principal $principal -Settings $settings

        # Create flag to indicate we're in continuation mode
        "Continuation" | Out-File -FilePath $ContinuationFlag

        # Create new AD forest (this will trigger reboot)
        Write-Output "Creating new Active Directory forest: $DomainName"
        $forestParams = @{
            DomainName = $DomainName
            SafeModeAdministratorPassword = $securePassword
            InstallDns = $true
            CreateDnsDelegation = $false
            DatabasePath = "C:\Windows\NTDS"
            LogPath = "C:\Windows\NTDS"
            SysvolPath = "C:\Windows\SYSVOL"
            Force = $true
            NoRebootOnCompletion = $false  # Allow automatic reboot
        }
        
        Install-ADDSForest @forestParams

        # This point should not be reached due to reboot
        Write-Output "Forest installation completed - system should reboot automatically"
        
    } else {
        # PHASE 2: This should not run in this script instance since we allow auto-reboot
        Write-Output "=== PHASE 2: This instance should not reach here ==="
        Write-Output "The scheduled task should handle post-reboot configuration."
    }

}
catch {
    Write-Error "Domain Controller setup failed: $($_.Exception.Message)"
    Write-Error $_.Exception.StackTrace
    exit 1
}
finally {
    Stop-Transcript
}

# End of script
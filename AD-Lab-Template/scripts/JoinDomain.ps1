param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$true)]
    [string]$AdminUsername,
    
    [Parameter(Mandatory=$true)]
    [string]$AdminPassword,
    
    [Parameter(Mandatory=$true)]
    [string]$DCIPAddress
)

# Create log file
$LogFile = "C:\Windows\Temp\DomainJoin.log"
Start-Transcript -Path $LogFile -Append

Write-Output "Starting domain join process..."
Write-Output "Domain: $DomainName"
Write-Output "DC IP: $DCIPAddress"
Write-Output "Admin User: $AdminUsername"

try {
    # Set DNS server to domain controller
    Write-Output "Setting DNS server to $DCIPAddress"
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DCIPAddress
        Write-Output "Set DNS for adapter: $($adapter.Name)"
    }

    # Wait for DNS resolution to work
    Write-Output "Testing DNS resolution..."
    $retryCount = 0
    $maxRetries = 30
    
    do {
        try {
            $result = Resolve-DnsName -Name $DomainName -Type A -ErrorAction Stop
            Write-Output "DNS resolution successful for $DomainName"
            break
        }
        catch {
            Write-Output "DNS resolution failed, retry $retryCount of $maxRetries"
            Start-Sleep -Seconds 10
            $retryCount++
        }
    } while ($retryCount -lt $maxRetries)

    if ($retryCount -eq $maxRetries) {
        throw "DNS resolution failed after $maxRetries attempts"
    }

    # Create credential object
    $securePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("$DomainName\$AdminUsername", $securePassword)

    # Test domain connectivity
    Write-Output "Testing domain connectivity..."
    try {
        $domainController = Get-ADDomainController -DomainName $DomainName -Credential $credential -ErrorAction Stop
        Write-Output "Successfully connected to domain controller: $($domainController.Name)"
    }
    catch {
        Write-Output "Direct AD connection failed, proceeding with domain join anyway..."
    }

    # Join the domain
    Write-Output "Joining domain $DomainName..."
    
    # Use Add-Computer cmdlet
    Add-Computer -DomainName $DomainName -Credential $credential -Force -Verbose
    
    Write-Output "Domain join completed successfully!"
    
    # Move computer to Workstations OU (optional)
    try {
        $computerName = $env:COMPUTERNAME
        $workstationsOU = "OU=Workstations,DC=$($DomainName.Replace('.', ',DC='))"
        
        # Import AD module if available
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory
            Move-ADObject -Identity "CN=$computerName,CN=Computers,DC=$($DomainName.Replace('.', ',DC='))" -TargetPath $workstationsOU -Credential $credential
            Write-Output "Moved computer to Workstations OU"
        }
        else {
            Write-Output "ActiveDirectory module not available, computer remains in default Computers container"
        }
    }
    catch {
        Write-Output "Failed to move computer to Workstations OU: $($_.Exception.Message)"
    }

    # Create local test accounts
    Write-Output "Creating local test accounts..."
    try {
        $localPassword = ConvertTo-SecureString "LocalUser123!" -AsPlainText -Force
        
        # Check if user already exists
        if (-not (Get-LocalUser -Name "LocalTestUser" -ErrorAction SilentlyContinue)) {
            New-LocalUser -Name "LocalTestUser" -Password $localPassword -Description "Local test user account" -PasswordNeverExpires
            Add-LocalGroupMember -Group "Users" -Member "LocalTestUser"
            Write-Output "Created LocalTestUser account"
        }
        else {
            Write-Output "LocalTestUser already exists"
        }
    }
    catch {
        Write-Output "Failed to create local test user: $($_.Exception.Message)"
    }

    # Configure Windows Update to use WSUS if available (optional)
    Write-Output "Configuring Windows Update settings..."
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        # Disable automatic updates during lab testing
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -ErrorAction SilentlyContinue
        Write-Output "Configured Windows Update settings"
    }
    catch {
        Write-Output "Failed to configure Windows Update: $($_.Exception.Message)"
    }

    # Install RSAT tools for management
    Write-Output "Installing RSAT tools..."
    try {
        $rsatFeatures = @(
            "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0",
            "Rsat.Dns.Tools~~~~0.0.1.0",
            "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
        )
        
        foreach ($feature in $rsatFeatures) {
            Add-WindowsCapability -Online -Name $feature -ErrorAction SilentlyContinue
            Write-Output "Installed RSAT feature: $feature"
        }
    }
    catch {
        Write-Output "Failed to install some RSAT tools: $($_.Exception.Message)"
    }

    # Set time zone (optional)
    Write-Output "Setting time zone..."
    try {
        Set-TimeZone -Id "Eastern Standard Time" -ErrorAction SilentlyContinue
        Write-Output "Time zone set successfully"
    }
    catch {
        Write-Output "Failed to set time zone: $($_.Exception.Message)"
    }

    Write-Output "Domain join process completed successfully!"
    Write-Output "The computer will restart automatically to complete the domain join."

    # Schedule restart
    shutdown /r /t 60 /c "Restarting to complete domain join" /f

}
catch {
    Write-Error "Domain join failed: $($_.Exception.Message)"
    Write-Error $_.Exception.StackTrace
    exit 1
}
finally {
    Stop-Transcript
}

# End of script
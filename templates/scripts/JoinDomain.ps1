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
Write-Output "Current time: $(Get-Date)"

try {
    # Set DNS server to domain controller
    Write-Output "Setting DNS server to $DCIPAddress"
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DCIPAddress
        Write-Output "Set DNS for adapter: $($adapter.Name)"
    }

    # Clear DNS cache
    Write-Output "Clearing DNS cache..."
    Clear-DnsClientCache

    # Wait for DNS resolution to work
    Write-Output "Testing DNS resolution..."
    $retryCount = 0
    $maxRetries = 30
    $lastDnsError = ""
    
    do {
        try {
            $result = Resolve-DnsName -Name $DomainName -Type A -ErrorAction Stop
            Write-Output "DNS resolution successful for $DomainName - IP: $($result.IPAddress)"
            break
        }
        catch {
            $lastDnsError = $_.Exception.Message
            Write-Output "DNS resolution failed, retry $retryCount of $maxRetries - Error: $lastDnsError"
            Start-Sleep -Seconds 10
            $retryCount++
        }
    } while ($retryCount -lt $maxRetries)

    if ($retryCount -eq $maxRetries) {
        throw "DNS resolution failed after $maxRetries attempts. Last error: $lastDnsError"
    }

    # Test domain controller connectivity
    Write-Output "Testing domain controller connectivity..."
    $connectivityTests = @(
        @{ Port = 389; Service = "LDAP" },
        @{ Port = 88; Service = "Kerberos" },
        @{ Port = 53; Service = "DNS" }
    )

    foreach ($test in $connectivityTests) {
        try {
            $connection = Test-NetConnection -ComputerName $DCIPAddress -Port $test.Port -WarningAction SilentlyContinue
            if ($connection.TcpTestSucceeded) {
                Write-Output "Successfully connected to $($test.Service) on port $($test.Port)"
            } else {
                Write-Output "Warning: Could not connect to $($test.Service) on port $($test.Port)"
            }
        }
        catch {
            Write-Output "Warning: Failed to test $($test.Service) connectivity: $($_.Exception.Message)"
        }
    }

    # Create credential object
    $securePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("$DomainName\$AdminUsername", $securePassword)

    # Join the domain with retry logic
    Write-Output "Joining domain $DomainName..."
    
    $joinRetryCount = 0
    $maxJoinRetries = 3
    $joinSuccessful = $false
    $lastJoinError = ""
    
    do {
        try {
            Add-Computer -DomainName $DomainName -Credential $credential -Force -Verbose -ErrorAction Stop
            $joinSuccessful = $true
            Write-Output "Domain join completed successfully!"
            break
        }
        catch {
            $joinRetryCount++
            $lastJoinError = $_.Exception.Message
            Write-Output "Domain join attempt $joinRetryCount failed: $lastJoinError"
            
            if ($joinRetryCount -lt $maxJoinRetries) {
                Write-Output "Retrying domain join in 30 seconds..."
                Start-Sleep -Seconds 30
            }
        }
    } while ($joinRetryCount -lt $maxJoinRetries -and -not $joinSuccessful)

    if (-not $joinSuccessful) {
        throw "Domain join failed after $maxJoinRetries attempts. Last error: $lastJoinError"
    }

    # Verify domain join
    Write-Output "Verifying domain join..."
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        if ($computerSystem.Domain -eq $DomainName) {
            Write-Output "Domain join verification successful. Computer is now member of: $($computerSystem.Domain)"
        } else {
            Write-Output "Warning: Domain join verification shows domain as: $($computerSystem.Domain)"
        }
    }
    catch {
        Write-Output "Could not verify domain join status: $($_.Exception.Message)"
    }

    # Install RSAT tools for management (before attempting to move computer)
    Write-Output "Installing RSAT tools..."
    try {
        $rsatFeatures = @(
            "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0",
            "Rsat.Dns.Tools~~~~0.0.1.0",
            "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
        )
        
        foreach ($feature in $rsatFeatures) {
            try {
                $result = Add-WindowsCapability -Online -Name $feature -ErrorAction Stop
                if ($result.RestartNeeded) {
                    Write-Output "RSAT feature $feature installed (restart required)"
                } else {
                    Write-Output "RSAT feature $feature installed successfully"
                }
            }
            catch {
                Write-Output "Failed to install RSAT feature ${feature}: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Output "Failed to install RSAT tools: $($_.Exception.Message)"
    }

    # Try to move computer to Workstations OU (only if AD module is available)
    Write-Output "Attempting to move computer to Workstations OU..."
    try {
        # First check if ActiveDirectory module is available
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction Stop
            
            $computerName = $env:COMPUTERNAME
            $domainDN = "DC=" + $DomainName.Replace('.', ',DC=')
            $workstationsOU = "OU=Workstations,$domainDN"
            $computerDN = "CN=$computerName,CN=Computers,$domainDN"
            
            # Check if Workstations OU exists, create if it doesn't
            try {
                Get-ADOrganizationalUnit -Identity $workstationsOU -Credential $credential -ErrorAction Stop | Out-Null
                Write-Output "Workstations OU exists"
            }
            catch {
                Write-Output "Workstations OU does not exist, creating it..."
                New-ADOrganizationalUnit -Name "Workstations" -Path $domainDN -Credential $credential -ErrorAction Stop
                Write-Output "Created Workstations OU"
            }
            
            # Move the computer
            Move-ADObject -Identity $computerDN -TargetPath $workstationsOU -Credential $credential -ErrorAction Stop
            Write-Output "Successfully moved computer to Workstations OU"
        }
        else {
            Write-Output "ActiveDirectory module not available, computer remains in default Computers container"
        }
    }
    catch {
        Write-Output "Failed to move computer to Workstations OU: $($_.Exception.Message)"
        Write-Output "Computer will remain in default Computers container"
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

    # Configure Windows Update to use manual updates during lab testing
    Write-Output "Configuring Windows Update settings..."
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        $regPathAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $regPathAU)) {
            New-Item -Path $regPathAU -Force | Out-Null
        }
        
        # Configure for manual updates during lab testing
        Set-ItemProperty -Path $regPathAU -Name "NoAutoUpdate" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $regPathAU -Name "AUOptions" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        Write-Output "Configured Windows Update for manual updates"
    }
    catch {
        Write-Output "Failed to configure Windows Update: $($_.Exception.Message)"
    }

    # Set time zone to match domain controller
    Write-Output "Setting time zone..."
    try {
        Set-TimeZone -Id "Central Standard Time" -ErrorAction Stop
        Write-Output "Time zone set to Central Standard Time"
    }
    catch {
        Write-Output "Failed to set time zone: $($_.Exception.Message)"
    }

    # Enable RDP (should already be enabled, but ensure it's configured)
    Write-Output "Ensuring RDP is enabled..."
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
        Write-Output "RDP enabled and firewall configured"
    }
    catch {
        Write-Output "Failed to configure RDP: $($_.Exception.Message)"
    }

    Write-Output "Domain join process completed successfully!"
    Write-Output "Summary:"
    Write-Output "  - Domain: $DomainName"
    Write-Output "  - Computer: $env:COMPUTERNAME"
    Write-Output "  - Admin User: $AdminUsername"
    Write-Output "  - Completion Time: $(Get-Date)"
    Write-Output ""
    Write-Output "The computer will restart in 60 seconds to complete the domain join."
    Write-Output "After restart, you can log in with domain credentials: $DomainName\$AdminUsername"

    # Schedule restart with more time for cleanup
    shutdown /r /t 60 /c "Restarting to complete domain join" /f

}
catch {
    Write-Error "Domain join failed: $($_.Exception.Message)"
    Write-Error "Full error details:"
    Write-Error $_.Exception.StackTrace
    
    # Additional diagnostic information
    Write-Output ""
    Write-Output "=== DIAGNOSTIC INFORMATION ==="
    Write-Output "Computer Name: $env:COMPUTERNAME"
    Write-Output "Current Domain: $((Get-WmiObject -Class Win32_ComputerSystem).Domain)"
    Write-Output "DNS Settings:"
    Get-DnsClientServerAddress | ForEach-Object { Write-Output "  Interface: $($_.InterfaceAlias) - DNS: $($_.ServerAddresses -join ', ')" }
    Write-Output "Network Adapters:"
    Get-NetAdapter | Where-Object Status -eq "Up" | ForEach-Object { Write-Output "  $($_.Name): $($_.Status)" }
    Write-Output "================================"
    
    exit 1
}
finally {
    Stop-Transcript
}

# End of script
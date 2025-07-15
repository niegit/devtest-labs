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

try {
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

    # Create new AD forest
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
        NoRebootOnCompletion = $true
    }
    
    Install-ADDSForest @forestParams

    Write-Output "Forest installation completed. Waiting before configuring additional settings..."
    Start-Sleep -Seconds 30

    # Import AD module
    Import-Module ActiveDirectory -Force

    # Wait for AD services to be ready
    $retryCount = 0
    $maxRetries = 20
    do {
        try {
            Get-ADDomain -Identity $DomainName -ErrorAction Stop
            Write-Output "Active Directory domain is ready"
            break
        }
        catch {
            Write-Output "Waiting for AD services to start, retry $retryCount of $maxRetries"
            Start-Sleep -Seconds 15
            $retryCount++
        }
    } while ($retryCount -lt $maxRetries)

    if ($retryCount -eq $maxRetries) {
        throw "Active Directory services failed to start after $maxRetries attempts"
    }

    # Create Organizational Units
    Write-Output "Creating Organizational Units..."
    
    $domainDN = "DC=$($DomainName.Replace('.', ',DC='))"
    
    # Create Servers OU
    try {
        New-ADOrganizationalUnit -Name "Servers" -Path $domainDN -Description "Servers Organizational Unit" -ProtectedFromAccidentalDeletion $true
        Write-Output "Created Servers OU"
    }
    catch {
        Write-Output "Servers OU may already exist or error occurred: $($_.Exception.Message)"
    }

    # Create Workstations OU  
    try {
        New-ADOrganizationalUnit -Name "Workstations" -Path $domainDN -Description "Workstations Organizational Unit" -ProtectedFromAccidentalDeletion $true
        Write-Output "Created Workstations OU"
    }
    catch {
        Write-Output "Workstations OU may already exist or error occurred: $($_.Exception.Message)"
    }

    # Create Users OU
    try {
        New-ADOrganizationalUnit -Name "Users" -Path $domainDN -Description "Users Organizational Unit" -ProtectedFromAccidentalDeletion $true
        Write-Output "Created Users OU"
    }
    catch {
        Write-Output "Users OU may already exist or error occurred: $($_.Exception.Message)"
    }

    # Create test users
    Write-Output "Creating test users..."
    
    $usersOU = "OU=Users,$domainDN"
    
    # Create TestUser1
    try {
        New-ADUser -Name "testuser1" -DisplayName "Test User 1" -SamAccountName "testuser1" -UserPrincipalName "testuser1@$DomainName" -Path $usersOU -AccountPassword $securePassword -Enabled $true -PasswordNeverExpires $true
        Write-Output "Created testuser1"
    }
    catch {
        Write-Output "Failed to create testuser1: $($_.Exception.Message)"
    }

    # Create TestUser2
    try {
        New-ADUser -Name "testuser2" -DisplayName "Test User 2" -SamAccountName "testuser2" -UserPrincipalName "testuser2@$DomainName" -Path $usersOU -AccountPassword $securePassword -Enabled $true -PasswordNeverExpires $true
        Write-Output "Created testuser2"
    }
    catch {
        Write-Output "Failed to create testuser2: $($_.Exception.Message)"
    }

    # Configure DNS forwarders
    Write-Output "Configuring DNS forwarders..."
    try {
        $forwarders = Get-DnsServerForwarder -ErrorAction SilentlyContinue
        if (-not ($forwarders.IPAddress -contains "8.8.8.8")) {
            Add-DnsServerForwarder -IPAddress "8.8.8.8" -PassThru
            Write-Output "Added DNS forwarder 8.8.8.8"
        }
        if (-not ($forwarders.IPAddress -contains "8.8.4.4")) {
            Add-DnsServerForwarder -IPAddress "8.8.4.4" -PassThru
            Write-Output "Added DNS forwarder 8.8.4.4"
        }
    }
    catch {
        Write-Output "Failed to configure DNS forwarders: $($_.Exception.Message)"
    }

    # Enable Windows Firewall logging
    Write-Output "Configuring Windows Firewall logging..."
    try {
        netsh advfirewall set allprofiles logging droppedconnections enable
        netsh advfirewall set allprofiles logging allowedconnections enable
        Write-Output "Enabled firewall logging"
    }
    catch {
        Write-Output "Failed to configure firewall logging: $($_.Exception.Message)"
    }

    # Configure time zone
    Write-Output "Setting time zone..."
    try {
        Set-TimeZone -Id "Central Standard Time" -ErrorAction SilentlyContinue
        Write-Output "Time zone set to Central Standard Time"
    }
    catch {
        Write-Output "Failed to set time zone: $($_.Exception.Message)"
    }

    Write-Output "Active Directory Domain Controller setup completed successfully!"
    Write-Output "Domain: $DomainName"
    Write-Output "Test users created: testuser1, testuser2 (password same as admin)"
    Write-Output "OUs created: Servers, Workstations, Users"
    Write-Output "The server will restart automatically to complete the setup."

    # Schedule restart
    shutdown /r /t 60 /c "Restarting to complete Active Directory setup" /f

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
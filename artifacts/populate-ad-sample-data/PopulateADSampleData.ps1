param(
    [int]$UserCount = 25,
    [int]$DepartmentCount = 5,
    [string]$CreateServiceAccounts = "true",
    [string]$EnablePasswordPolicy = "true",
    [string]$CreateSecurityGroups = "true"
)

# Convert string parameters to boolean
$CreateServiceAccountsBool = $CreateServiceAccounts -eq "true" -or $CreateServiceAccounts -eq "True" -or $CreateServiceAccounts -eq "1"
$EnablePasswordPolicyBool = $EnablePasswordPolicy -eq "true" -or $EnablePasswordPolicy -eq "True" -or $EnablePasswordPolicy -eq "1"
$CreateSecurityGroupsBool = $CreateSecurityGroups -eq "true" -or $CreateSecurityGroups -eq "True" -or $CreateSecurityGroups -eq "1"

$LogFile = "C:\Windows\Temp\PopulateADSampleData.log"
Start-Transcript -Path $LogFile -Append

Write-Output "=== Active Directory Sample Data Population ==="
Write-Output "Start Time: $(Get-Date)"

# Check if this is a domain controller
Write-Output "Checking if this server is a domain controller..."
$isDC = $false

$dcRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
if ($dcRole -eq 4 -or $dcRole -eq 5) {
    $isDC = $true
    Write-Output "Server is a domain controller"
}

if (-not $isDC) {
    $addsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
    if ($addsService -and $addsService.Status -eq "Running") {
        $isDC = $true
        Write-Output "Active Directory Domain Services is running"
    }
}

if (-not $isDC) {
    Write-Output "This server is not a domain controller. Exiting."
    exit 0
}

# Check and start ADWS service
Write-Output "Checking Active Directory Web Services..."
$adwsService = Get-Service -Name "ADWS" -ErrorAction SilentlyContinue
if ($adwsService) {
    if ($adwsService.StartType -eq "Disabled") {
        Write-Output "ADWS is disabled. Enabling and starting it..."
        Set-Service ADWS -StartupType Automatic
        Start-Service ADWS
        Write-Output "ADWS enabled and started"
    }
    elseif ($adwsService.Status -ne "Running") {
        Write-Output "Starting ADWS service..."
        Start-Service ADWS
        Write-Output "ADWS started"
    }
    else {
        Write-Output "ADWS is already running"
    }
    
    # Wait a moment for ADWS to fully initialize
    Start-Sleep -Seconds 5
}
else {
    Write-Output "Warning: ADWS service not found"
}

# Import Active Directory module
Write-Output "Importing Active Directory module..."
Import-Module ActiveDirectory -Force -ErrorAction Stop
Write-Output "Active Directory module imported successfully"

# Get domain information
$domain = Get-ADDomain -ErrorAction Stop
$domainDN = $domain.DistinguishedName
$domainName = $domain.DNSRoot
Write-Output "Domain: $domainName"

# Sample data
$firstNames = @("John", "Jane", "Michael", "Sarah", "David", "Emily", "Robert", "Lisa")
$lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis")
$departments = @("IT", "HR", "Finance", "Marketing", "Sales", "Operations")

# Create Department OUs
Write-Output "Creating Department Organizational Units..."
$selectedDepartments = $departments | Get-Random -Count $DepartmentCount
$createdDepts = @()

foreach ($dept in $selectedDepartments) {
    $deptOU = "OU=$dept,$domainDN"
    
    $existing = Get-ADOrganizationalUnit -Filter "Name -eq '$dept'" -SearchBase $domainDN -SearchScope OneLevel -ErrorAction SilentlyContinue
    
    if (-not $existing) {
        New-ADOrganizationalUnit -Name $dept -Path $domainDN -Description "$dept Department" -ProtectedFromAccidentalDeletion $false
        Write-Output "Created $dept OU"
    } else {
        Write-Output "$dept OU already exists"
    }
    
    $createdDepts += $dept
}

# Create Security Groups
if ($CreateSecurityGroupsBool) {
    Write-Output "Creating Security Groups..."
    
    foreach ($dept in $createdDepts) {
        $groupName = "$dept-Users"
        $deptOU = "OU=$dept,$domainDN"
        
        $existing = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
        
        if (-not $existing) {
            New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Path $deptOU -Description "All users in $dept department"
            Write-Output "Created $groupName security group"
        } else {
            Write-Output "$groupName group already exists"
        }
    }
}

# Create Sample Users
Write-Output "Creating Sample Users..."
$defaultPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
$usersCreated = 0
$usersPerDept = [math]::Floor($UserCount / $createdDepts.Count)

foreach ($dept in $createdDepts) {
    $deptOU = "OU=$dept,$domainDN"
    
    for ($i = 1; $i -le $usersPerDept; $i++) {
        $firstName = $firstNames | Get-Random
        $lastName = $lastNames | Get-Random
        $username = "$($firstName.Substring(0,1).ToLower())$($lastName.ToLower())$($usersCreated + 1)"
        $displayName = "$firstName $lastName"
        $email = "$username@$domainName"
        
        $existing = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
        
        if (-not $existing) {
            $userParams = @{
                Name = $displayName
                DisplayName = $displayName
                GivenName = $firstName
                Surname = $lastName
                SamAccountName = $username
                UserPrincipalName = $email
                EmailAddress = $email
                Department = $dept
                Company = "Contoso Corporation"
                Path = $deptOU
                AccountPassword = $defaultPassword
                Enabled = $true
                PasswordNeverExpires = $true
                ChangePasswordAtLogon = $false
            }

            New-ADUser @userParams
            Write-Output "Created user: $username ($displayName) - $dept"
            
            if ($CreateSecurityGroupsBool) {
                Add-ADGroupMember -Identity "$dept-Users" -Members $username -ErrorAction SilentlyContinue
            }
            
            $usersCreated++
        } else {
            Write-Output "User $username already exists, skipping"
        }
    }
}

# Create Service Accounts
if ($CreateServiceAccountsBool) {
    Write-Output "Creating Service Accounts..."
    
    $serviceOU = "OU=Service Accounts,$domainDN"
    $existing = Get-ADOrganizationalUnit -Filter "Name -eq 'Service Accounts'" -SearchBase $domainDN -SearchScope OneLevel -ErrorAction SilentlyContinue
    
    if (-not $existing) {
        New-ADOrganizationalUnit -Name "Service Accounts" -Path $domainDN -Description "Service and application accounts" -ProtectedFromAccidentalDeletion $false
        Write-Output "Created Service Accounts OU"
    }

    $serviceAccounts = @("svc-backup", "svc-sql", "svc-iis")

    foreach ($svcName in $serviceAccounts) {
        $existing = Get-ADUser -Filter "SamAccountName -eq '$svcName'" -ErrorAction SilentlyContinue
        
        if (-not $existing) {
            $svcParams = @{
                Name = $svcName
                DisplayName = "$svcName service account"
                SamAccountName = $svcName
                UserPrincipalName = "$svcName@$domainName"
                Path = $serviceOU
                AccountPassword = $defaultPassword
                Enabled = $true
                PasswordNeverExpires = $true
                CannotChangePassword = $true
            }

            New-ADUser @svcParams
            Write-Output "Created service account: $svcName"
        } else {
            Write-Output "Service account $svcName already exists"
        }
    }
}

# Summary
Write-Output "=== Summary Report ==="
Write-Output "Domain: $domainName"
Write-Output "Users created: $usersCreated"
Write-Output "Departments: $($createdDepts -join ', ')"
Write-Output "All user passwords: P@ssw0rd123!"
Write-Output "Active Directory sample data population completed successfully!"

Stop-Transcript
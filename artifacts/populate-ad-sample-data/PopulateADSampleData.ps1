param(
    [int]$UserCount = 25,
    [int]$DepartmentCount = 5,
    [bool]$CreateServiceAccounts = $true,
    [bool]$EnablePasswordPolicy = $true,
    [bool]$CreateSecurityGroups = $true
)

# Create log file
$LogFile = "C:\Windows\Temp\PopulateADSampleData.log"
Start-Transcript -Path $LogFile -Append

Write-Output "=== Active Directory Sample Data Population ==="
Write-Output "Start Time: $(Get-Date)"
Write-Output "Parameters:"
Write-Output "  User Count: $UserCount"
Write-Output "  Department Count: $DepartmentCount"
Write-Output "  Create Service Accounts: $CreateServiceAccounts"
Write-Output "  Enable Password Policy: $EnablePasswordPolicy"
Write-Output "  Create Security Groups: $CreateSecurityGroups"

# Function to check if server is a domain controller
function Test-IsDomainController {
    $isDC = $false
    
    # Check domain role
    $dcRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
    if ($dcRole -eq 4 -or $dcRole -eq 5) {
        $isDC = $true
        Write-Output "✓ Server is a domain controller (role: $dcRole)"
    }
    
    # Additional check for AD DS service
    if (-not $isDC) {
        $addsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
        if ($addsService -and $addsService.Status -eq "Running") {
            $isDC = $true
            Write-Output "✓ Active Directory Domain Services is running"
        }
    }
    
    return $isDC
}

# Function to create organizational unit
function New-SafeOU {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Description
    )
    
    $ouDN = "OU=$Name,$Path"
    $existing = Get-ADOrganizationalUnit -Filter "Name -eq '$Name'" -SearchBase $Path -SearchScope OneLevel -ErrorAction SilentlyContinue
    
    if ($existing) {
        Write-Output "  $Name OU already exists"
        return $ouDN
    }
    
    New-ADOrganizationalUnit -Name $Name -Path $Path -Description $Description -ProtectedFromAccidentalDeletion $false
    Write-Output "  ✓ Created $Name OU"
    return $ouDN
}

# Function to create security group
function New-SafeGroup {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Description
    )
    
    $existing = Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
    
    if ($existing) {
        Write-Output "  $Name group already exists"
        return
    }
    
    New-ADGroup -Name $Name -GroupScope Global -GroupCategory Security -Path $Path -Description $Description
    Write-Output "  ✓ Created $Name security group"
}

# Function to create user
function New-SafeUser {
    param(
        [hashtable]$UserParams
    )
    
    $existing = Get-ADUser -Filter "SamAccountName -eq '$($UserParams.SamAccountName)'" -ErrorAction SilentlyContinue
    
    if ($existing) {
        Write-Output "  User $($UserParams.SamAccountName) already exists, skipping"
        return $false
    }
    
    New-ADUser @UserParams
    Write-Output "  ✓ Created user: $($UserParams.SamAccountName) ($($UserParams.DisplayName)) - $($UserParams.Department)"
    return $true
}

# Main execution
try {
    # Check if this is a domain controller
    Write-Output "Checking if this server is a domain controller..."
    if (-not (Test-IsDomainController)) {
        Write-Output "❌ This server is not a domain controller. Exiting."
        Write-Output "This artifact should only be run on domain controllers."
        exit 0
    }

    # Import Active Directory module
    Write-Output "Importing Active Directory module..."
    Import-Module ActiveDirectory -Force -ErrorAction Stop
    Write-Output "✓ Active Directory module imported successfully"

    # Get domain information
    $domain = Get-ADDomain -ErrorAction Stop
    $domainDN = $domain.DistinguishedName
    $domainName = $domain.DNSRoot
    Write-Output "✓ Domain: $domainName"
    Write-Output "✓ Domain DN: $domainDN"

    # Sample data arrays
    $firstNames = @("John", "Jane", "Michael", "Sarah", "David", "Emily", "Robert", "Lisa", "William", "Jennifer")
    $lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez")
    $departments = @("IT", "HR", "Finance", "Marketing", "Sales", "Operations", "Legal", "Research")
    
    $jobTitles = @{
        "IT" = @("System Administrator", "Network Engineer", "Software Developer", "Help Desk Technician", "Database Administrator")
        "HR" = @("HR Manager", "Recruiter", "HR Generalist", "Training Coordinator", "Benefits Administrator")
        "Finance" = @("Accountant", "Financial Analyst", "Controller", "CFO", "Accounts Payable Clerk")
        "Marketing" = @("Marketing Manager", "Content Creator", "Digital Marketing Specialist", "Brand Manager")
        "Sales" = @("Sales Representative", "Sales Manager", "Account Executive", "Business Development Manager")
        "Operations" = @("Operations Manager", "Process Analyst", "Operations Coordinator", "Supply Chain Manager")
        "Legal" = @("Legal Counsel", "Paralegal", "Compliance Officer", "Contract Manager")
        "Research" = @("Research Scientist", "Data Analyst", "Research Manager", "Lab Technician")
    }

    # Create Department OUs
    Write-Output "`n=== Creating Department Organizational Units ==="
    $selectedDepartments = $departments | Get-Random -Count $DepartmentCount
    $createdDepts = @()

    foreach ($dept in $selectedDepartments) {
        $ouDN = New-SafeOU -Name $dept -Path $domainDN -Description "$dept Department"
        $createdDepts += $dept
    }

    # Create Security Groups
    if ($CreateSecurityGroups) {
        Write-Output "`n=== Creating Security Groups ==="
        
        # Create department groups
        foreach ($dept in $createdDepts) {
            $groupName = "$dept-Users"
            $deptOU = "OU=$dept,$domainDN"
            New-SafeGroup -Name $groupName -Path $deptOU -Description "All users in $dept department"
        }

        # Create company-wide groups
        New-SafeGroup -Name "All-Employees" -Path $domainDN -Description "All company employees"
        New-SafeGroup -Name "Managers" -Path $domainDN -Description "All department managers"
        New-SafeGroup -Name "Remote-Workers" -Path $domainDN -Description "Employees working remotely"
        New-SafeGroup -Name "VPN-Users" -Path $domainDN -Description "Users with VPN access"
    }

    # Create Sample Users
    Write-Output "`n=== Creating Sample Users ==="
    $defaultPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
    $usersCreated = 0
    $usersPerDept = [math]::Floor($UserCount / $createdDepts.Count)
    $remainingUsers = $UserCount % $createdDepts.Count

    foreach ($dept in $createdDepts) {
        $deptOU = "OU=$dept,$domainDN"
        $currentDeptUsers = $usersPerDept
        if ($remainingUsers -gt 0) {
            $currentDeptUsers++
            $remainingUsers--
        }

        $deptTitles = $jobTitles[$dept]
        
        for ($i = 1; $i -le $currentDeptUsers; $i++) {
            $firstName = $firstNames | Get-Random
            $lastName = $lastNames | Get-Random
            $username = "$($firstName.Substring(0,1).ToLower())$($lastName.ToLower())$($usersCreated + 1)"
            $displayName = "$firstName $lastName"
            $email = "$username@$domainName"
            $jobTitle = $deptTitles | Get-Random
            
            $userParams = @{
                Name = $displayName
                DisplayName = $displayName
                GivenName = $firstName
                Surname = $lastName
                SamAccountName = $username
                UserPrincipalName = $email
                EmailAddress = $email
                Title = $jobTitle
                Department = $dept
                Company = "Contoso Corporation"
                Office = "$dept Department"
                Path = $deptOU
                AccountPassword = $defaultPassword
                Enabled = $true
                PasswordNeverExpires = $true
                ChangePasswordAtLogon = $false
            }

            $created = New-SafeUser -UserParams $userParams
            
            if ($created -and $CreateSecurityGroups) {
                # Add to groups
                Add-ADGroupMember -Identity "$dept-Users" -Members $username -ErrorAction SilentlyContinue
                Add-ADGroupMember -Identity "All-Employees" -Members $username -ErrorAction SilentlyContinue
                
                # Random group assignments
                if ((Get-Random -Maximum 100) -lt 30) {
                    Add-ADGroupMember -Identity "Remote-Workers" -Members $username -ErrorAction SilentlyContinue
                }
                if ((Get-Random -Maximum 100) -lt 40) {
                    Add-ADGroupMember -Identity "VPN-Users" -Members $username -ErrorAction SilentlyContinue
                }
                if ($jobTitle -like "*Manager*") {
                    Add-ADGroupMember -Identity "Managers" -Members $username -ErrorAction SilentlyContinue
                }
            }
            
            if ($created) {
                $usersCreated++
            }
        }
    }

    # Create Service Accounts
    if ($CreateServiceAccounts) {
        Write-Output "`n=== Creating Service Accounts ==="
        
        $serviceOU = New-SafeOU -Name "Service Accounts" -Path $domainDN -Description "Service and application accounts"

        $serviceAccounts = @(
            @{Name="svc-backup"; Description="Backup service account"},
            @{Name="svc-sql"; Description="SQL Server service account"},
            @{Name="svc-iis"; Description="IIS application pool account"}
        )

        foreach ($svcAccount in $serviceAccounts) {
            $svcParams = @{
                Name = $svcAccount.Name
                DisplayName = $svcAccount.Description
                SamAccountName = $svcAccount.Name
                UserPrincipalName = "$($svcAccount.Name)@$domainName"
                Description = $svcAccount.Description
                Path = $serviceOU
                AccountPassword = $defaultPassword
                Enabled = $true
                PasswordNeverExpires = $true
                CannotChangePassword = $true
            }

            $created = New-SafeUser -UserParams $svcParams
            if ($created) {
                Write-Output "  ✓ Created service account: $($svcAccount.Name)"
            }
        }
    }

    # Summary
    Write-Output "`n=== Summary Report ==="
    Write-Output "Domain: $domainName"
    Write-Output "Users created: $usersCreated"
    Write-Output "Departments: $($createdDepts -join ', ')"
    Write-Output "`nAll user passwords: P@ssw0rd123!"
    Write-Output "`n✅ Active Directory sample data population completed successfully!"
    
}
catch {
    Write-Error "❌ Failed to populate AD sample data: $($_.Exception.Message)"
    exit 1
}
finally {
    Stop-Transcript
}
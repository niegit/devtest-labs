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

try {
    # Check if this is a domain controller
    Write-Output "Checking if this server is a domain controller..."
    
    $isDC = $false
    try {
        $dcRole = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole
        # DomainRole 4 = Backup Domain Controller, 5 = Primary Domain Controller
        if ($dcRole -eq 4 -or $dcRole -eq 5) {
            $isDC = $true
            Write-Output "✓ Server is a domain controller"
        }
    }
    catch {
        Write-Output "Could not determine domain controller status via WMI"
    }

    # Additional check for AD DS service
    if (-not $isDC) {
        try {
            $addsService = Get-Service -Name "NTDS" -ErrorAction Stop
            if ($addsService.Status -eq "Running") {
                $isDC = $true
                Write-Output "✓ Active Directory Domain Services is running"
            }
        }
        catch {
            Write-Output "Active Directory Domain Services is not installed or running"
        }
    }

    if (-not $isDC) {
        Write-Output "❌ This server is not a domain controller. Exiting."
        Write-Output "This artifact should only be run on domain controllers."
        exit 0
    }

    # Import Active Directory module
    Write-Output "Importing Active Directory module..."
    try {
        Import-Module ActiveDirectory -Force -ErrorAction Stop
        Write-Output "✓ Active Directory module imported successfully"
    }
    catch {
        Write-Output "❌ Failed to import Active Directory module: $($_.Exception.Message)"
        exit 1
    }

    # Get domain information
    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        $domainName = $domain.DNSRoot
        Write-Output "✓ Domain: $domainName"
        Write-Output "✓ Domain DN: $domainDN"
    }
    catch {
        Write-Output "❌ Failed to get domain information: $($_.Exception.Message)"
        exit 1
    }

    # Sample data arrays
    $firstNames = @("John", "Jane", "Michael", "Sarah", "David", "Emily", "Robert", "Lisa", "William", "Jennifer", 
                   "James", "Amy", "Christopher", "Jessica", "Daniel", "Ashley", "Matthew", "Amanda", "Anthony", "Melissa",
                   "Mark", "Deborah", "Donald", "Stephanie", "Steven", "Dorothy", "Andrew", "Carol", "Joshua", "Ruth",
                   "Kenneth", "Sharon", "Paul", "Michelle", "Kevin", "Laura", "Brian", "Sarah", "George", "Kimberly",
                   "Edward", "Debra", "Ronald", "Rachel", "Timothy", "Carolyn", "Jason", "Janet", "Jeffrey", "Catherine")

    $lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
                  "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
                  "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
                  "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
                  "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts")

    $departments = @("IT", "HR", "Finance", "Marketing", "Sales", "Operations", "Legal", "Research")
    $jobTitles = @{
        "IT" = @("System Administrator", "Network Engineer", "Software Developer", "Help Desk Technician", "Database Administrator", "IT Manager", "Security Analyst")
        "HR" = @("HR Manager", "Recruiter", "HR Generalist", "Training Coordinator", "Benefits Administrator", "HR Director")
        "Finance" = @("Accountant", "Financial Analyst", "Controller", "CFO", "Accounts Payable Clerk", "Budget Analyst", "Finance Manager")
        "Marketing" = @("Marketing Manager", "Content Creator", "Digital Marketing Specialist", "Brand Manager", "Marketing Coordinator", "SEO Specialist")
        "Sales" = @("Sales Representative", "Sales Manager", "Account Executive", "Business Development Manager", "Sales Director", "Customer Success Manager")
        "Operations" = @("Operations Manager", "Process Analyst", "Operations Coordinator", "Supply Chain Manager", "Logistics Coordinator")
        "Legal" = @("Legal Counsel", "Paralegal", "Compliance Officer", "Contract Manager", "Legal Assistant")
        "Research" = @("Research Scientist", "Data Analyst", "Research Manager", "Lab Technician", "Research Coordinator")
    }

    # Create Department OUs
    Write-Output "`n=== Creating Department Organizational Units ==="
    $selectedDepartments = $departments | Get-Random -Count $DepartmentCount
    $createdDepts = @()

    foreach ($dept in $selectedDepartments) {
        try {
            $deptOU = "OU=$dept,$domainDN"
            
            # Check if OU already exists
            try {
                Get-ADOrganizationalUnit -Identity $deptOU -ErrorAction Stop | Out-Null
                Write-Output "  $dept OU already exists"
            }
            catch {
                New-ADOrganizationalUnit -Name $dept -Path $domainDN -Description "$dept Department" -ProtectedFromAccidentalDeletion $false
                Write-Output "  ✓ Created $dept OU"
            }
            
            $createdDepts += $dept
        }
        catch {
            Write-Output "  ❌ Failed to create $dept OU: $($_.Exception.Message)"
        }
    }

    # Create Security Groups (if enabled)
    if ($CreateSecurityGroups) {
        Write-Output "`n=== Creating Security Groups ==="
        foreach ($dept in $createdDepts) {
            try {
                $groupName = "$dept-Users"
                $groupOU = "OU=$dept,$domainDN"
                
                # Check if group already exists
                try {
                    Get-ADGroup -Identity $groupName -ErrorAction Stop | Out-Null
                    Write-Output "  $groupName group already exists"
                }
                catch {
                    New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Path $groupOU -Description "All users in $dept department"
                    Write-Output "  ✓ Created $groupName security group"
                }
            }
            catch {
                Write-Output "  ❌ Failed to create $groupName group: $($_.Exception.Message)"
            }
        }

        # Create additional security groups
        $additionalGroups = @(
            @{Name="All-Employees"; Description="All company employees"; Path=$domainDN},
            @{Name="Managers"; Description="All department managers"; Path=$domainDN},
            @{Name="Remote-Workers"; Description="Employees working remotely"; Path=$domainDN},
            @{Name="VPN-Users"; Description="Users with VPN access"; Path=$domainDN}
        )

        foreach ($group in $additionalGroups) {
            try {
                # Check if group already exists
                try {
                    Get-ADGroup -Identity $group.Name -ErrorAction Stop | Out-Null
                    Write-Output "  $($group.Name) group already exists"
                }
                catch {
                    New-ADGroup -Name $group.Name -GroupScope Global -GroupCategory Security -Path $group.Path -Description $group.Description
                    Write-Output "  ✓ Created $($group.Name) security group"
                }
            }
            catch {
                Write-Output "  ❌ Failed to create $($group.Name) group: $($_.Exception.Message)"
            }
        }
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
            try {
                # Generate unique username
                $firstName = $firstNames | Get-Random
                $lastName = $lastNames | Get-Random
                $username = "$($firstName.Substring(0,1).ToLower())$($lastName.ToLower())$($usersCreated + 1)"
                $displayName = "$firstName $lastName"
                $email = "$username@$domainName"
                $jobTitle = $deptTitles | Get-Random
                
                # Check if user already exists
                try {
                    Get-ADUser -Identity $username -ErrorAction Stop | Out-Null
                    Write-Output "  User $username already exists, skipping"
                    continue
                }
                catch {
                    # User doesn't exist, proceed to create
                }

                # Create user
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

                New-ADUser @userParams
                Write-Output "  ✓ Created user: $username ($displayName) - $dept"
                
                # Add to security groups
                if ($CreateSecurityGroups) {
                    try {
                        Add-ADGroupMember -Identity "$dept-Users" -Members $username -ErrorAction SilentlyContinue
                        Add-ADGroupMember -Identity "All-Employees" -Members $username -ErrorAction SilentlyContinue
                        
                        # Randomly add to additional groups
                        if ((Get-Random -Maximum 100) -lt 30) { # 30% chance
                            Add-ADGroupMember -Identity "Remote-Workers" -Members $username -ErrorAction SilentlyContinue
                        }
                        if ((Get-Random -Maximum 100) -lt 40) { # 40% chance
                            Add-ADGroupMember -Identity "VPN-Users" -Members $username -ErrorAction SilentlyContinue
                        }
                        if ($jobTitle -like "*Manager*" -or $jobTitle -like "*Director*") {
                            Add-ADGroupMember -Identity "Managers" -Members $username -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        Write-Output "    Warning: Could not add $username to some groups"
                    }
                }
                
                $usersCreated++
            }
            catch {
                Write-Output "  ❌ Failed to create user $username : $($_.Exception.Message)"
            }
        }
    }

    # Create Service Accounts (if enabled)
    if ($CreateServiceAccounts) {
        Write-Output "`n=== Creating Service Accounts ==="
        
        # Create Service Accounts OU
        $serviceOU = "OU=Service Accounts,$domainDN"
        try {
            Get-ADOrganizationalUnit -Identity $serviceOU -ErrorAction Stop | Out-Null
            Write-Output "  Service Accounts OU already exists"
        }
        catch {
            New-ADOrganizationalUnit -Name "Service Accounts" -Path $domainDN -Description "Service and application accounts" -ProtectedFromAccidentalDeletion $false
            Write-Output "  ✓ Created Service Accounts OU"
        }

        $serviceAccounts = @(
            @{Name="svc-backup"; Description="Backup service account"},
            @{Name="svc-sql"; Description="SQL Server service account"},
            @{Name="svc-iis"; Description="IIS application pool account"},
            @{Name="svc-monitoring"; Description="System monitoring service account"},
            @{Name="svc-reporting"; Description="Reporting services account"}
        )

        foreach ($svcAccount in $serviceAccounts) {
            try {
                $svcUsername = $svcAccount.Name
                
                # Check if service account already exists
                try {
                    Get-ADUser -Identity $svcUsername -ErrorAction Stop | Out-Null
                    Write-Output "  Service account $svcUsername already exists"
                    continue
                }
                catch {
                    # Service account doesn't exist, proceed to create
                }

                $svcParams = @{
                    Name = $svcUsername
                    DisplayName = $svcAccount.Description
                    SamAccountName = $svcUsername
                    UserPrincipalName = "$svcUsername@$domainName"
                    Description = $svcAccount.Description
                    Path = $serviceOU
                    AccountPassword = $defaultPassword
                    Enabled = $true
                    PasswordNeverExpires = $true
                    CannotChangePassword = $true
                }

                New-ADUser @svcParams
                Write-Output "  ✓ Created service account: $svcUsername"
            }
            catch {
                Write-Output "  ❌ Failed to create service account $svcUsername : $($_.Exception.Message)"
            }
        }
    }

    # Configure Fine-Grained Password Policy (if enabled)
    if ($EnablePasswordPolicy) {
        Write-Output "`n=== Configuring Password Policy ==="
        try {
            $policyName = "Standard-User-Policy"
            
            # Check if policy already exists
            try {
                Get-ADFineGrainedPasswordPolicy -Identity $policyName -ErrorAction Stop | Out-Null
                Write-Output "  Password policy $policyName already exists"
            }
            catch {
                $policyParams = @{
                    Name = $policyName
                    DisplayName = "Standard User Password Policy"
                    Description = "Standard password policy for regular users"
                    Precedence = 10
                    MinPasswordAge = "1.00:00:00"  # 1 day
                    MaxPasswordAge = "90.00:00:00" # 90 days
                    MinPasswordLength = 8
                    PasswordHistoryCount = 12
                    ComplexityEnabled = $true
                    ReversibleEncryptionEnabled = $false
                    LockoutDuration = "00:30:00"    # 30 minutes
                    LockoutObservationWindow = "00:30:00"
                    LockoutThreshold = 5
                }

                New-ADFineGrainedPasswordPolicy @policyParams
                
                # Apply to All-Employees group if it exists
                if ($CreateSecurityGroups) {
                    try {
                        Add-ADFineGrainedPasswordPolicySubject -Identity $policyName -Subjects "All-Employees"
                        Write-Output "  ✓ Created and applied password policy to All-Employees"
                    }
                    catch {
                        Write-Output "  ✓ Created password policy (could not apply to All-Employees group)"
                    }
                }
                else {
                    Write-Output "  ✓ Created password policy"
                }
            }
        }
        catch {
            Write-Output "  ❌ Failed to create password policy: $($_.Exception.Message)"
        }
    }

    # Generate summary report
    Write-Output "`n=== Summary Report ==="
    Write-Output "Domain: $domainName"
    Write-Output "Users created: $usersCreated"
    Write-Output "Departments: $($createdDepts -join ', ')"
    
    if ($CreateSecurityGroups) {
        try {
            $groupCount = (Get-ADGroup -Filter "Name -like '*-Users' -or Name -eq 'All-Employees' -or Name -eq 'Managers' -or Name -eq 'Remote-Workers' -or Name -eq 'VPN-Users'").Count
            Write-Output "Security groups: $groupCount"
        }
        catch {
            Write-Output "Security groups: Created (count unavailable)"
        }
    }
    
    if ($CreateServiceAccounts) {
        try {
            $svcCount = (Get-ADUser -Filter "Name -like 'svc-*'").Count
            Write-Output "Service accounts: $svcCount"
        }
        catch {
            Write-Output "Service accounts: Created (count unavailable)"
        }
    }

    Write-Output "`n=== Sample Credentials ==="
    Write-Output "All user passwords: P@ssw0rd123!"
    Write-Output "Sample users can be found in their respective department OUs"
    Write-Output "Service accounts are in the Service Accounts OU"
    
    Write-Output "`n✅ Active Directory sample data population completed successfully!"
    Write-Output "End Time: $(Get-Date)"

}
catch {
    Write-Error "❌ Failed to populate AD sample data: $($_.Exception.Message)"
    Write-Error $_.Exception.StackTrace
    exit 1
}
finally {
    Stop-Transcript
}
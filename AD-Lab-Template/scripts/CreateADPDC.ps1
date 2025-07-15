configuration CreateADPDC {
    param (
        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [int]$RetryCount = 20,
        [int]$RetryIntervalSec = 30
    )

    Import-DscResource -ModuleName xActiveDirectory, xStorage, xNetworking, PSDesiredStateConfiguration

    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($AdminCreds.UserName)", $AdminCreds.Password)

    Node localhost {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }

        WindowsFeature DNS {
            Ensure = "Present"
            Name = "DNS"
        }

        Script EnableDNSDiags {
            SetScript = {
                Set-DnsServerDiagnostics -All $true
                Write-Verbose -Verbose "Enabling DNS client diagnostics"
            }
            GetScript = { @{} }
            TestScript = { $false }
            DependsOn = "[WindowsFeature]DNS"
        }

        WindowsFeature DnsTools {
            Ensure = "Present"
            Name = "RSAT-DNS-Server"
            DependsOn = "[WindowsFeature]DNS"
        }

        xDnsServerAddress DnsServerAddress {
            Address = '127.0.0.1'
            InterfaceAlias = 'Ethernet'
            AddressFamily = 'IPv4'
            DependsOn = "[WindowsFeature]DNS"
        }

        WindowsFeature ADDSInstall {
            Ensure = "Present"
            Name = "AD-Domain-Services"
            DependsOn = "[WindowsFeature]DNS"
        }

        WindowsFeature ADDSTools {
            Ensure = "Present"
            Name = "RSAT-ADDS-Tools"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        xADDomain FirstDS {
            DomainName = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath = "C:\Windows\NTDS"
            LogPath = "C:\Windows\NTDS"
            SysvolPath = "C:\Windows\SYSVOL"
            DependsOn = @("[WindowsFeature]ADDSInstall", "[xDnsServerAddress]DnsServerAddress")
        }

        # Wait for AD to be ready
        xWaitForADDomain DscForestWait {
            DomainName = $DomainName
            DomainUserCredential = $DomainCreds
            RetryCount = $RetryCount
            RetryIntervalSec = $RetryIntervalSec
            DependsOn = "[xADDomain]FirstDS"
        }

        # Create additional OU structure
        xADOrganizationalUnit ServersOU {
            Name = "Servers"
            Path = "DC=$($DomainName.Replace('.', ',DC='))"
            ProtectedFromAccidentalDeletion = $true
            Description = "Servers Organizational Unit"
            Ensure = "Present"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        xADOrganizationalUnit WorkstationsOU {
            Name = "Workstations"
            Path = "DC=$($DomainName.Replace('.', ',DC='))"
            ProtectedFromAccidentalDeletion = $true
            Description = "Workstations Organizational Unit"
            Ensure = "Present"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        xADOrganizationalUnit UsersOU {
            Name = "Users"
            Path = "DC=$($DomainName.Replace('.', ',DC='))"
            ProtectedFromAccidentalDeletion = $true
            Description = "Users Organizational Unit"
            Ensure = "Present"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        # Create test users
        xADUser TestUser1 {
            DomainName = $DomainName
            UserName = "testuser1"
            Password = $DomainCreds
            DisplayName = "Test User 1"
            Path = "OU=Users,DC=$($DomainName.Replace('.', ',DC='))"
            PasswordNeverExpires = $true
            Ensure = "Present"
            DependsOn = "[xADOrganizationalUnit]UsersOU"
        }

        xADUser TestUser2 {
            DomainName = $DomainName
            UserName = "testuser2"
            Password = $DomainCreds
            DisplayName = "Test User 2"
            Path = "OU=Users,DC=$($DomainName.Replace('.', ',DC='))"
            PasswordNeverExpires = $true
            Ensure = "Present"
            DependsOn = "[xADOrganizationalUnit]UsersOU"
        }

        # Configure DNS forwarders
        Script SetConditionalForwardedZone {
            SetScript = {
                $ForwardDnsServer = '8.8.8.8'
                $zone = Get-DnsServerForwarder -ErrorAction SilentlyContinue
                if (-not $zone.IPAddress.Contains($ForwardDnsServer)) {
                    Write-Verbose -Verbose "Adding DNS forwarder to 8.8.8.8"
                    Add-DnsServerForwarder -IPAddress $ForwardDnsServer -PassThru
                }
            }
            GetScript = { @{} }
            TestScript = { 
                $ForwardDnsServer = '8.8.8.8'
                $zone = Get-DnsServerForwarder -ErrorAction SilentlyContinue
                return $zone.IPAddress.Contains($ForwardDnsServer)
            }
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        # Enable Advanced Windows Firewall Logging
        Script EnableFirewallLogging {
            SetScript = {
                netsh advfirewall set allprofiles logging droppedconnections enable
                netsh advfirewall set allprofiles logging allowedconnections enable
                Write-Verbose -Verbose "Enabled firewall logging"
            }
            GetScript = { @{} }
            TestScript = { $false }
        }

        # Install additional management tools
        WindowsFeature GPMC {
            Ensure = "Present"
            Name = "GPMC"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        WindowsFeature ADCSAdmin {
            Ensure = "Present"
            Name = "RSAT-ADCS-Mgmt"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }
    }
}
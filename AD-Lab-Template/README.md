# Active Directory Lab Environment for Azure DevTest Labs

This template creates a complete Active Directory lab environment with a domain controller and Windows 11 client that automatically joins the domain.

## Overview

**Components Deployed:**
- Windows Server 2022 Domain Controller (DC01)
- Windows 11 Professional Client (CLIENT01)
- Virtual Network with proper DNS configuration
- Active Directory Domain Services with test OUs and users
- Automatic domain join for client machine

## Prerequisites

1. Azure subscription with DevTest Labs enabled
2. Contributor or Owner access to the target resource group
3. Azure PowerShell modules installed (Az.Accounts, Az.Resources, Az.DevTestLabs)

## Quick Start

### Option 1: Azure Portal Deployment

1. Connect your template repository to your DevTest Lab:
   - Go to your DevTest Lab in Azure Portal
   - Navigate to Configuration and policies > Repository
   - Add a new repository pointing to your GitHub repo containing these templates

2. Deploy from DevTest Lab:
   - Go to My environment templates
   - Select "Active Directory Lab Environment"
   - Fill in parameters and deploy

### Option 2: PowerShell Deployment

```powershell
# Set your parameters
$params = @{
    SubscriptionId = "your-subscription-id"
    LabName = "MSP-Lab-001"
    ResourceGroupName = "rg-devtest-lab"
    DomainName = "testlab.local"
    AdminPassword = (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)
}

# Run deployment
.\Deploy-ADEnvironment.ps1 @params
```

### Option 3: ARM Template Direct Deployment

```bash
az deployment group create \
  --resource-group rg-devtest-lab \
  --template-file azuredeploy.json \
  --parameters azuredeploy.parameters.json
```

## File Structure

```
Templates/
├── azuredeploy.json              # Main ARM template
├── azuredeploy.parameters.json   # Default parameters
├── metadata.json                 # Template metadata for DevTest Labs
├── scripts/
│   ├── CreateADPDC.ps1          # PowerShell DSC for domain controller
│   └── JoinDomain.ps1           # Domain join script for client
├── Deploy-ADEnvironment.ps1     # PowerShell deployment script
└── README.md                    # This file
```

## Parameters

| Parameter | Description | Default Value |
|-----------|-------------|---------------|
| labName | Name of the DevTest Lab | MSP-Lab-001 |
| domainName | FQDN of the AD domain | testlab.local |
| adminUsername | Administrator username | labadmin |
| adminPassword | Administrator password | *(required)* |
| serverVmName | Domain controller VM name | DC01 |
| clientVmName | Windows 11 client VM name | CLIENT01 |
| vmSize | VM size for both machines | Standard_D2s_v3 |

## Security Notes

⚠️ **Important Security Considerations:**

1. **Passwords**: Change default passwords before deployment
2. **Network Access**: VMs are accessible via RDP through DevTest Lab's shared IP
3. **Auto-shutdown**: Configure auto-shutdown policies to control costs
4. **Cleanup**: Delete environments when testing is complete

## Test Accounts Created

The template automatically creates:

**Domain Users:**
- testuser1@[domain] (password same as admin)
- testuser2@[domain] (password same as admin)

**Local Account on Client:**
- LocalTestUser (password: LocalUser123!)

## Organizational Units Created

- Servers OU
- Workstations OU  
- Users OU

## Deployment Timeline

| Step | Duration | Description |
|------|----------|-------------|
| 1 | 2-3 mins | VM provisioning |
| 2 | 8-12 mins | Domain controller promotion |
| 3 | 2-3 mins | Windows 11 client setup |
| 4 | 1-2 mins | Domain join process |
| **Total** | **15-20 mins** | Complete environment |

## Troubleshooting

### Common Issues

**Domain Join Fails:**
- Check DNS settings on client VM
- Verify domain controller is fully promoted
- Check network connectivity between VMs

**Cannot Connect to VMs:**
- Ensure VMs are started in DevTest Lab
- Check RDP connectivity through lab's shared IP
- Verify firewall settings

**Domain Controller Promotion Fails:**
- Check PowerShell DSC logs in `C:\WindowsAzure\Logs`
- Verify sufficient resources (RAM/CPU)
- Check for Windows Updates conflicts

### Log Locations

**Domain Controller:**
- DSC Logs: `C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC\`
- AD Logs: Event Viewer > Applications and Services Logs > Directory Service

**Windows 11 Client:**
- Domain Join Log: `C:\Windows\Temp\DomainJoin.log`
- Custom Script Extension: `C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\`

## Customization

### Adding More Users
Edit the `CreateADPDC.ps1` file and add additional `xADUser` resources.

### Changing VM Sizes
Modify the `vmSize` parameter in `azuredeploy.parameters.json`.

### Additional Software
Add software installation commands to the `JoinDomain.ps1` script.

## Cost Optimization

- Use B-series VMs for lower costs during testing
- Configure auto-shutdown policies
- Set up cost alerts in Azure
- Delete environments when not in use

## Support

For issues with this template:
1. Check the troubleshooting section above
2. Review Azure DevTest Labs documentation
3. Check Azure Activity Log for deployment errors
4. Contact your MSP administrator

## Version History

- v1.0 - Initial release with Windows Server 2022 and Windows 11
- Supports standard DevTest Lab features
- Automated domain join and OU structure creation

---

**Note**: This template is designed for testing and training purposes. Do not use in production environments without proper security hardening.
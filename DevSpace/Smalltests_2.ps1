$Script:RoleToFind = ""
$Script:Roles = ""

import-module ActiveDirectory
function CheckServerRoles {

    $Private:WonderwareRolesList = "WW17GR;WW17IDE;WW17AOS;WW17OI;WW17IT;WW17HIS;WW17HIC;WW17AIOG;WW17AIOH;WW20GR;WW20IDE;WW20AOS;WW20OI;WW20IT;WW20HIS;WW20HIC;WW20AIOG;WW20AIOH;WW20AIOHM;WW20AIOGM"
    $Private:ThinmanagerDisRolesList = "RSTMGR11DIS;RSTMGR12DIS;RSTMGR13DIS"
    $Private:ThinManagerSrvRolesList = "RSTMGR11SRV;RSTMGR12SRV;RSTMGR13SRV"
    $Private:RockwellSrvInfRolesList = "RSFTAC11SRV;RSFTAC13SRV;RSFTAC11INF;RSFTAC13INF"
    $Private:RockwellDevRolesList = "RSFTAC11Dev;RSFTAC13Dev"
    $Private:DmoRolesList = "FEATDMO1RDN;FEATDMO1Std;DMO2RDN;DMO22RDN;DMO2ARCSTD;Dmo22ArcStd;Dmo22Std"

    $Private:WonderwareRoles = $Private:WonderwareRolesList.Split(";")
    $Private:ThinManagerDisRoles = $Private:ThinmanagerDisRolesList.Split(";")
    $Private:ThinManagerSrvRoles = $Private:ThinManagerSrvRolesList.Split(";")
    $Private:RockwellSrvInfRoles = $Private:RockwellSrvInfRolesList.Split(";")
    $Private:RockwellDevRoles = $Private:RockwellDevRolesList.Split(";")
    $Private:DmoRoles = $Private:DmoRolesList.Split(";")

    $Private:AdGroupAdministrators = @("Nestle\CHORNWWAdministrators", "Nestle\CHAVEWWAdministrators", "Nestle\CHROMWWAdministrators")
    $Private:AdGroupRemoteDesktopUsers = @("CHORNTMRemoteDesktopusers", "CHAVETMRemoteDesktopusers", "CHROMTMRemoteDesktopusers")

    # Check Role List extracted from server one by one
    foreach ($Private:RoleFromServer in $Script:RolesFromServer) {
        $Private:Found = $false
        
        # Check Wonderware Role List one by one
        foreach ($Private:WonderwareRole in $Private:WonderwareRoles) {
           
            # Check if Role extracted from server corresponds to Wonderware Role
            if ($Private:RoleFromServer -eq $Private:WonderwareRole) {
                $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"
                
                # Check each member of the specified local group
                foreach ($Private:MemberLocalGroup in $Private:LocalGroupMembers){ 
                    if($Private:AdGroupAdministrators -contains $Private:MemberLocalGroup.Name){
                        $Private:Found = $true
                    }else{
                        # To Define ( How do we choose which factory group we add )
                    }
                }
            }
        }
        
        # Check ThinManagerDis Role List one by one
        foreach ($Private:ThinManagerRole in $Private:ThinManagerDisRoles) {
           
            # Check if Role extracted from server corresponds to Wonderware Role
            if ($Private:RoleFromServer -eq $Private:ThinManagerRole) {
                $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Remote Desktop Users"
                
                # Check each member of the specified local group
                foreach ($Private:MemberLocalGroup in $Private:LocalGroupMembers){ 
                    if($Private:MemberLocalGroup.Name -eq "Nestle\$Private:AdGroupRemoteDesktopUsers"){
                        $Private:Found = $true
                        Write-Host $Private:MemberLocalGroup.Name
                    }
                }
            }
        }
    }
}

function CheckRegistryKey {
    $Private:RegistryKey = "HKLM:\SOFTWARE\Nestle\"
    $Private:RegistryValueName = "Roles"

    $Private:RegistryValue = Get-ItemPropertyValue -Path $Private:RegistryKey -Name $Private:RegistryValueName

    if ([string]::IsNullOrEmpty($Private:RegistryValue)) {
        Write-Host "Error: Registry Key value is empty or null"
    } else {
        $Script:RolesFromServer = $Private:RegistryValue.Split("#")
        Write-Host "Role Values:"
        CheckServerRoles
    }
}

CheckRegistryKey
pause
pause
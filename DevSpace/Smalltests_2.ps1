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
    $Private:ThinmanagerDisRoles = $Private:ThinmanagerDisRolesList.Split(";")
    $Private:ThinManagerSrvRoles = $Private:ThinManagerSrvRolesList.Split(";")
    $Private:RockwellSrvInfRoles = $Private:RockwellSrvInfRolesList.Split(";")
    $Private:RockwellDevRoles = $Private:RockwellDevRolesList.Split(";")
    $Private:DmoRoles = $Private:DmoRolesList.Split(";")

    $Private:AdGroupAdministrators = "CHORNWWAdministrators"
    $Private:AdGroupRemoteDesktopUsers = "CH*WWAdministrators"

    foreach ($Private:RoleFromServer in $Script:RolesFromServer) {
        $Private:Found = $false
        foreach ($Private:WonderwareRole in $Private:WonderwareRoles) {
           
            if ($Private:RoleFromServer -eq $Private:WonderwareRole) {
                $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"
                
                foreach ($Private:MemberLocalGroup in $Private:LocalGroupMembers){ 
                    if($Private:MemberLocalGroup.Name -eq "NESTLE\ChornWWAdministrators"){
                        $Private:Found = $true
                        break
                    }else{
                        Write-Host "Group CHORNWWADMINISTRATORS NOT FOUND"
                    }
                }
            }
        }
    }
}

function RegistryKeyCheck {
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

RegistryKeyCheck
pause
pause
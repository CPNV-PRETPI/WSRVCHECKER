param(
    
    [Parameter(Mandatory=$true)]
    [string]$ExecutionPolicy,

    [Parameter(Mandatory=$true)]
    [string]$FactoryAbbreviation
    )
    
#region Variables
    $Script:ExecutionPolicy = $ExecutionPolicy
    $Script:FactoryAbbreviation = $FactoryAbbreviation
    $Script:RolesFromServer = ""
    $Script:LogFile = "C:\Temp\Scripts\RegistryKey\RegistryKeyErrors.log"
#endregion

#region Functions

#
function WriteLog{
    param (
        [Parameter(Mandatory=$false)]
        [string]$Private:Message
    )

    $Private:TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Private:LogMessage = "$Private:TimeStamp - $Private:Message"

    if(!(Test-Path $Script:LogFile)){
        try{
            New-Item $Script:LogFile -ItemType File | Out-Null
        }catch{
            WriteLog "WriteLog: LogFile is inaccessible"
        }
    }
    
    if(!([string]::IsNullOrEmpty($Private:Message))){
        Add-Content -Path $Script:LogFile -Value $Private:LogMessage
    }
}

# Check ExecutionPolicy
function CheckExecutionPolicy{
    # Check Executionpolicy
    if($Script:ExecutionPolicy -ne "Bypass"){
        WriteLog "Rights: Script ONLY runs with the ExecutionPolicy 'Bypass'!"
        Exit 
    }else{
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy $Script:ExecutionPolicy -Force
    }
}

# Check Privilieges
function CheckAdminRights {
    $Private:IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    If (-Not $Private:IsAdmin) {
        WriteLog "Rights: Script is NOT running with Administrators priviledges!"
        Exit 
    }
}

function CheckServerRoles {

    # Definition of the lists of potential roles
    $Private:WonderwareRolesList = "WW17GR;WW17IDE;WW17AOS;WW17OI;WW17IT;WW17HIS;WW17HIC;WW17AIOG;WW17AIOH;WW20GR;WW20IDE;WW20AOS;WW20OI;WW20IT;WW20HIS;WW20HIC;WW20AIOG;WW20AIOH;WW20AIOHM;WW20AIOGM"
    $Private:ThinmanagerDisRolesList = "RSTMGR11DIS;RSTMGR12DIS;RSTMGR13DIS"
    $Private:ThinManagerSrvRolesList = "RSTMGR11SRV;RSTMGR12SRV;RSTMGR13SRV"
    $Private:RockwellSrvInfRolesList = "RSFTAC11SRV;RSFTAC13SRV;RSFTAC11INF;RSFTAC13INF"
    $Private:RockwellDevRolesList = "RSFTAC11Dev;RSFTAC13Dev"
    $Private:DmoRolesList = "FEATDMO1RDN;FEATDMO1Std;DMO2RDN;DMO22RDN;DMO2ARCSTD;Dmo22ArcStd;Dmo22Std"

    # Definition of the separator of the list
    $Private:WonderwareRoles = $Private:WonderwareRolesList.Split(";")
    $Private:ThinManagerDisRoles = $Private:ThinmanagerDisRolesList.Split(";")
    $Private:ThinManagerSrvRoles = $Private:ThinManagerSrvRolesList.Split(";")
    $Private:RockwellSrvInfRoles = $Private:RockwellSrvInfRolesList.Split(";")
    $Private:RockwellDevRoles = $Private:RockwellDevRolesList.Split(";")
    $Private:DmoRoles = $Private:DmoRolesList.Split(";")

    #region Factory AD groups
    # Wonderware
    $Private:AdGroupWwAdministratorsChorn = "Nestle\CHORNWWAdministrators"
    $Private:AdGroupWwAdministratorsChrom = "Nestle\CHROMWWAdministrators"
    $Private:AdGroupWwAdministratorsChave = "Nestle\CHAVEWWAdministrators"

    # Thinmanager
    $Private:AdGroupRemoteDesktopUsersChorn = "Nestle\CHORNTMRemoteDesktopusers"
    $Private:AdGroupRemoteDesktopUsersChrom = "Nestle\CHROMTMRemoteDesktopusers"
    $Private:AdGroupRemoteDesktopUsersChave = "Nestle\CHAVETMRemoteDesktopusers"

    $Private:AdGroupTmAdministratorsChorn = "Nestle\CHORNTMAdministrators"
    $Private:AdGroupTmAdministratorsChrom = "Nestle\CHROMTMAdministrators"
    $Private:AdGroupTmAdministratorsChave = "Nestle\CHAVETMAdministrators"

    $Private:AdGroupTmInteractiveShadowUsersChorn = "Nestle\CHORNTMInteractiveShadowUsers"
    $Private:AdGroupTmInteractiveShadowUsersChrom = "Nestle\CHROMTMInteractiveShadowUsers"
    $Private:AdGroupTmInteractiveShadowUsersChave = "Nestle\CHAVETMInteractiveShadowUsers"
    
    $Private:AdGroupTmPowerUsersChorn = "Nestle\CHORNTMPowerUsers"
    $Private:AdGroupTmPowerUsersChrom = "Nestle\CHROMTMPowerUsers"
    $Private:AdGroupTmPowerUsersChave = "Nestle\CHAVETMPowerUsers"
    
    $Private:AdGroupTmShadowUsersChorn = "Nestle\CHORNTMShadowUsers"
    $Private:AdGroupTmShadowUsersChrom = "Nestle\CHROMTMShadowUsers"
    $Private:AdGroupTmShadowUsersChave = "Nestle\CHAVETMShadowUsers"

    $Private:AdGroupTmUsersChorn = "Nestle\CHORNTMUsers"
    $Private:AdGroupTmUsersChrom = "Nestle\CHROMTMUsers"
    $Private:AdGroupTmUsersChave = "Nestle\CHAVETMUsers"

    # Rockwell
    $Private:AdGroupFtAdministratorsChorn = "Nestle\CHORNFTAdministrators"
    $Private:AdGroupFtAdministratorsChrom = "Nestle\CHROMFTAdministrators"
    $Private:AdGroupFtAdministratorsChave = "Nestle\CHAVEFTAdministrators"

    $Private:AdGroupFtDevelopersChorn = "Nestle\CHORNFTDevelopers"
    $Private:AdGroupFtDevelopersChrom = "Nestle\CHROMFTDevelopers"
    $Private:AdGroupFtDevelopersChave = "Nestle\CHAVEFTDevelopers"

    $Private:AdGroupLmsUsersChorn = "Nestle\CHORNLMSusers"
    $Private:AdGroupLmsUsersChrom = "Nestle\CHROMLMSusers"
    $Private:AdGroupLmsUsersChave = "Nestle\CHAVELMSusers"

    $Private:AdGroupFtEngineerChorn = "Nestle\CHORNFTEngineer"
    $Private:AdGroupFtEngineerChrom = "Nestle\CHROMFTEngineer"
    $Private:AdGroupFtEngineerChave = "Nestle\CHAVEFTEngineer"

    $Private:AdGroupFtMaintainersChorn = "Nestle\CHORNFTMaintainers"
    $Private:AdGroupFtMaintainersChrom = "Nestle\CHROMFTMaintainers"
    $Private:AdGroupFtMaintainersChave = "Nestle\CHAVEFTMaintainers"

    # DMO
    $Private:AdGroupDmoAdministratorsChorn = "Nestle\CHORNDMOAdministrators"
    $Private:AdGroupDmoAdministratorsChrom = "Nestle\CHROMDMOAdministrators"
    $Private:AdGroupDmoAdministratorsChave = "Nestle\CHAVEDMOAdministrators"

    #endregion
    # Check Role List extracted from server one by one
    
    $Private:Found = $false
    do{
        foreach ($Private:RoleFromServer in $Script:RolesFromServer) {
            
            foreach ($Private:WonderwareRole in $Private:WonderwareRoles) {
                
                # Check if Role extracted from server corresponds to one of Wonderware Roles
                if ($Private:WonderwareRole -eq $Private:RoleFromServer) {
                    $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"
                    try{
                        if($Script:FactoryAbbreviation -eq "CHORN"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupWWAdministratorsChorn)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupWWAdministratorsChorn -ErrorAction Stop 
                            }   
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupWWAdministratorsChave)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupWWAdministratorsChave -ErrorAction Stop 
                            }   
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupWWAdministratorsChrom)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupWWAdministratorsChrom -ErrorAction Stop 
                            }   
                        }
                    }catch{
                        $Private:Found = $true
                    }
                }
            }

            foreach ($Private:ThinManagerDisRole in $Private:ThinManagerDisRoles) {
                
                # Check if Role extracted from server corresponds to one of Thinmanager DIS Roles
                if ($Private:ThinManagerDisRole -eq $Private:RoleFromServer) {
                    $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Remote Desktop Users"
                    try{
                        if($Script:FactoryAbbreviation -eq "CHORN"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupRemoteDesktopUsersChorn)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupRemoteDesktopUsersChorn -ErrorAction Stop 
                            }   
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupRemoteDesktopUsersChave)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupRemoteDesktopUsersChave -ErrorAction Stop 
                            }   
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupRemoteDesktopUsersChrom)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupRemoteDesktopUsersChrom -ErrorAction Stop 
                            }   
                        }
                    }catch{
                        $Private:Found = $true
                    }
                }
            }

            foreach ($Private:ThinManagerSrvRole in $Private:ThinManagerSrvRoles) {
                
                # Check if Role extracted from server corresponds to one of Thinmanager SRV Roles
                if ($Private:ThinManagerSrvRole -eq $Private:RoleFromServer) {
                    $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"
                    try{
                        if($Script:FactoryAbbreviation -eq "CHORN"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmAdministratorsChorn)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupTmAdministratorsChorn -ErrorAction Stop 
                            }   
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmAdministratorsChave)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupTmAdministratorsChave -ErrorAction Stop 
                            }   
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmAdministratorsChrom)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupTmAdministratorsChrom -ErrorAction Stop 
                            }   
                        }

                    }catch{
                        $Private:Found = $true
                    }
                }
            }

            foreach ($Private:ThinManagerSrvRole in $Private:ThinManagerSrvRoles) {
                
                # Check if Role extracted from server corresponds to one of Thinmanager SRV Roles
                if ($Private:ThinManagerSrvRole -eq $Private:RoleFromServer) {
                    $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Remote Desktop Users"
                    try{
                        if($Script:FactoryAbbreviation -eq "CHORN"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmInteractiveShadowUsersChorn)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmInteractiveShadowUsersChorn -ErrorAction Stop 
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmPowerUsersChorn)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmInteractivePowerUsersChorn -ErrorAction Stop 
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmShadowUsersChorn)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmInteractivePowerUsersChorn -ErrorAction Stop 
                            } 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmUsersChorn)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmInteractivePowerUsersChorn -ErrorAction Stop 
                            }  
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmInteractiveShadowUsersChave)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmInteractiveShadowUsersChave -ErrorAction Stop 
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmPowerUsersChave)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmPowerUsersChave -ErrorAction Stop 
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmShadowUsersChave)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmInteractivePowerUsersChave -ErrorAction Stop 
                            } 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmUsersChave)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmInteractivePowerUsersChave -ErrorAction Stop 
                            } 
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmInteractiveShadowUsersChrom)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmInteractiveShadowUsersChrom -ErrorAction Stop 
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmPowerUsersChrom)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmPowerUsersChrom -ErrorAction Stop 
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmShadowUsersChrom)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmInteractivePowerUsersChrom -ErrorAction Stop 
                            } 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmUsersChrom)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupTmInteractivePowerUsersChrom -ErrorAction Stop 
                            }  
                        }

                    }catch{
                        $Private:Found = $true
                    }
                }
            }
            
            foreach ($Private:RockwellSrvInfRole in $Private:RockwellSrvInfRoles) {
                
                # Check if Role extracted from server corresponds to one of Rockwell SRV or INF Roles
                if ($Private:RockwellSrvInfRole -eq $Private:RoleFromServer) {
                    $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"
                    try{
                        if($Script:FactoryAbbreviation -eq "CHORN"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChorn)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupFtAdministratorsChorn -ErrorAction Stop 
                            } 
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChave)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupFtAdministratorsChave -ErrorAction Stop 
                            }  
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChrom)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupFtAdministratorsChrom -ErrorAction Stop 
                            }   
                        }
                    }catch{
                        $Private:Found = $true
                    }
                }
            }

            foreach ($Private:RockwellDevRole in $Private:RockwellDevRoles) {
                
                # Check if Role extracted from server corresponds to one of Rockwell SRV or INF Roles
                if ($Private:RockwellDevRole -eq $Private:RoleFromServer) {
                    $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"
                    try{
                        if($Script:FactoryAbbreviation -eq "CHORN"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChorn)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupFtAdministratorsChorn -ErrorAction Stop 
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChorn)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupFtDevelopersChorn -ErrorAction Stop 
                            }   
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChave)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupFtAdministratorsChave -ErrorAction Stop 
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChave)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupFtDevelopersChave -ErrorAction Stop 
                            }      
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChrom)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupFtAdministratorsChrom -ErrorAction Stop 
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChrom)){
                                Add-LocalGroupMember -Group "Administrators" -Member $Private:AdGroupFtDevelopersChrom -ErrorAction Stop 
                            }
                        }
                    }catch{
                        $Private:Found = $true
                    }
                }
            }

            foreach ($Private:RockwellDevRole in $Private:RockwellDevRoles) {
                
                # Check if Role extracted from server corresponds to one of Rockwell SRV or INF Roles
                if ($Private:RockwellDevRole -eq $Private:RoleFromServer) {
                    $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Remote Desktop Users"
                    try{
                        if($Script:FactoryAbbreviation -eq "CHORN"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChorn)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupLmsUsersChorn -ErrorAction Stop 
                            } 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChorn)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupFtEngineerChorn -ErrorAction Stop 
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChorn)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupFtMaintainersChorn -ErrorAction Stop 
                            }   
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChave)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupLmsUsersChave -ErrorAction Stop 
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChave)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupFtEngineerChave -ErrorAction Stop 
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChave)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupFtMaintainersChave -ErrorAction Stop 
                            }      
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChrom)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupLmsUsersChrom -ErrorAction Stop 
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChrom)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupFtEngineerChrom -ErrorAction Stop 
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChrom)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupFtMaintainersChrom -ErrorAction Stop 
                            } 
                        }
                    }catch{
                        $Private:Found = $true
                    }
                }
            }

            foreach ($Private:DmoRole in $Private:DmoRoles) {
                
                # Check if Role extracted from server corresponds to one of Rockwell SRV or INF Roles
                if ($Private:DmoRole -eq $Private:RoleFromServer) {
                    $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"
                    try{
                        if($Script:FactoryAbbreviation -eq "CHORN"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupDmoAdministratorsChorn)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupDmoAdministratorsChorn -ErrorAction Stop 
                            }  
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupDmoAdministratorsChave)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupDmoAdministratorsChave -ErrorAction Stop 
                            }   
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupDmoAdministratorsChrom)){
                                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Private:AdGroupDmoAdministratorsChrom -ErrorAction Stop 
                            }   
                        }
                    }catch{
                        $Private:Found = $true
                    }
                }
            }
        }
    }while($Private:Found -eq $false)
        
}

function CheckRegistryKey {
    $Private:RegistryKey = "HKLM:\SOFTWARE\Nestle\"
    $Private:RegistryValueName = "Roles"

    $Private:RegistryValue = Get-ItemPropertyValue -Path $Private:RegistryKey -Name $Private:RegistryValueName

    if ([string]::IsNullOrEmpty($Private:RegistryValue)) {
        WriteLog "CheckRegistryKey: Registry Key value is empty or null"
    } else {
        $Script:RolesFromServer = $Private:RegistryValue.Split("#")
        CheckServerRoles
    }
}

#endregion

#region Main

WriteLog
CheckExecutionPolicy
CheckAdminRights
CheckRegistryKey
pause
pause

#endregion
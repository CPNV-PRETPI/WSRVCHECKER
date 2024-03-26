#Requires -Version 5.1
<#
.SYNOPSIS
    CheckRegistryKey
 
.DESCRIPTION
    The script objective is to check the registry key that contains the roles of a server and check those results to see if some AD groups are indeed in some local groups on the server

.PARAMETER ExecutionPolicy
    Bypass

.PARAMETER OutputFolder
    C:\Temp\Scripts\ActiveDirectory\
 
.EXAMPLE
    powershell.exe .\\CheckRegistryKey.ps1 -ExecutionPolicy Bypass -OutputFolder C:\Temp\Scripts\RegistryKey\ -FactoryAbbreviation "CHORN" -OutputFolder 
#>

param(
    
    [Parameter(Mandatory=$true)]
    [string]$ExecutionPolicy,

    [Parameter(Mandatory=$true)]
    [string]$FactoryAbbreviation,

    [Parameter(Mandatory=$true)]
    [string]$OutputFolder
    )
    
#region Variables
    $Script:ExecutionPolicy = $ExecutionPolicy
    $Script:FactoryAbbreviation = $FactoryAbbreviation
    $Script:OutputFolder = $OutputFolder
    $Script:Data = ""
    $Script:RolesFromServer = ""
    $Script:MachineName = Hostname
    $Script:LogFile = "C:\Temp\Scripts\RegistryKey\RegistryKeyErrors.log"
    $Script:TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
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

# Check if OutputFolder parameter exists and is accessible
function CheckCsvOutputFolder{
    if(!(Test-Path $Script:OutputFolder))
    {
        WriteLog "CsvOutputFolder: Outputfolder path is inaccessible"
        Exit
    }
}

function GetCsvData{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Private:DataForCsv
    )

    $Script:Data = @" 
        RoleFromServer;AdGroup;LocalGroup;Validation  
"@

    $Script:Data += @"
        $Private:DataForCsv
"@  
    Write-Host $Private:DataForCsv
}

# Extract all data to a .zip file
function ExtractData{
    # Get the data
    CheckCsvOutputFolder
    Write-Host $Script:Data

    # Converts data to an object
    $Private:PSObject = $Script:Data | ConvertFrom-Csv

    # Export the data object to a CSV file
    $Private:PSObject | Export-Csv -Path "$Script:OutputFolder\$Script:TimeStamp.csv" -NoTypeInformation

    # Define the .zip file name
    $Private:ZipFolderName = "$($Script:MachineName)_$Script:TimeStamp.zip"
    
    # Compress files to a .zip folder
    
    Compress-Archive -Path "$Script:OutputFolder\$Script:TimeStamp.csv",$Script:LogFile,$Script:InputFile -DestinationPath "$Script:OutputFolder\$Private:ZipFolderName"

    # Delete original files
    Remove-Item -Path $Script:LogFile 
    Remove-Item -Path "$Script:OutputFolder\$Script:TimeStamp.csv" 
    # Remove-Item -Path "$Script:InputFile" -Force
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
            
            foreach ($Private:WonderwareRole in $Private:WonderwareRolesList.Split(";")) {
                
                # Check if Role extracted from server corresponds to one of Wonderware Roles
                if ($Private:WonderwareRole -eq $Private:RoleFromServer) {
                    
                    $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"
                    try{
                        if($Script:FactoryAbbreviation -eq "CHORN"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupWWAdministratorsChorn)){
                                Write-Host "false"
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupWWAdministratorsChorn;Administrators;false"
                                
                            }else{
                                Write-Host "true"
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupWWAdministratorsChorn;Administrators;true"
                                $Private:LocalGroupMembers = $Private:LocalGroupMembers | Where-Object { $_ -ne $Private:RoleFromServer }
                            }  
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupWWAdministratorsChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupWWAdministratorsChave;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupWWAdministratorsChave;Administrators;true"
                            }   
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupWWAdministratorsChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupWWAdministratorsChrom;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupWWAdministratorsChrom;Administrators;true"
                            }
                        }

                        $Private:RoleFromServer = $Private:RoleFromServer | Where-Object { $_ -ne $Private:RoleFromServer }
                        CheckServerRoles
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
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupRemoteDesktopUsersChorn;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupRemoteDesktopUsersChorn;Remote Desktop Users;true"
                            }   
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupRemoteDesktopUsersChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupRemoteDesktopUsersChave;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupRemoteDesktopUsersChave;Remote Desktop Users;true"
                            }   
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupRemoteDesktopUsersChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupRemoteDesktopUsersChrom;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupRemoteDesktopUsersChrom;Remote Desktop Users;true"
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
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmAdministratorsChorn;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmAdministratorsChorn;Administrators;true"
                            }   
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmAdministratorsChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmAdministratorsChave;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmAdministratorsChave;Administrators;true"
                            }   
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmAdministratorsChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmAdministratorsChrom;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmAdministratorsChrom;Administrators;true"
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
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmInteractiveShadowUsersChorn;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmInteractiveShadowUsersChorn;Remote Desktop Users;true"
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmPowerUsersChorn)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmPowerUsersChorn;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmPowerUsersChorn;Remote Desktop Users;true"
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmShadowUsersChorn)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmShadowUsersChorn;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmShadowUsersChorn;Remote Desktop Users;true"
                            } 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmUsersChorn)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmUsersChorn;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmUsersChorn;Remote Desktop Users;true"
                            }  
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmInteractiveShadowUsersChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmInteractiveShadowUsersChave;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmInteractiveShadowUsersChave;Remote Desktop Users;true"
                            } 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmPowerUsersChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmPowerUsersChave;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmPowerUsersChave;Remote Desktop Users;true"
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmShadowUsersChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmShadowUsersChave;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmShadowUsersChave;Remote Desktop Users;true"
                            } 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmUsersChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmUsersChave;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmUsersChave;Remote Desktop Users;true"
                            } 
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmInteractiveShadowUsersChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmInteractiveShadowUsersChrom;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmInteractiveShadowUsersChrom;Remote Desktop Users;true"
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmPowerUsersChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmPowerUsersChrom;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmPowerUsersChrom;Remote Desktop Users;true"
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmShadowUsersChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmShadowUsersChrom;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmShadowUsersChrom;Remote Desktop Users;true"
                            } 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupTmUsersChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmUsersChrom;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupTmUsersChrom;Remote Desktop Users;true"
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
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChorn;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChorn;Administrators;true"
                            } 
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChave;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChave;Administrators;true"
                            }  
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChrom;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChrom;Administrators;true"
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
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChorn;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChorn;Administrators;true"
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChorn)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChorn;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChorn;Administrators;true"
                            }   
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChave;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChave;Administrators;true"
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChave;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChave;Administrators;true"
                            }      
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChrom;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChrom;Administrators;true"
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChrom;Administrators;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChrom;Administrators;true"
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
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChorn;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChorn;Remote Desktop Users;true"
                            } 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChorn)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChorn;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChorn;Remote Desktop Users;true"
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChorn)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChorn;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChorn;Remote Desktop Users;true"
                            }   
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChave;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChave;Remote Desktop Users;true"
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChave;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChave;Remote Desktop Users;true"
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChave;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChave;Remote Desktop Users;true"
                            }     
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChrom;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChrom;Remote Desktop Users;true"
                            }   
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtAdministratorsChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChrom;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtAdministratorsChrom;Remote Desktop Users;true"
                            }
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupFtDevelopersChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChrom;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupFtDevelopersChrom;Remote Desktop Users;true"
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
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupDmoAdministratorsChorn;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupDmoAdministratorsChorn;Remote Desktop Users;true"
                            }  
                        }       
    
                        if($Script:FactoryAbbreviation -eq "CHAVE"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupDmoAdministratorsChave)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupDmoAdministratorsChave;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupDmoAdministratorsChave;Remote Desktop Users;true"
                            }    
                        }

                        if($Script:FactoryAbbreviation -eq "CHROM"){ 
                            if(!($Private:LocalGroupMembers -contains $Private:AdGroupDmoAdministratorsChrom)){
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupDmoAdministratorsChrom;Remote Desktop Users;false"
                            }else{
                                GetCsvData "$Private:RoleFromServer;$Private:AdGroupDmoAdministratorsChrom;Remote Desktop Users;true"
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
        Exit
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
CheckCsvOutputFolder
CheckRegistryKey
pause

#endregion
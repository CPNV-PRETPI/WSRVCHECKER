#Requires -Version 5.1
<#
.SYNOPSIS
    WSrvChecker
 
.DESCRIPTION
    The script objective is to check values of specific parameters of a Windows Server 2022 and report it to the administrator

.PARAMETER ExecutionPolicy
    Bypass

 .PARAMETER InputFile
    C:\Temp\Input_PreTPI.csv

.PARAMETER OutputFolder
    C:\Temp\
 
.EXAMPLE
    powershell.exe .\\Test.ps1 -ExecutionPolicy Bypass -InputFile C:\Temp\Input_PreTPI-FAILS.csv -OutputFolder C:\Temp\
    Runs the script with the specified ExecutionPolicy and result file
#>

param(
    
    [Parameter(Mandatory=$true)]
    [string]$ExecutionPolicy,
        
    [Parameter(Mandatory=$true)]
    [string]$InputFile,

    [Parameter(Mandatory=$true)]
    [string]$OutputFolder
)

#region Variables
$Script:ExecutionPolicy = $ExecutionPolicy
$Script:InputFile = $InputFile
$Script:OutputFolder = $OutputFolder
$Script:TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Script:Data = ""
$Script:Group = ""
$Script:UserExistanceChecker = ""
$Script:GroupChecker = ""
$Script:Csv = ""
$Script:MachineName = Hostname 
$Script:LogFile = "C:\Temp\Errors.log"
#endregion

#region Modules
import-module ActiveDirectory
#endregion

#region Functions

# Write in logfile
function WriteLog{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Private:Message
    )

    if(!(Test-Path $Script:LogFile)){
        try{
            New-Item $Script:LogFile -ItemType File | Out-Null
        }catch{
            WriteLog "Parameter: LogFile is inaccessible"
        }
    }
    $Private:TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Private:LogMessage = "$Private:TimeStamp - $Private:Message"
    Add-Content -Path $Script:LogFile -Value $Private:LogMessage
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
        WriteLog "Parameter: Outputfolder path is inaccessible"
        Exit 
    }
        }

# Check if InputFile is readable
function CheckCsvInputFileAccessibility {
    # Importation of CsvFile
    try{
        # Extraction of the csv file
        $Script:Csv = Import-CSV -Path $InputFile -Delimiter ";"
        }catch{
            WriteLog "Parameter: Import CSV file failed"
            Exit
        }
    }

# Check CsvInputFile data
function GetCsvdata{
    $Script:Data = @" 
        Group;MemberToCheck;Validation  
"@

    # Reading csv file  
    foreach($Private:Line in $Script:Csv){
        # Columns Assignment
        $Script:Group = $Private:Line.'Group'
        $Script:MemberToCheck = $Private:Line.'MemberToCheck'
        $Private:CheckValidation = CheckUserGroupMembership
        
        # Write Data to be exported in string
        if (($Script:GroupChecker) -and ($Script:UserExistanceChecker)){
                $Script:Data += @"
                
                    $Script:Group;$Script:MemberToCheck;$Private:CheckValidation
"@  
        }
    }
}


function CheckUserExistance {
    try{
        if($Private:UserExistanceTest = Get-ADUser -Identity $Script:MemberToCheck){
            return $true    
        }
    }
    catch{
        if(!($Private:UserExistanceChecker)){
            WriteLog "AdCheck: Member ->'$Script:MemberToCheck' doesn't exist or is not accessible"
            return $False
        }
    }
}

function CheckGroup {
    try{
        if ($Private:GroupExistanceTest = Get-ADGroup -Identity $Script:Group){
            $Private:GroupEmptyRead = Get-ADGroup -Identity $Script:Group -Properties Members 
            if($Private:GroupEmptyTest = $Private:GroupEmptyRead.Members.Count -ge 1){
                return $true
            }
        }
    }
    catch{
        if(!($Private:GroupExistanceTest)){
            WriteLog "AdCheck: Group ->'$Script:Group' doesn't exist or is not accessible"
            return $False
        }elseif(!($Private:GroupEmptyTest)){
            WriteLog "AdCheck: Group ->'$Script:Group' has no members"
            return $False
        }
    }
}

function CheckUserGroupMembership {
    if (($Script:GroupChecker) -and ($Script:UserExistanceChecker)){
        if($Private:CheckUserGroupMemberShip = Get-ADGroupMember -Identity $Script:Group | Where-Object {$_.SamAccountName -eq $Script:MemberToCheck}){
            return $true
        }else{
            return $False
        }
    }
}

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

    $Private:AdGroupAdministrators = @("CHORNWWAdministrators", "CHAVEWWAdministrators", "CHROMWWAdministrators")
    $Private:AdGroupRemoteDesktopUsers = @("CHORNTMRemoteDesktopusers", "CHAVETMRemoteDesktopusers", "CHROMTMRemoteDesktopusers")

    # Check Role List extracted from server one by one
    foreach ($Private:RoleFromServer in $Script:RolesFromServer) {
        $Private:Found = $false
        # Check Wonderware Role List one by one
        foreach ($Private:WonderwareRole in $Private:WonderwareRoles) {
            # Check if Role extracted from server corresponds to Wonderware Role
            if ($Private:RoleFromServer -eq $Private:WonderwareRole) {
                $Private:LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"
                # Check if Group searched is in local group members list
                foreach ($Private:MemberLocalGroup in $Private:LocalGroupMembers){ 
                    if($Private:MemberLocalGroup.Name -eq "NESTLE\ChornWWAdministrators"){
                        $Private:Found = $true
                        Write-Host $Private:MemberLocalGroup.Name
                    }
                }
            }
        }
    }
}

function CheckRegistryKey {
    # Define the Path and Value Name of RegistryKey
    $Private:RegistryKey = "HKLM:\SOFTWARE\Nestle\"
    $Private:RegistryValueName = "Roles"

    # Get RegistryKey
    $Private:RegistryKeyValue = Get-ItemPropertyValue -Path $Private:RegistryKey -Name $Private:RegistryValueName

    # Check RegistryKey value
    if ([string]::IsNullOrEmpty($Private:RegistryKeyValue)) {
        WriteLog "Registry: Registry Key value is empty or null"
    } else {
        # Split the RegistryKey value with separator '#'
        $Private:Roles = $Private:RegistryKeyValue.Split("#")
        
        # Gets each role of server and calls the right function for it
        foreach ($Private:Role in $Private:Roles) {
            if (!([string]::IsNullOrEmpty($Private:Role))) {
                    # To Define
            }
        }
    }
}

# Extract all data to a .zip file
function ExtractData{
    # Get the data
    GetCsvdata

    # Converts data to an object
    $Private:PSObject = $Script:Data | ConvertFrom-Csv

    # Export the data object to a CSV file
    $Private:PSObject | Export-Csv -Path "$Script:OutputFolder\$Script:TimeStamp.csv" -NoTypeInformation

    # Define the .zip folder name
    $Private:ZipFolderName = "$($Script:MachineName)_$Script:TimeStamp.zip"
    
    # Compress files to a .zip folder
    WriteLog "Trying to compress files.."
    Compress-Archive -Path "$Script:OutputFolder\$Script:TimeStamp.csv",$Script:LogFile,$Script:InputFile -DestinationPath "$Script:OutputFolder\$Private:ZipFolderName"

    # Delete original files
    Remove-Item -Path $Script:LogFile 
    Remove-Item -Path "$Script:OutputFolder\$Script:TimeStamp.csv" 
    # Remove-Item -Path "$Script:InputFile" -Force
}

# Regroupe all checkers for the beginning of the script in one function
function StartScriptCheckers{
    CheckExecutionPolicy
    CheckAdminRights
    CheckCsvOutputFolder
    CheckCsvInputFileAccessibility
}

#endregion

#region Main
StartScriptCheckers
CheckRegistryKey
ExtractData
Exit
#endregion


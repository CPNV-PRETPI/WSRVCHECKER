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
$Script:Csv = ""
$Script:MachineName = Hostname
$Script:DomainName = "Nestle" 
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
function CsvOutputFolder{
    if(!(Test-Path $Script:OutputFolder))
    {
        WriteLog "Parameter: Outputfolder path is inaccessible"
        Exit 
    }
        }

# Check if data is ok
function CsvInputFile {
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
function CsvGetdata{
    $Script:Data = @" 
        Group;MemberToCheck;Validation  
"@

    # Reading csv file  
    foreach($Private:Line in $Script:Csv){
        # Columns Assignment
        $Script:Group = $Private:Line.'Group'
        $Script:MemberToCheck = $Private:Line.'MemberToCheck'
        $Private:CheckValidation = CheckUserGroupMembership

        Write-Host $Private:CheckValidation
        # Write Data to be exported in string
        if (($Private:GroupChecker) -and ($Private:UserExistanceChecker)){
                $Script:Data += @"

                $Script:Group;$Script:MemberToCheck;$Private:CheckValidation
"@  
        }
    }
    Write-Host $Script:Data
}


function UserExistanceChecker {
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


function GroupChecker {
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

    $Private:UserExistanceChecker = UserExistanceChecker
    $Private:GroupChecker = GroupChecker
    if (($Private:GroupChecker) -and ($Private:UserExistanceChecker)){
        Write-Host "Group and User exists"
        if($Private:CheckUserGroupMemberShip = Get-ADGroupMember -Identity $Script:Group | Where-Object {$_.SamAccountName -eq $Script:MemberToCheck}){
            return $true
        }else{
            return $False
        }
    }
}

function RegistryKeyCheck {
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
function DataExtract{
    # Get the data
    CsvGetdata

    # Converts data to an object
    $Private:PSObject = $Script:Data | ConvertFrom-Csv

    # Export the data object to a CSV file
    $Private:PSObject | Export-Csv -Path "$Script:OutputFolder\$Script:TimeStamp.csv" -NoTypeInformation

    # Define the .zip file name
    $Private:ZipFolderName = "$($Script:MachineName)_$Script:TimeStamp.zip"
    
    # Compress .txt files to a .zip folder
    WriteLog "Trying to compress files.."
    Compress-Archive -Path "$Script:OutputFolder\$Script:TimeStamp.csv",$Script:LogFile,$Script:InputFile -DestinationPath "$Script:OutputFolder\$Private:ZipFolderName"

    #
    # Delete original files
    Remove-Item -Path $Script:LogFile 
    Remove-Item -Path "$Script:OutputFolder\$Script:TimeStamp.csv" 
    # Remove-Item -Path "$Script:InputFile" -Force
    
}

# Regroupe all checkers for the beginning of the script in one function
function ScriptStartCheckers{
    CheckExecutionPolicy
    CheckAdminRights
    CsvOutputFolder
    CsvInputFile
}

#endregion

#region Main
ScriptStartCheckers
DataExtract
Exit
#endregion


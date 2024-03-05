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
    powershell.exe .\\Test.ps1 -ExecutionPolicy Bypass -InputFile C:\Temp\Input_PreTPI-WORKS.csv -OutputFolder C:\Temp\
    Runs the script with the specified ExecutionPolicy and result file
#>

param(
    
    [Parameter(Mandatory="Bypass")]
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
$Script:MemberToCheck = ""
$Script:Csv = ""
$Script:MachineName = Hostname
$Script:LogFile = ""
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
    $Private:LogFilePath = "C:\Temp"
    $Private:LogFileName = "Errors.log"
    $Script:LogFile = "$Private:LogFilePath\$Private:LogFileName"
    if (!(Test-Path $Private:LogFilePath)){
        New-Item -ItemType Directory -Path $Private:LogFilePath
    }
    if(!(Test-Path $Script:LogFile)){
        try{
            New-Item "$Script:LogFile" -ItemType File | Out-Null
        }catch{
            WriteLog "Parameter: Outputfolder path is inaccessible for logfile"
        }
    }
    $Private:TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Private:LogMessage = "$Private:TimeStamp - $Private:Message"
    Add-Content -Path "$Script:LogFile" -Value $Private:LogMessage
}
# Check ExecutionPolicy
function CheckExecutionPolicy{
    # Check Executionpolicy
    if($Script:ExecutionPolicy -ne "Bypass"){
        WriteLog "Script ONLY runs with the ExecutionPolicy 'Bypass'!"
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

# Check if OutputFolder parameter is accessible
function CsvOutputFile{
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
    CsvInputFile
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
        $Private:UserExistanceChecker = UserExistanceChecker
        $Private:GroupChecker = GroupChecker
        if (($Private:GroupChecker) -and ($Private:UserExistanceChecker)){
                $Script:Data += @"

                $Script:Group;$Script:MemberToCheck;$Private:CheckValidation
"@  
        }
    }
}

# 
function UserExistanceChecker {
    try{
        if($Script:MemberToCheck -eq ""){
        WriteLog "AdCheck: Member Value is missing"
    }else{
        if($Private:UserExistanceTest = Get-ADUser -Identity $Script:MemberToCheck){
            return $true    
        }
    }
    }catch{
        if(!($Private:UserExistanceChecker)){
        WriteLog "AdCheck: '$Script:MemberToCheck' doesn't exist or is not accessible"
        return $False
    }
}
}

function GroupChecker {
    try{
    if($Script:Group -eq ""){
        WriteLog "AdCheck: Group Value is missing"
    }else{
        if ($Private:GroupExistanceTest = Get-ADGroup -Identity $Script:Group){
            $Private:GroupEmptyRead = Get-ADGroup -Identity $Script:Group -Properties Members
            if($Private:GroupEmptyTest = $Private:GroupEmptyRead.Members.Count -ge 1){
                return $true
            }
        }
    }
    }catch{
        if(!($Private:GroupExistanceTest)){
            WriteLog "AdCheck: '$Script:Group' doesn't exist or is not accessible"
            return $False
        }elseif(!($Private:GroupEmptyTest)){
            WriteLog "AdCheck: '$Script:Group' has no members"
            return $False
    }
    }
}

function CheckUserGroupMembership {
    # Define and calls Group and user checker ( We don't call it in the 'if' to be sure that those functions aren't executed multiple times for one data check )
    $Private:UserExistanceChecker = UserExistanceChecker
    $Private:GroupChecker = GroupChecker
    
    if (($Private:GroupChecker) -and ($Private:UserExistanceChecker)){
        if($Private:CheckUserGroupMemberShip = Get-ADGroupMember -Identity $Script:Group | Where-Object {$_.SamAccountName -eq $Script:MemberToCheck}){
            return $true
        }else{
            return $False
        }
    }
    if(!($Private:UserExistanceChecker)){
        WriteLog "AdCheck: User doesn't exists or is not accessible" 
    }
    if(!($Private:GroupChecker)){
        WriteLog "AdCheck: Group doesn't exists or is not accessible" 
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
    Compress-Archive -Path "$Script:OutputFolder\$Script:TimeStamp.csv",$Script:LogFile -DestinationPath "$Script:OutputFolder\$Private:ZipFolderName"

    # Delete original files
    Remove-Item -Path $Script:LogFile
    Remove-Item -Path "$Script:OutputFolder\$Script:TimeStamp.csv"
    # Remove-Item -Path "$Script:InputFile"
}
#endregion

#region Main
CheckExecutionPolicy
CheckAdminRights
CsvOutputFile
DataExtract
Exit
#endregion


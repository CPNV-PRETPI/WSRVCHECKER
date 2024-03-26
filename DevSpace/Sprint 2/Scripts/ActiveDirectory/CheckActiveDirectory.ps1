#Requires -Version 5.1
<#
.SYNOPSIS
    CheckActiveDirectory
 
.DESCRIPTION
    The script objective is to check membership of specific Active Directory users in Active Directory groups

.PARAMETER ExecutionPolicy
    Bypass

 .PARAMETER InputFile
    C:\Temp\Scripts\ActiveDirectory\Input.csv

.PARAMETER OutputFolder
    C:\Temp\Scripts\ActiveDirectory\
 
.EXAMPLE
    powershell.exe .\\CheckActiveDirectory.ps1 -ExecutionPolicy Bypass -InputFile C:\Temp\Scripts\ActiveDirectory\Input.csv -OutputFolder C:\Temp\Scripts\ActiveDirectory\
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
$Script:LogFile = "C:\Temp\Scripts\ActiveDirectoryErrors.log"
#endregion

#region Modules
import-module ActiveDirectory
#endregion

#region Functions

# Write in logfile
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
        WriteLog "CheckExecutionPolicy: Script ONLY runs with the ExecutionPolicy 'Bypass'!"
        Pause
        Exit
    }else{
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy $Script:ExecutionPolicy -Force
    }
}

# Check Privilieges
function CheckAdminRights {
    $Private:IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    If (-Not $Private:IsAdmin) {
        WriteLog "CheckAdminRights: Script is NOT running with Administrators priviledges!"
        Pause
        Exit
    }
}

# Check if OutputFolder parameter exists and is accessible
function CheckCsvOutputFolder{
    if(!(Test-Path $Script:OutputFolder))
    {
        WriteLog "CsvOutputFolder: Outputfolder path is inaccessible"
        Pause
        Exit
    }
}

# Check if InputFile is readable
function CheckCsvInputFile {
    # Importation of CsvFile
    try{
        # Extraction of the csv file
        $Script:Csv = Import-CSV -Path $InputFile -Delimiter ";"
    }catch{
        WriteLog "CsvInputFile: Import CSV file failed"
        Pause
        Exit
    }
}

# Check CsvInputFile data
function GetCsvData{
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
        if (!($Script:GroupChecker = $null) -and !($Script:UserExistanceChecker = $null)){
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
            return $False
        }
    }
}


function CheckGroupExistance {
    try{
        if ($Private:GroupExistanceTest = Get-ADGroup -Identity $Script:Group){
                return $true
        }
    }
    catch{
        if(!($Private:GroupExistanceTest)){
            return $False
        }
    }
}

function CheckUserGroupMembership {
    $Script:GroupChecker = CheckGroupExistance
    $Script:UserExistanceChecker = CheckUserExistance
    if (($Script:GroupChecker) -and ($Script:UserExistanceChecker)){
        if($Private:CheckUserGroupMemberShip = Get-ADGroupMember -Identity $Script:Group | Where-Object {$_.SamAccountName -eq $Script:MemberToCheck}){
            return $true
        }else{
            return $False
        }
    }
}

# Extract all data to a .zip file
function ExtractData{
    # Get the data
    GetCsvData

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

#endregion

#region Main
WriteLog
CheckExecutionPolicy
CheckAdminRights
CheckCsvOutputFolder
CheckCsvInputFile
ExtractData
Pause
#endregion
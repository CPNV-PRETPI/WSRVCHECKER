#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Server 2022 Parameters checker
 
.DESCRIPTION
    The script objective is to check values of specific parameters of a Windows Server 2022 and report it so that the administrator can check if a change is needed

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
$Script:Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Script:Data = ""
$Script:Group = ""
$Script:MemberToCheck = ""
$Script:Csv = ""
#endregion

#region Modules
import-module ActiveDirectory
#endregion

#region Functions

# Checks ExecutionPolicy
function CheckExecutionPolicy{
    # Check Executionpolicy
    if($Script:ExecutionPolicy -ne "Bypass"){
    Write-Host "* --------" -Foreground Red
    Write-Host "* ERROR: Script ONLY runs with the ExecutionPolicy 'Bypass'!" -Foreground Red
    Write-Host "* Script is canceled!" -Foreground Red
    Write-Host "* --------" -Foreground Red
    Exit 
    }else{
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy $Script:ExecutionPolicy -Force
}
}
# Checks Privilieges
function CheckAdminRights {
$Private:IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
If (-Not $Private:IsAdmin) {
  Write-Host "* --------" -Foreground Red
  Write-Host "* ERROR: Script is NOT running with Administrators priviledges!" -Foreground Red
  Write-Host "* Script is canceled!" -Foreground Red
  Write-Host "* --------" -Foreground Red
  Exit 
}
}

function CsvOutputFile{
    if(Test-Path $Script:OutputFolder)
    {
    try{
        (New-Item "$Script:OutputFolder\$Script:Timestamp.csv" -ItemType File | Out-Null) -and (Test-Path$Script:OutputFolder)
    }catch{
            Write-Host "* --------" -Foreground Red
            Write-Host "* ERROR: Outputfolder path is inaccessible" -Foreground Red
            Write-Host "* Script is canceled!" -Foreground Red
            Write-Host "* --------" -Foreground Red 
            Exit 
    }
    }else{
            Write-Host "* --------" -Foreground Red
            Write-Host "* ERROR: Outputfolder path is incorrect" -Foreground Red
            Write-Host "* Script is canceled!" -Foreground Red
            Write-Host "* --------" -Foreground Red 
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
            Write-Host "* --------" -Foreground Red
            Write-Host "* ERROR: Import CSV file failed" -Foreground Red
            Write-Host "* Script is canceled!" -Foreground Red
            Write-Host "* --------" -Foreground Red
            Exit
        }
    }

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
    
            if($Private:CheckValidation = CheckUserGroupMembership){
            $Script:Data += @"

            $Script:Group;$Script:MemberToCheck;$Private:CheckValidation
"@  
        }
    }
}

function UserExistanceChecker {
    try{
        if($Script:MemberToCheck -eq ""){
        Write-Host "* Member Value is missing" -Foreground Yellow
    }else{
        if($Private:UserExistanceTest = Get-ADUser -Identity $Script:MemberToCheck){
            return $true    
        }
    }
    }catch{
        if(!($Private:UserExistanceChecker)){
        Write-Host "* '$Script:MemberToCheck' doesn't exist or is not accessible" -Foreground Yellow
        return $False
    }
}
}

function GroupChecker {
    try{
    if($Script:Group -eq ""){
        Write-Host "* Group Value is missing" -Foreground Yellow
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
            Write-Host "* '$Script:Group' doesn't exist or is not accessible" -Foreground Yellow
            return $False
        }elseif(!($Private:GroupEmptyTest)){
            Write-Host "* '$Script:Group' has no members" -Foreground Yellow
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
            Write-Host "* '$Script:MemberToCheck' is in '$Script:Group'" -Foreground Green
            return $true
        }else{
            Write-Host "* '$Script:MemberToCheck' is not in '$Script:Group'" -Foreground Cyan
            return $False
        }
    }
    if(!($Private:UserExistanceChecker)){
        Write-Host  -Foreground Red
        Write-Host "* ERROR: User data problem" -Foreground Red
        Write-Host "* Script can't check line" -Foreground Red
        Write-Host "* --------" -Foreground Red
    }
    if(!($Private:GroupChecker)){
        Write-Host "* --------" -Foreground Red
        Write-Host "* ERROR: Group data problem" -Foreground Red
        Write-Host "* Script can't check line" -Foreground Red
        Write-Host "* --------" -Foreground Red 
    }
    }

# Extract all data to a file
function DataExtract{
    # Get the data
    CsvGetdata

    # Converts data to an object
    $Private:PSObject = $Script:Data | ConvertFrom-Csv

    # Export the data object to a CSV file
    $Private:PSObject | Export-Csv -Path "$Script:OutputFolder\$Script:Timestamp.csv" -NoTypeInformation

    # Define the .zip file name
    $Private:ZipFolderName = "$Script:Timestamp.zip"
    
    # Compress .txt files to a .zip folder
    Compress-Archive -Path "$Script:OutputFolder\$Script:Timestamp.csv" -DestinationPath "$Script:OutputFolder\$Private:ZipFolderName"

    # Delete original files
    Remove-Item -Path "$Script:OutputFolder\$Script:Timestamp.csv"
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


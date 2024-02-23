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
#endregion

#region Modules
import-module ActiveDirectory
#endregion

#region Functions

# Checks ExecutionPolicy
function CheckExecutionPolicy{
    # Check Executionpolicy
    if($Script:ExecutionPolicy -ne "Bypass"){
    Write-Host "*" -Foreground Red
    Write-Host "* ERROR: Script ONLY runs with the ExecutionPolicy 'Bypass'!" -Foreground Red
    Write-Host "* Script is canceled!" -Foreground Red
    Write-Host "*" -Foreground Red
    Exit 
    }else{
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy $Script:ExecutionPolicy -Force
}
}
# Checks Privilieges
function CheckAdminRights {
$Private:IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
If (-Not $Private:IsAdmin) {
  Write-Host "*" -Foreground Red
  Write-Host "* ERROR: Script is NOT running with Administrators priviledges!" -Foreground Red
  Write-Host "* Script is canceled!" -Foreground Red
  Write-Host "*" -Foreground Red
  Exit 
}
}

# Check if data is ok
function CsvInputFileChecker {
    try{
        # Extraction of the csv file
        $Private:Csv = Import-CSV -Path $InputFile -Delimiter ";"

        # Check if csv file is empty
        if ($Private:Csv -eq $null){
            Write-Host "*" -Foreground Red
            Write-Host "* ERROR: No data found" -Foreground Red
            Write-Host "* CSV input file is empty" -Foreground Red
            Write-Host "* Script is canceled!" -Foreground Red
            Write-Host "*" -Foreground Red
            Exit
        }    
        }catch{
            Write-Host "*" -Foreground Red
            Write-Host "* ERROR: Import CSV file failed" -Foreground Red
            Write-Host "* Try to check if the CSV exists or is accessible" -Foreground Red
            Write-Host "* Script is canceled!" -Foreground Red
            Write-Host "*" -Foreground Red
            Exit
        }

    # Creation of head titles of the csv file
    $Script:Data = @" 
        Group;MemberToCheck;Validation  
"@
    # Reading csv file  
    foreach($Private:Line in $Private:Csv){
        # Columns Assignment
        $Script:Group = $Private:Line.'Group'
        $Script:MemberToCheck = $Private:Line.'MemberToCheck'
        try{
            
        }
        
    }catch{

    }
    }

function UserExistanceChecker {
    if($Private:UserExistanceTest = Get-ADUser -SamAccountName $Script:MemberToCheck){
        return $true    
    }else{
        return $False
    }
}
function UserChecker {
    if (UserExistanceChecker){
    # Checks if user is in a specific group only if user exists
    if($Private:GroupMemberCheck = Get-ADGroupMember -Identity $Script:Group | Where-Object {$_.name -eq $Script:MemberToCheck}){
        $Private:MemberInGroup = $true
    }else{
        $Private:MemberInGroup = $False
    }
    }
}

function GroupChecker {
    if ($Private:GroupExistanceTest = Get-ADGroup -Identity $Script:Group){
                return $true
    }else{
        return $False
    }
}

# Extract all data to a file
function DataExtract{
    # Check the data
    DataChecker

    # Converts data to an object
    $Private:PSObject = $Script:Data | ConvertFrom-Csv

    # Export the data object to a CSV file
    New-Item "$Script:OutputFolder\$Script:Timestamp.csv" -ItemType File | Out-Null
    $Private:PSObject | Export-Csv -Path "$Script:OutputFolder\$Script:Timestamp.csv" -NoTypeInformation

    # Define the .zip file name
    $Private:ZipFolderName = "$Script:Timestamp.zip"
    
    # Compress .txt files to a .zip folder
    Compress-Archive -Path "$Script:OutputFolder\$Script:Timestamp.csv" -DestinationPath "$Script:OutputFolder\$Private:ZipFolderName"
}
#endregion

#region Main
CheckExecutionPolicy
CheckAdminRights
DataExtract
Exit
#endregion


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

.PARAMETER OutputFile
    C:\Temp\Output_PreTPI.csv
 
.EXAMPLE
    powershell.exe .\\Test.ps1 -ExecutionPolicy Bypass -InputFile C:\Temp\Input_PreTPI.csv -OutputFile C:\Temp\Output_PreTPI.csv
 
    Runs the script with the specified ExecutionPolicy and result file
#>

param(
    
    [Parameter(Mandatory="Bypass")]
    [string]$ExecutionPolicy,
        
    [Parameter(Mandatory=$true)]
    [string]$InputFile,

    [Parameter(Mandatory=$true)]
    [string]$OutputFile
)

#region Variables
$Script:ExecutionPolicy = $ExecutionPolicy
$Script:InputFile = $InputFile
$Script:OutputFile = $OutputFile
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
function DataChecker {
    
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
    }
    # Creation of head titles of the csv file
    $Script:Data = @" 
        Group;MemberToCheck;Validation  
"@
    # Reading csv file  
    foreach($Private:Line in $Private:Csv){
        # Columns Assignment
        $Private:Group = $Private:Line.'Group'
        $Private:MemberToCheck = $Private:Line.'MemberToCheck'
        
        # Group Exists Checker
        if (Get-ADGroup -Identity "$Private:Group" -ne $null){
            Write-Host "$Private:Group exists"
        }else{
            Write-Host "$Private:Group doesn't exist"
        }
        
        # Group Members Checker
        $Private:GroupMemberCheck = Get-ADGroupMember -Identity $Private:Group | Where-Object {$_.name -eq $Script:Member}
        if($Private:GroupMemberCheck){
            $Private:MemberInGroup = $true
        }else{
            $Private:MemberInGroup = $False
        }
        
        # Convert data as String
        $Script:Data += @"

        $Private:Group;$Private:MemberToCheck;$Private:MemberInGroup
"@ 
Write-Host $Script:Data  
}


# Extract all data to a file
function DataExtract{
    # Check the data
    DataChecker

    # Converts data to an object
    $Private:PSObject = $Script:Data | ConvertFrom-Csv
    
    # Gets the directory of the OutputFile
    $Private:OutputFolder = Split-Path -Path $Script:OutputFile -Parent

    # Export the data object to a CSV file
    if (!(Test-Path "$Private:OutputFolder\$Script:Timestamp.csv")){
        New-Item "$Private:OutputFolder\$Script:Timestamp.csv" -ItemType File
    }
    $Private:PSObject | Export-Csv -Path "$Private:OutputFolder\$Script:Timestamp.csv" -NoTypeInformation

    # Define the .zip file name
    $Private:ZipFolderName = "$Script:Timestamp.zip"
    
    # Compress .txt files to a .zip folder
    
    Compress-Archive -Path "$Private:OutputFolder\$Script:Timestamp.csv" -DestinationPath "$Private:OutputFolder\$Private:ZipFolderName"
}
#endregion

#region Main
CheckExecutionPolicy
CheckAdminRights
DataExtract
Exit
#endregion


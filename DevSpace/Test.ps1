#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Server 2022 Parameters checker
 
.DESCRIPTION
    The script objective is to check values of specific parameters of a Windows Server 2022 and report it so the administrator can check if a change is needed
  
.PARAMETER OutputFile
    C:\Temp\PreTPI.txt
 
.EXAMPLE
    .\\Test.ps1 -ExecutionPolicy Bypass -OutputFile C:\Temp\PreTPI.txt
 
    Runs the script with the specified ExecutionPolicy and result file
#>

param(
    
    [Parameter()]
    [string]$ExecutionPolicy = "Bypass",
    
    [Parameter(Mandatory=$true)]
    [string]$OutputFile
)

# Define the Execution Policy
Set-ExecutionPolicy -Scope Process -ExecutionPolicy $ExecutionPolicy -Force

#region Variables

$ErrorActionPreference = 'Stop'
$script:ProcessNumber = 0
$script:ServiceNumber = 0 
$script:data = ""
#endregion

#region Functions

# Checks privilieges
function CheckAdminRights {
$IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
If (-Not $IsAdmin) {
  Write-Host "*" -Foreground Red
  Write-Host "* ERROR: Script is NOT running with Administrators priviledges!" -Foreground Red
  Write-Host "* Script is canceled!" -Foreground Red
  Write-Host "*" -Foreground Red
  pause
  Exit 20  #Exit script with 20=FailureReturnCode
}else{
  Write-Host "Admin Rights -> OK"
}
}
# Add AD group to Local Group
function ADGroupsInLocalGroups {
    do {
        Write-Host "Do you want to add AD Groups in local groups?"
        $Choice = Read-Host "Type Y or N"
        
        if ($Choice -eq 'Y') {
            $DomainName = Read-Host "Please type the domain name"
            $ADGroupName = Read-Host "Please type the exact AD group to add"
            $LocalGroupName = Read-Host "Please type the exact local group where you want your AD group to be added"
            
            Add-LocalGroupMember -Group $LocalGroupName -Member ($DomainName + "/" + $ADGroupName)
        }
        
    } while ($Choice -eq 'Y')
}

# Count number of processes 
function ProcessCount {
    $script:ProcessNumber = (Get-Process).Count
}

# Count number of services
function ServiceCount {
    $script:ServiceNumber = (Get-service).Count
}

# Check if data is ok
function DataChecker {
    #Call functionns to get process and service counts
    ProcessCount
    ServiceCount

    # Processes Checker
    if ($script:ProcessNumber -ge 100){
        $private:ProcessCheck = $true
    }else{
        $private:ProcessCheck = $False
    }
    # Services Checker
    if ($script:ServiceNumber -ge 100){
        $private:ServiceCheck = $true
    }else{
        $private:ServiceCheck = $False
    }
    # Convert data as String
    $script:Data = @"    
     $private:ProcessCheck,$script:ProcessNumber
     $private:ServiceCheck,$script:ServiceNumber
"@
     Write-Host $script:Data

}
# Extract all data to a file
function DataExtract{
    # Check the data
    DataChecker

    # Send the Converted data to a .txt file
    $script:Data | Out-File -FilePath C:\Temp\Output.txt

    # Define Date Time
    $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    # Define the .zip file name
    $ZipFolderName = "$Timestamp.zip"
    
    # Compress .txt files to a .zip folder
    Compress-Archive -Path "Output.txt" -DestinationPath "C:\Temp\$ZipFolderName"
}
#endregion

#region Main
Write-Host "Setting execution policy to: $ExecutionPolicy"
#CheckAdminRights
ADGroupsInLocalGroups
DataExtract
pause
#endregion


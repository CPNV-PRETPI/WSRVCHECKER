import-module ActiveDirectory

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
$Script:DomainName = "Nestle.com" 
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
$Script:UserExistanceChecker = UserExistanceChecker
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
$Script:GroupChecker = GroupChecker
}



# Regroupe all checkers for the beginning of the script in one function
function StartCheckers{
    CheckExecutionPolicy
    CheckAdminRights
}

#endregion

#region Main
StartCheckers
DataExtract
Exit
#endregion


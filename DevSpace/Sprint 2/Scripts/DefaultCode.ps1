param(
    
    [Parameter(Mandatory=$true)]
    [string]$ExecutionPolicy

    )

$Script:ExecutionPolicy = $ExecutionPolicy
$Script:LogFile = "C:\Temp\Scripts\Errors.log"


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
    Write-Host $Private:LogMessage -ForegroundColor Red
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

function ShowMenu{
    Write-Host "================ WSRVChecker =============="
    Write-Host "  " 
    Write-Host "    |  1: Active Directory Checker    |" 
    Write-Host "    |  2: Server Roles Checker        |" 
    Write-Host "    |  3: Press '3' for this option.  |"
    Write-Host "    |                                 |"
    Write-Host "    |  Q: Press 'Q' to quit.          |"
    Write-Host "  "    
}


function MakeChoice{
    do
    {
        ShowMenu

        $Private:Selection = Read-Host "Please make a selection"
        $Private:ScriptChoice1 = "C:\Temp\Scripts\ActiveDirectory\CheckActiveDirectory.ps1"
        $Private:ScriptChoice2 = "C:\Temp\Scripts\RegistryKey\RegistryKey.ps1"
        $Private:ScriptChoice3 = "C:\Temp\Smalltests_2.ps1"

        switch ($Private:Selection)
        {
            "1" {
                Write-Host "To start this script you need to set parameters" -ForegroundColor Yellow
                Write-Host "  "
                $Private:InputFile = Read-Host "Please enter the path of the input file to check" 
                $Private:OutputFolder = Read-Host "Please enter the path of the result"

                Start-Process -FilePath "cmd.exe" -ArgumentList "/c powershell.exe -File $Private:ScriptChoice1 -ExecutionPolicy Bypass -InputFile $Private:InputFile -OutputFolder $Private:OutputFolder"
            } "2" {
                Write-Host "To start this script you need to set parameters" -ForegroundColor Yellow
                Write-Host "  "
                $Private:FactoryAbbreviation = Read-Host "Please enter the abbreviation of your factory ( CHORN | CHROM | CHAVE )"

                Start-Process -FilePath "cmd.exe" -ArgumentList "/c powershell.exe -File $Private:ScriptChoice2 -ExecutionPolicy Bypass -FactoryAbbreviation $Private:FactoryAbbreviation"
            } "3" {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c powershell.exe -File $Private:ScriptChoice3"
            } "Q" {
                return
            }
        }
    }
    until ($Private:Selection -eq "Q")
}


#region Main

CheckAdminRights
CheckExecutionPolicy
MakeChoice
Pause

#endregion
param(
    
    [Parameter(Mandatory=$true)]
    [string]$Test
)

#region Variables
$Script:OutputFolder = $Test
#Functions



function CsvOutputFolder{
    
        try{
            if($Script:OutputFolder = ""){
                Write-Host "vide"
            }else{
                Write-Host "Pas vide"
            }
        }
        catch{
            Write-Host "Parameters: Outputfolder path is not provided"
        }
        }
#Main
CsvOutputFolder
Pause
Pause
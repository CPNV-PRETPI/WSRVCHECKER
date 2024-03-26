$Private:AdGroupAdministrators = @("CHORNAdministrators", "CHAVEAdministrators", "CHROMAdministrators")
Write-Host $Private:AdGroupAdministrators

$Private:LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"

if($Private:AdGroupAdministrators -contains $Private:LocalGroupMembers){
    Write-Host "bien vu"
}else{
    Write-Host "force"
}
 
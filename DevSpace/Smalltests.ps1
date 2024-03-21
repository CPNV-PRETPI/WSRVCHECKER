$LocalGroupMembers = Get-LocalGroupMember -Group "Administrators"
$GroupExists = $false

foreach ($member in $LocalGroupMembers) {
    if ($member.Name -eq "NESTLE\ChornWWAdministrators") {
        $GroupExists = $true
        break
    }
}
 
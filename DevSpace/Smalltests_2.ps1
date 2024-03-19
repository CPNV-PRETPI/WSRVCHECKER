
function RegistryKeyCheck {
$Private:RegistryKey = "HKLM:\SOFTWARE\Nestle\"
$Private:RegistryValueName = "Roles"

$Private:RegistryValue = Get-ItemPropertyValue -Path $Private:RegistryKey -Name $Private:RegistryValueName

if ([string]::IsNullOrEmpty($Private:RegistryValue)) {
    WriteLog "Error: Registry Key value is empty or null"
} else {
    $Private:Roles = $Private:RegistryValue.Split("#")
    Write-Output "Role Values:"
    foreach ($Private:Role in $Private:Roles) {
        if (!([string]::IsNullOrEmpty($Private:Role))) {
            # To Define
        }
    }
}
}
pause


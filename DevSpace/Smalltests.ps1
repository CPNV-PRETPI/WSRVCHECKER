import-module ActiveDirectory

    $Script:Group = "CHAVE Beamex Administrators" 
    $Script:MemberToCheck = "nnribeirnu"

<#function UserExistanceChecker {
    try{
        if($Script:MemberToCheck -eq ""){
        Write-Host "'Member Value is empty" -Foreground Yellow
    }else{
        if($Private:UserExistanceTest = Get-ADUser -Identity $Script:MemberToCheck){
            return $true    
        }
    }
    }catch{
        Write-Host "'$Script:MemberToCheck' doesn't exist or is not accessible" -Foreground Yellow
        return $False
    }
}

function GroupChecker {
    try{
    if($Script:Group -eq ""){
        Write-Host "'Group Value is empty" -Foreground Yellow
    }else{
        if ($Private:GroupExistanceTest = Get-ADGroup -Identity $Script:Group){
            $Private:GroupEmptyRead = Get-ADGroup -Identity $Script:Group -Properties Members
            if($Private:GroupEmptyTest = $Private:GroupEmptyRead.Members.Count){
                return $true
            }
        }
    }
    }catch{
        if($Private:GroupEmptyTest){
            Write-Host "'$Script:Group' is empty" -Foreground Yellow
        }else{
            Write-Host "'$Script:Group' doesn't exist or is not accessible" -Foreground Yellow
        }
        return $False
    }
    }

function CheckUserGroupMembership {
    if ((UserExistanceChecker) -and (GroupChecker)){
    # Checks if user is in a specific group only if user exists
    if(Get-ADGroupMember -Identity $Script:Group | Where-Object {$_.SamAccountName -eq $Script:MemberToCheck}){
        return $true
    }else{
        Write-Host "'$Script:MemberToCheck' is not in '$Script:Group'" -Foreground Yellow
        return $False
    }
    }
}

CheckUserGroupMembership
Pause#>

$Private:GroupEmptyRead = Get-ADGroup -Identity $Script:Group -Properties Members
if($Private:GroupEmptyTest = $Private:GroupEmptyRead.Members.Count -ge 1){
    write-host "c'est ok"
}else{
    
}
Write-Host $GroupEmptyRead
Write-Host "------------------------------------------"
Write-Host $GroupEmptyTest
Pause
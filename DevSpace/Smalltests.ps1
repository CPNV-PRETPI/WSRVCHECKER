import-module ActiveDirectory

    $Script:Group = "CHAVE LMS Users" 
    $Script:MemberToCheck = "nnrirnu"

function UserExistanceChecker {
    try{
    if($Private:UserExistanceTest = Get-ADUser -Identity $Script:MemberToCheck){
        return $true
    }
    }catch{
        return $False
    }
}

function GroupExistanceChecker {
    try{
    if ($Private:GroupExistanceTest = Get-ADGroup -Identity $Script:Group){
        return $true
    }
    }catch{
        return $False
    }
    }

    function CheckUserGroupMembership {
    if ((UserExistanceChecker) -and (GroupExistanceChecker)){
    # Checks if user is in a specific group only if user exists
    if($Private:GroupMemberCheck = Get-ADGroupMember -Identity $Script:Group | Where-Object {$_.SamAccountName -eq $Script:MemberToCheck}){
        return $true
    }else{
        return $False
    }
    }
}


function CsvGetdata{
    
    $Script:Data = @" 
        Group;MemberToCheck;Validation  
"@
        # Complete '$Script:Data' with data for each line + validation
        
        if(CheckUserGroupMembership){
        $Private:CheckValidation = $true
        $Script:Data += @"

        $Script:Group;$Script:MemberToCheck;$Private:CheckValidation
"@  
        }else{
         $Private:CheckValidation = $False
        $Script:Data += @"

        $Script:Group;$Script:MemberToCheck;$Private:CheckValidation
"@   
        }
Write-Host $Script:Data
    }
    CsvGetdata    
    Pause

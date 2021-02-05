#Script to Grant or Revoke selected membership
$action = "Grant"
#$action = "Revoke"

$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$aRefList = $accountReference | ConvertFrom-Json 
$pRef = $permissionReference | ConvertFrom-json;   
$dR = $dryRun | ConvertFrom-json;



if ([Net.ServicePointManager]::SecurityProtocol -notmatch "Tls12") {
    [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
}

$success = $false;        
$auditMessage = "Group membership for person " + $p.DisplayName + " not updated successfully";


try {
    #serviceProxy = New-WebServiceProxy -uri $config.UrlSoap  -NameSpace "MijnCaress"
    $serviceProxy = New-WebServiceProxy -uri $config.wsdlFileSoap  -NameSpace "MijnCaress"

    $caressService = [MijnCaress.IinvUserManagementservice]::new();
    $caressService.Url = $config.urlSoap

    if (![string]::IsNullOrEmpty($Config.ProxyAddress)) {
        $caressService.Proxy = [System.Net.WebProxy]::new($config.ProxyAddress);
    }     

    if (![string]::IsNullOrEmpty($Config.CertificateSoap)){
        [System.Security.Cryptography.X509Certificates.X509Certificate] $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromCertFile($Config.CertificateSoap);
        $null = $caressService.ClientCertificates.Add($certificate);
    }

    [string] $authToken = $CaressService.CreateSession($config.UsernameSoap,$config.PasswordSoap) 
    
    if (![string]::IsNullOrEmpty($authToken)){

        [MijnCaress.AuthHeader] $auth =  [MijnCaress.AuthHeader]::new()
        $auth.sSessionId = $authToken;
        $auth.sUserName = $config.UsernameSoap;     
        $caressService.AuthHeaderValue = $auth              
    }
    else {  
        $message = "Could not retreive authentication token from $($caressService.Url)  for user $($config.UsernameSoap)";      
        throw ($message)    
    }    
  
    [MijnCaress.TremUser[]] $userList = $CaressService.GetUsers()

    foreach ($aRef in $aRefList)
    {

        [int] $MembershipAlreadyExistCount = 0;
        [MijnCaress.TremUserUserGroup] $memberschip = [MijnCaress.TremUserUserGroup]::new()
        $memberschip.UserSysId = $aRef.SysId
        $memberschip.UsergroupSysId = $pRef.Identification.SysId     
    
        # current memberships are in the "usergroup" field of the user
        foreach ($user in $userList)
        {
            if ($user.SysId -eq  $memberschip.UserSysId)
            {
                foreach ($userGroupSysId in $user.usergroup)
                {
                    if($memberschip.UsergroupSysId -eq $userGroupSysId.SysId)
                    {
                        $MembershipAlreadyExistCount++                       
                    }
                }
                if ($MembershipAlreadyExistCount -gt 0){ break}
            }
        }  

        if (-Not($dR -eq $true)) { 

            [int] $updateResult = 0
            if ($action -eq "Grant") {
                if ($MembershipAlreadyExistCount -eq 0 ){
                    $updateResult = $CaressService.SetUserGroup($memberschip)
                }
            }
            if ($action -eq "Revoke") {
                while ($MembershipAlreadyExistCount -gt 0) {
                    $updateResult = $CaressService.RemoveUsergroup($memberschip)
                    $MembershipAlreadyExistCount--
                }
            }

            if (0 -ne $updateResult)
            {
                $Success = $False
                $auditMessage = " Group membership for person " + $p.DisplayName + " not updated successfully. Could not update membership of $($aRef.userName)";      

                $result = [PSCustomObject]@{
                    Success= $success;
                    AccountReference =  $aRefList     
                    AuditDetails=$auditMessage;
                    Account = [PSCustomObject]@{};
                };
                Write-Output $result | ConvertTo-Json -Depth 10
                [System.Net.Webexception] $updateException = [System.Net.Webexception]::new()
                $updateException.Source = "HelloIDMembershipScript"
                throw ($updateException)
            }        
        }
    }
}
catch [System.Net.Webexception] {
    if ($_.Exception.Source -ne "HelloIDMembershipScript"){
        throw $_
    }
    exit
}
finally{
        $CaressService.DestroySession();
}

$auditMessage = "Group membership for person " + $p.DisplayName + " updated successfully";
$Success = $true
$result = [PSCustomObject]@{
    Success= $success;
    AccountReference =  $aRefList     
    AuditDetails=$auditMessage;
    Account = [PSCustomObject]@{};
};
Write-Output $result | ConvertTo-Json -Depth 10
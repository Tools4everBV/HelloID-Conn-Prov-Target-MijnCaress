$config = ConvertFrom-Json $configuration


if ([Net.ServicePointManager]::SecurityProtocol -notmatch "Tls12") {
    [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
}

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

    if(-Not($dR -eq $true)) {
        [MijnCaress.TremUserGroup[]] $userGroups = $caressService.getuserGroups()        
    }
}
finally{
    $CaressService.DestroySession();
}

$permissions = [System.Collections.Generic.List[psobject]]::new()
foreach ($g in $userGroups) {
    $permission = @{
        DisplayName    = $g.name
        Identification = @{
            Name = $g.name
            SysId = $g.SysId
            Type = $g.Type
        }
    }
    $permissions.add( $permission )
}   

Write-Output ($permissions | ConvertTo-Json)


    
    
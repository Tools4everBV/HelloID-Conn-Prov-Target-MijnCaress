$config = $configuration | ConvertFrom-Json
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
$null = New-WebServiceProxy -Uri $config.wsdlFileSoap  -Namespace 'MijnCaress'
$caressService = [MijnCaress.IinvUserManagementservice]::new();
$caressService.Url = "$($config.urlBase)/soap/InvokableUserManagement/IinvUserManagement"

if ( -not [string]::IsNullOrEmpty($Config.CertificatePath)) {
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New()
    $certificate.Import($Config.CertificatePath, $config.CertificatePassword, 'UserKeySet')
    $null = $caressService.ClientCertificates.Add($certificate)
}
# Proxy needs a certificate to make it work
if ( -not [string]::IsNullOrEmpty($Config.ProxyAddress)) {
    $caressService.Proxy = [System.Net.WebProxy]::New($config.ProxyAddress)
}
$authToken = $CaressService.CreateSession($config.UsernameAPI, $config.PasswordAPI)

if ($authToken) {
    $auth = [MijnCaress.AuthHeader]::New()
    $auth.sSessionId = $authToken;
    $auth.sUserName = $config.UsernameAPI;
    $caressService.AuthHeaderValue = $auth
}
else {
    throw "Could not retrieve authentication token from [$($caressService.Url)] for user [$($config.UsernameAPI)]"
}

$permissions = $caressService.getuserGroups()

$permissions | ForEach-Object { $_ | Add-Member -NotePropertyMembers  @{
        DisplayName    = "$($_.Name) ($($_.type))"
        Identification = @{
            Reference = $_.SysId
        }
    }
}

Write-Output $permissions | ConvertTo-Json -Depth 10



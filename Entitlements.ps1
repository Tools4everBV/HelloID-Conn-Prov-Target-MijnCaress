$config = $configuration | ConvertFrom-Json

$null = New-WebServiceProxy -Uri $config.wsdlFileSoap  -Namespace 'MijnCaress'
$caressService = [MijnCaress.IinvUserManagementservice]::new();
$caressService.Url = $config.urlSoap

if ( -not [string]::IsNullOrEmpty($Config.CertificateSoap)) {
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New()
    $certificate.Import($Config.CertificateSoap, $config.CertificatePassword, 'UserKeySet')
    $null = $caressService.ClientCertificates.Add($certificate)
}
# Proxy needs a certificate to make it work
if ( -not [string]::IsNullOrEmpty($Config.ProxyAddress)) {
    $caressService.Proxy = [System.Net.WebProxy]::New($config.ProxyAddress)
}
$authToken = $CaressService.CreateSession($config.UsernameSoap, $config.PasswordSoap)

if ($authToken) {
    $auth = [MijnCaress.AuthHeader]::New()
    $auth.sSessionId = $authToken;
    $auth.sUserName = $config.UsernameSoap;
    $caressService.AuthHeaderValue = $auth
} else {
    throw "Could not retrieve authentication token from [$($caressService.Url)] for user [$($config.UsernameSoap)]"
}

$permissions = $caressService.getuserGroups()

$permissions | % { $_ | Add-Member -NotePropertyMembers  @{
        DisplayName    = $_.Name
        Identification = @{
            Reference = $_.SysId
        }
    }
}

Write-Output $permissions |ConvertTo-Json -Depth 10




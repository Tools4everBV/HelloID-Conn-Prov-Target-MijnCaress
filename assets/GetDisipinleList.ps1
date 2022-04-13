$config = ConvertFrom-Json $configuration

$null = New-WebServiceProxy -Uri $config.wsdlFileSoap  -Namespace 'MijnCaress'
$caressService = [MijnCaress.IinvUserManagementservice]::new();
$caressService.Url = $config.urlSoap

# $caressService.Proxy = [System.Net.WebProxy]::new($config.ProxyAddress)
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$certificate.Import($Config.CertificateSoap, $config.CertificatePassword, 'UserKeySet')
$null = $caressService.ClientCertificates.Add($certificate)

try {
    $authToken = $CaressService.CreateSession($config.UsernameSoap, $config.PasswordSoap)
    $auth = [MijnCaress.AuthHeader]::New()
    $auth.sSessionId = $authToken;
    $auth.sUserName = $config.UsernameSoap;
    $caressService.AuthHeaderValue = $auth

    $DisciplineList = $caressService.GetDisciplines()
    $DisciplineList | Export-Csv  -Path c:\temp\disiplineList.csv -NoTypeInformation -Encoding UTF8

} catch {
    $_.Exception.Message
    $_.Exception.InnerException.Message
    $_.Exception.InnerException.InnerException.message
}



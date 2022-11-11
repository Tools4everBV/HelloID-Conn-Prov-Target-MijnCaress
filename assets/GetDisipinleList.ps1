$configuration = '[copy paste from target using: write-verbose -verbose $configuration]'

try{
$config = ConvertFrom-Json $configuration

    Write-Verbose "Setup connection with mijnCaress [$($config.wsdlFileSoap)]"
    $null = New-WebServiceProxy -Uri $config.wsdlFileSoap  -Namespace 'MijnCaress'
    $caressService = [MijnCaress.IinvUserManagementservice]::new();
    $caressService.Url = "$($config.urlBase)/soap/InvokableUserManagement/IinvUserManagement"
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New()
    $certificate.Import($Config.certificatePath, $config.CertificatePassword, 'UserKeySet')
    $null = $caressService.ClientCertificates.Add($certificate)

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


    $DisciplineList = $caressService.GetDisciplines()
    $DisciplineList | Export-Csv  -Path "$($config.UserLocationFile)\disiplineList-exportall.csv" -NoTypeInformation -Encoding UTF8

} catch {
    $_.Exception.Message
    $_.Exception.InnerException.Message
    $_.Exception.InnerException.InnerException.message
}



$config = ConvertFrom-Json $configuration
$success = $false

$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $null = New-WebServiceProxy -Uri $config.wsdlFileSoap  -Namespace 'MijnCaress'
    $caressService = [MijnCaress.IinvUserManagementservice]::new()
    $caressService.Url = $config.urlSoap

    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $certificate.Import($Config.CertificateSoap, $config.CertificatePassword, 'UserKeySet')
    $null = $caressService.ClientCertificates.Add($certificate)
    $authToken = $CaressService.CreateSession($config.UsernameSoap, $config.PasswordSoap)

    $auth = [MijnCaress.AuthHeader]::New()
    $auth.sSessionId = $authToken
    $auth.sUserName = $config.UsernameSoap
    $caressService.AuthHeaderValue = $auth

    $success = $true

    $users = $caressService.GetUsers()
    $users | Export-Csv  -Path $config.UserLocationFile  -NoTypeInformation -Encoding UTF8

    $auditLogs.Add([PSCustomObject]@{
            Message = "Successfull created user accounts Cache $($config.UserLocationFile)"
            Action  = 'CreateResource'
            IsError = $false
        })

} catch {
    $auditLogs.Add([PSCustomObject]@{
            Message = "Error: $( $_.Exception.Message)"
            Action  = "CreateResource"
            IsError = $true
        })

} finally {
    # Send results
    $result = [PSCustomObject]@{
        Success   = $success
        AuditLogs = $auditLogs
    }
    Write-Output ($result) | ConvertTo-Json -Depth 10
}

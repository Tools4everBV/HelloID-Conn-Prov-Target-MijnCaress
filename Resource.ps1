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


    $users = $caressService.GetUsers()

    $userList = $users | Select-Object * -ExcludeProperty Usergroup
    $authorizationList = $users | Select-Object @{Name = 'UserSysId'; Expression = { $_.SysId } } -ExpandProperty Usergroup

    $userList | Export-Csv  -Path "$($config.UserLocationFile)\users.csv"  -NoTypeInformation -Encoding UTF8
    $authorizationList | Export-Csv  -Path "$($config.UserLocationFile)\authorization.csv"  -NoTypeInformation -Encoding UTF8

    $success = $true
    $auditLogs.Add([PSCustomObject]@{
            Message = "Successfull created user and authorization Cache at: [$($config.UserLocationFile)]"
            Action  = 'CreateResource'
            IsError = $false
        })

} catch {
    $auditLogs.Add([PSCustomObject]@{
            Message = "Error: $( $_.Exception.Message)"
            Action  = 'CreateResource'
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

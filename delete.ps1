#####################################################
# HelloID-Conn-Prov-Target-MijnCaress-Delete
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

# Account mapping
$account = [PSCustomObject]@{
    SysId          = $aRef           #  $null for new account instead of update
    Status         = 'N'                                # "A" = Active, "N" = Not active
    MustChangePass = 'F' # Note specification is required
    End            = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')
}


try {
    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        $auditLogs.Add([PSCustomObject]@{
                Message = "Delete MijnCaress account from: [$($p.DisplayName)], will be executed during enforcement"
            })
    }
    Write-Verbose "Setup connection with MijnCaress [$($config.wsdlFileSoap)]"
    $null = New-WebServiceProxy -Uri $config.wsdlFileSoap  -Namespace 'MijnCaress'
    $caressService = [MijnCaress.IinvUserManagementservice]::new();
    $caressService.Url = "$($config.urlBase)/soap/InvokableUserManagement/IinvUserManagement"

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New()
    $certificate.Import($Config.CertificatePath, $config.CertificatePassword, 'UserKeySet')
    $null = $caressService.ClientCertificates.Add($certificate)


    if ( -not [string]::IsNullOrEmpty($Config.ProxyAddress)) {
        $caressService.Proxy = [System.Net.WebProxy]::New($config.ProxyAddress)
    }
    $authToken = $CaressService.CreateSession($config.UsernameAPI, $config.PasswordAPI)

    if (-not [string]::IsNullOrEmpty($authToken)) {
        $auth = [MijnCaress.AuthHeader]::New()
        $auth.sSessionId = $authToken;
        $auth.sUserName = $config.UsernameAPI;
        $caressService.AuthHeaderValue = $auth
    }
    else {
        throw "Could not retreive authentication token from $($caressService.Url) for user $($config.UsernameSoap)"
    }

    [MijnCaress.TremSetUser] $newUser = [MijnCaress.TremSetUser]::new()
    $newUser.SysId = $aRef
    $newUser.Status = $account.Status
    $newUser.End = $account.End
    $newUser.MustChangePass = $account.MustChangePass

    Write-Verbose "Deleting MijnCaress account: [$aRef] from: [$($p.DisplayName)]"

    if (-not($dryRun -eq $true)) {
        $null = $caressService.SetUser($newUser)
    }
    $success = $true
    $auditLogs.Add([PSCustomObject]@{
            Message = "Delete account for: [$($p.DisplayName)] was successful."
            IsError = $false
        })

}
catch {
    $success = $false
    $ex = $PSItem
    $errorMessage = "Could not delete MijnCaress account for: [$($p.DisplayName)]. Error: $($ex.Exception.Message)"

    Write-Verbose $errorMessage -Verbose
    $auditLogs.Add([PSCustomObject]@{
            Message = $errorMessage
            IsError = $true
        })
}
finally {
    $result = [PSCustomObject]@{
        Success   = $success
        Auditlogs = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
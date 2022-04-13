#####################################################
# HelloID-Conn-Prov-Target-MijnCaress-Entitlement-Grant
#
# Version: 1.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

try {
    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        $auditLogs.Add([PSCustomObject]@{
                Message = "Grant MijnCaress entitlement: [$($pRef.Reference)] to: [$($p.DisplayName)], will be executed during enforcement"
            })
    }
    Write-Verbose "Setup connection with MijnCaress [$($config.wsdlFileSoap)]"
    $null = New-WebServiceProxy -Uri $config.wsdlFileSoap  -Namespace 'MijnCaress'
    $caressService = [MijnCaress.IinvUserManagementservice]::new();
    $caressService.Url = $config.urlSoap

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New()
    $certificate.Import($Config.CertificateSoap, $config.CertificatePassword, 'UserKeySet')
    $null = $caressService.ClientCertificates.Add($certificate)

    if ( -not [string]::IsNullOrEmpty($Config.ProxyAddress)) {
        $caressService.Proxy = [System.Net.WebProxy]::New($config.ProxyAddress)
    }
    $authToken = $CaressService.CreateSession($config.UsernameSoap, $config.PasswordSoap)

    if (-not [string]::IsNullOrEmpty($authToken)) {
        $auth = [MijnCaress.AuthHeader]::New()
        $auth.sSessionId = $authToken;
        $auth.sUserName = $config.UsernameSoap;
        $caressService.AuthHeaderValue = $auth
    } else {
        throw "Could not retreive authentication token from $($caressService.Url) for user $($config.UsernameSoap)"
    }

    if (-not($dryRun -eq $true)) {
        Write-Verbose "Granting MijnCaress entitlement: [$($pRef.Reference)] to: [$($p.DisplayName)]"

        [MijnCaress.TremUserUserGroup] $memberschip = [MijnCaress.TremUserUserGroup]::new()
        $memberschip.UserSysId = $aRef
        $memberschip.UsergroupSysId = $pRef.Reference
        $null = $CaressService.SetUserGroup($memberschip)
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Message = "Grant MijnCaress entitlement: [$($pRef.Reference)] to: [$($p.DisplayName)] was successful."
                IsError = $false
            })
    }
} catch {
    $success = $false
    $ex = $PSItem
    $errorMessage = "Could not grant MijnCaress entitlement: [$($pRef.Reference)] to: [$($p.DisplayName)]. Error: $($ex.Exception.Message)"

    Write-Verbose $errorMessage -Verbose
    $auditLogs.Add([PSCustomObject]@{
            Message = $errorMessage
            IsError = $true
        })
} finally {
    $result = [PSCustomObject]@{
        Success   = $success
        Auditlogs = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}

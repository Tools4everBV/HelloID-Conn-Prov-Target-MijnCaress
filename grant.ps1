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

    if (-not($dryRun -eq $true)) {
        Write-Verbose "Granting MijnCaress entitlement: [$($pRef.Reference)] to: [$($p.DisplayName)]"

        Write-Verbose "Getting existing authorization from disk [$($config.UserLocationFile)\authorization.csv]"
        $authorizationList = Import-Csv -Path "$($config.UserLocationFile)\authorization.csv"

        $allreadyGranted = $authorizationList.Where({ $_.UserSysId -eq $aRef }).Where({ $_.SysId -eq $pRef.Reference })

        if ($allreadyGranted.count -eq 0) {
            [MijnCaress.TremUserUserGroup] $memberschip = [MijnCaress.TremUserUserGroup]::new()
            $memberschip.UserSysId = $aRef
            $memberschip.UsergroupSysId = $pRef.Reference
            $null = $CaressService.SetUserGroup($memberschip)
        }
        else {
            Write-Verbose "User [$aRef] already granted to group [$($pRef.Reference)]"
        }
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Message = "Grant MijnCaress entitlement: [$($pRef.Reference)] to: [$($p.DisplayName)] was successful."
                IsError = $false
            })
    }
}
catch {
    $success = $false
    $ex = $PSItem
    $errorMessage = "Could not grant MijnCaress entitlement: [$($pRef.Reference)] to: [$($p.DisplayName)]. Error: $($ex.Exception.Message)"

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
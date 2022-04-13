#####################################################
# HelloID-Conn-Prov-Target-MijnCaress-Update
#
# Version: 1.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# Account mapping
$account = [PSCustomObject]@{
    SysId           = $aRef
    Name            = $p.Name.NickName + ' ' + $p.name.FamilyName
    AdUsername      = $p.Accounts.MicrosoftActiveDirectory.SamAccountName
    Username        = $p.Accounts.MicrosoftActiveDirectory.SamAccountName
    # UPN            = $p.Accounts.MicrosoftActiveDirectory.SamAccountName
    Start           = $p.PrimaryContract.StartDate
    End             = $p.PrimaryContract.Enddate
    EmployeeId      = $p.externalId
    # Additional Mapping file is required
    DisciplineSysId = $p.PrimaryContract.Title.Name      # A lookup against the mapping file is perfromed later in the code
    MustChangePass  = 'F' # Mandatory
}

$previousAccount = [PSCustomObject]@{
    SysId           = $aRef
    Name            = $pp.Name.NickName + ' ' + $pp.name.FamilyName
    AdUsername      = $pp.Accounts.MicrosoftActiveDirectory.SamAccountName
    Username        = $pp.Accounts.MicrosoftActiveDirectory.SamAccountName
    # UPN            = $p.Accounts.MicrosoftActiveDirectory.SamAccountName
    Start           = $pp.PrimaryContract.StartDate
    End             = $pp.PrimaryContract.Enddate
    EmployeeId      = $p.externalId
    # Additional Mapping file is required
    DisciplineSysId = $pp.PrimaryContract.Title.Name     # Additional Mapping file is needed between function name en MijnCaress disiplineName
    MustChangePass  = 'F'  # Mandatory
}

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

try {
    $propertiesChanged = (Compare-Object @($previousAccount.PSObject.Properties) @($account.PSObject.Properties) -PassThru)

    if ($null -eq $propertiesChanged) {
        $auditLogs.Add([PSCustomObject]@{
                Message = "Update account for: [$($p.DisplayName)] was successful.(No changes found)"
                IsError = $false
            })
        $success = $true
        continue
    }
    Write-Verbose "Setup connection with mijnCaress [$($config.wsdlFileSoap)]"
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

    # Only update the changed properties
    [MijnCaress.TremSetUser] $newUser = [MijnCaress.TremSetUser]::new()
    foreach ($property in ($propertiesChanged)) {
        $newUser."$($property.name)" = $account.$($property.name)
    }
    $newUser.SysId = $aRef
    $newUser.MustChangePass = "F" # Is always required in API! , bug?

    if ($newUser.DisciplineSysId ) {

        Write-Verbose "Import CSV Discipline MappingFile [$($config.DisciplineMappingFile)"
        $DisciplineMapping = Import-Csv $config.DisciplineMappingFile -Delimiter ';' -Header FunctionName, DisciplineName
        $DisciplineName = ($DisciplineMapping | Where-Object { $_.FunctionName -eq $newUser.DisciplineSysId }).DisciplineName
        if ($null -eq $DisciplineName) {
            throw "No Discipline Name found for [$($newUser.DisciplineSysId)]. Please verify your mapping and configuration"
        }
        Write-Verbose "mijnCaress Disipline Name [$DisciplineName] found with lookup value [$($newUser.DisciplineSysId)]"


        # List is needed for lookup the ID.
        Write-Verbose 'Getting All disciplines'
        $DisciplineList = $caressService.GetDisciplines()
        $DisciplineSysId = ($DisciplineList | Where-Object { $_.Name -eq $DisciplineName }).SysId
        if ($null -eq $DisciplineSysId ) {
            throw "No DisiplineSysId is found on Name [$($DisciplineName)]"
        }
        $newUser.DisciplineSysId = $DisciplineSysId
        $account.DisciplineSysId = $DisciplineSysId
    }


    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        $auditLogs.Add([PSCustomObject]@{
                Message = "Update mijnCaress account for: [$($p.DisplayName)], will be executed during enforcement"
            })
    }

    if (-not($dryRun -eq $true)) {
        Write-Verbose "Updating mijnCaress account: [$aRef] for: [$($p.DisplayName)]"
        $null = $caressService.SetUser($newUser)

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Message = "Update account for: [$($p.DisplayName)] was successful."
                IsError = $false
            })
    }
} catch {
    $success = $false
    $ex = $PSItem
    $errorMessage = "Could not update mijnCaress account for: [$($p.DisplayName)]. Error: $($ex.Exception.Message)"

    Write-Verbose $errorMessage -Verbose
    $auditLogs.Add([PSCustomObject]@{
            Message = $errorMessage
            IsError = $true
        })
} finally {
    $result = [PSCustomObject]@{
        Success   = $success
        Account   = $account
        Auditlogs = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}

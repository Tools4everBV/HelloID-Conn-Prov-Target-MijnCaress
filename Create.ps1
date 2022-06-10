#####################################################
# HelloID-Conn-Prov-Target-MijnCaress-Create
#
# Version: 1.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# Specitfy the HelloID property to map to a MijnCaress Discipline
$DisciplineNameLookUpValue = $p.PrimaryContract.Title.Name

# Account mapping
$account = [PSCustomObject]@{
    SysId          = $null                              #  $null for new account instead of update
    Name           = $p.Name.NickName + ' ' + $p.name.FamilyName
    AdUsername     = $p.Accounts.MicrosoftActiveDirectory.SamAccountName
    Username       = $p.Accounts.MicrosoftActiveDirectory.SamAccountName
    UPN            = $p.Accounts.MicrosoftActiveDirectory.SamAccountName
    Start          = $p.PrimaryContract.StartDate       # "YYYY-MM-dd"
    End            = $p.PrimaryContract.Enddate         # "YYYY-MM-dd"
    Status         = 'N'                                # "A" = Active, "N" = Not active
    EmployeeId     = $p.externalId                      # $p.ExternalId    # The employee number
    DisciplineName = $Null                              # Additional Mapping file is needed between function name en MijnCaress disiplineName
    Password       = 'Welkom01'                         # Will be encrypted
    MustChangePass = 'F'                                # Note specification is required
}

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

# Set to true if accounts in the target system must be updated
$updatePerson = $true

#region functions
function New-DES {
    [CmdletBinding()]
    param( [Parameter(Mandatory)]
        [string]
        $key
    )
    [System.Security.Cryptography.MD5CryptoServiceProvider] $md5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
    [System.Security.Cryptography.TripleDESCryptoServiceProvider] $des = [System.Security.Cryptography.TripleDESCryptoServiceProvider]::new()
    $des.Key = $md5.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($key))
    $des.IV = [System.Byte[]]::New($([int][Math]::Ceiling($des.BlockSize / 8)))
    Write-Output $des
}

function ConvertTo-EncryptedString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $StringToEncrypt,

        [Parameter(Mandatory)]
        [string]
        $EncryptionKey
    )
    [System.Security.Cryptography.TripleDESCryptoServiceProvider] $des = New-DES -key $EncryptionKey
    [System.Security.Cryptography.ICryptoTransform] $cryptoTransform = $des.CreateEncryptor()
    $encryptionInput = [System.Text.Encoding]::Unicode.GetBytes($StringToEncrypt);
    $buffer = $cryptoTransform.TransformFinalBlock($encryptionInput, 0, $encryptionInput.Length)
    Write-Output ([System.Convert]::ToBase64String($buffer))
}
#endregion

try {
    Write-Verbose 'Encrypting Password and search for correct Discipline Name'
    $account.Password = ([string](ConvertTo-EncryptedString -StringToEncrypt $account.Password -EncryptionKey $config.EncryptionKey))
    $DisciplineMapping = Import-Csv $config.DisciplineMappingFile -Delimiter ';' -Header FunctionName, DisciplineName
    $DisciplineName = ($DisciplineMapping | Where-Object { $_.FunctionName -eq $DisciplineNameLookUpValue }).DisciplineName
    if ($null -eq $DisciplineName) {
        throw "No Discipline Name found for [$DisciplineNameLookUpValue]. Please verify your mapping and configuration"
    } elseif ( $DisciplineName.count -gt 1) {
        throw "Multiple Discipline names found [$($DisciplineName -join ', ')] for [$DisciplineNameLookUpValue]. Please verify your mapping and configuration"
    }
    $account.DisciplineName = $DisciplineName

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

    if ($authToken) {
        $auth = [MijnCaress.AuthHeader]::New()
        $auth.sSessionId = $authToken;
        $auth.sUserName = $config.UsernameSoap;
        $caressService.AuthHeaderValue = $auth
    } else {
        throw "Could not retrieve authentication token from [$($caressService.Url)] for user [$($config.UsernameSoap)]"
    }

    # List is needed for lookup the ID.
    Write-Verbose 'Getting All disciplines'
    $DisciplineList = $caressService.GetDisciplines()

    # Verify if a user must be created or correlated
    Write-Verbose "Getting All user accounts from disk [$($config.UserLocationFile)\users.csv]"
    $userList = Import-Csv -Path "$($config.UserLocationFile)\users.csv"

    $employee = $caressService.GetEmployeeById($account.EmployeeId) # throws error if employee not found
    if ($employee) {
        Write-Verbose "Found employee Name: [$($employee.Name)] Id: [$($employee.Id)]"
    }
    [array]$useraccountsFoundOnEmployeeID = $userList.Where({ $_.EmployeeSysId -eq $employee.SysId })
    Write-Verbose "Found [$($useraccountsFoundOnEmployeeID.Count)] users account for employee [$($employee.Id)], account(s) [$($useraccountsFoundOnEmployeeID.Username -join ", ")]"

    $useraccountsOndifferentEmployeeID = $userList.Where({ $_.username -eq $account.Username -and $_.EmployeeSysId -ne $employee.SysId })
    if ($useraccountsOndifferentEmployeeID ) {
        throw "Account with username $($account.Username) allready exist on a different Employee [$($useraccountsOndifferentEmployeeID.EmployeeSysId)]"
    }

    $userAccountFound = $useraccountsFoundOnEmployeeID.Where({ $_.username -eq $account.Username })
    $account.SysId = $userAccountFound.SysId

    if (-not($userAccountFound)) {
        $action = 'Create'
    } elseif ($updatePerson -eq $true) {
        $action = 'Update-Correlate'
    } else {
        $action = 'Correlate'
    }

    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        $auditLogs.Add([PSCustomObject]@{
                Message = "$action mijnCaress account [$($account.Username)] for: [$($p.DisplayName)], will be executed during enforcement"
            })
    }

    # Process
    if (-not($dryRun -eq $true)) {
        switch ($action) {
            'Create' {
                Write-Verbose "Creating mijnCaress account for: [$($p.DisplayName)]"
                [MijnCaress.TremSetUser]$newUser = [MijnCaress.TremSetUser]::new()
                $newUser.SysId = $null
                $newUser.Username = $account.Username
                $newUser.Name = $account.Name
                $newUser.Start = $account.Start
                $newUser.End = $account.End
                $newUser.Status = $account.Status
                $newUser.AdUsername = $account.AdUsername
                $newUser.Password = $account.Password
                $newUser.MustChangePass = $account.MustChangePass
                $newUser.UPN = $account.UPN
                $newUser.EmployeeSysId = $employee.SysId

                # Error Controle
                $DisciplineSysId = ($DisciplineList | Where-Object { $_.Name -eq $account.DisciplineName }).SysId
                if ($null -eq $DisciplineSysId ) {
                    throw "No disiplineSysId found with provided name [$($account.DisciplineName)], make sure you mapping is correct"
                }
                $newUser.DisciplineSysId = $DisciplineSysId

                $createResponse = $caressService.SetUser($newUser)
                $accountReference = $createResponse
            }

            'Update-Correlate' {
                Write-Verbose 'Updating and correlating mijnCaress account'
                [MijnCaress.TremSetUser]$setUser = [MijnCaress.TremSetUser]::new()
                $setUser.SysId = $userAccountFound.SysId
                $setUser.Username = $account.Username
                $setUser.Name = $account.Name
                $setUser.Start = $account.Start
                if (-not [string]::IsNullOrEmpty($userAccountFound.End) -and [string]::IsNullOrEmpty($account.End)) {
                    $setUser.End = '9999-01-01'
                } else {
                    $setUser.End = $account.End
                }
                $setUser.Status = $account.Status
                $setUser.AdUsername = $account.AdUsername
                $setUser.Password = $account.Password
                $setUser.MustChangePass = $account.MustChangePass
                $setUser.UPN = $account.UPN
                $setUser.EmployeeSysId = $employee.SysId

                # Error Controle
                $DisciplineSysId = ($DisciplineList | Where-Object { $_.Name -eq $account.DisciplineName }).SysId
                if ($null -eq $DisciplineSysId ) {
                    throw "No disiplineSysId found with provided name [$($account.DisciplineName)], make sure you mapping is correct"
                }
                $setUser.DisciplineSysId = $DisciplineSysId

                $createResponse = $caressService.SetUser($setUser)
                $accountReference = $userAccountFound.SysId
                break
            }

            'Correlate' {
                Write-Verbose "Correlating mijnCaress account for: [$($p.DisplayName)]"
                $accountReference = $userAccountFound.SysId
                break
            }
        }
        $auditLogs.Add([PSCustomObject]@{
                Message = "$action account for: [$($p.DisplayName)] was successful. accountReference is: [$($accountReference)]"
                IsError = $false
            })
    }
    $success = $true
} catch {
    $success = $false
    $ex = $PSItem
    $errorMessage = "Could not $action mijnCaress account for: [$($p.DisplayName)]. Error: $($ex.Exception.Message)"

    Write-Verbose $errorMessage -Verbose
    $auditLogs.Add([PSCustomObject]@{
            Message = $errorMessage
            IsError = $true
        })
    # End
} finally {
    if ($null -ne $CaressService) {
        $CaressService.DestroySession();
    }
    $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $accountReference
        Auditlogs        = $auditLogs
        Account          = $account
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}

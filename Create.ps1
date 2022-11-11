#####################################################
# HelloID-Conn-Prov-Target-MijnCaress-Create
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()
$action = "process"

# Specitfy the HelloID property to map to a MijnCaress Discipline
$DisciplineNameLookUpValue = $p.PrimaryContract.Title.code

# Specitfy the HelloID correlationfield and value
$correlationField = "salaryEmployeeNr"
$correlationvalue = $account.EmployeeId

#region Support Functions
function Get-RandomCharacters([int]$length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length } 
    $ofs = "" 
    return [String]$characters[$random]
}

function New-RandomPassword() {
    try {
        #passwordSpecifications:
        $length = 8
        $upper = 2
        $number = 2
        $special = 2
        $lower = $length - $upper - $number - $special
      
        $chars = "abcdefghkmnprstuvwxyz"
        $NumberPool = "23456789"
        $specialPool = "!#%^*()"

        $CharPoolLower = $chars.ToLower()
        $CharPoolUpper = $chars.ToUpper()

        $password = Get-RandomCharacters -characters $CharPoolUpper -length $upper
        $password += Get-RandomCharacters -characters $NumberPool -length $number
        $password += Get-RandomCharacters -characters $specialPool -length $special
        $password += Get-RandomCharacters -characters $CharPoolLower -length $Lower

        $passwordArray = $password.ToCharArray()   
        $passwordScrambledArray = $passwordArray | Get-Random -Count $passwordArray.Length     
        $password = -join $passwordScrambledArray

        return $password
    }
    catch {
        throw("An error was thrown while generating password: $($_.Exception.Message): $($_.ScriptStackTrace)")
    }
}

function GenerateName {
    [cmdletbinding()]
    Param (
        [object]$person
    )
    try {
        $initials = $person.Name.Initials -replace "\W"
        $initials = ([string]::Join('.', ([string[]]$initials.ToCharArray()))) + "."
        $FamilyNamePrefix = $person.Name.FamilyNamePrefix
        $FamilyName = $person.Name.FamilyName           
        $PartnerNamePrefix = $person.Name.FamilyNamePartnerPrefix
        $PartnerName = $person.Name.FamilyNamePartner 
        $convention = $person.Name.Convention
        $Name = ""       

        switch ($convention) {
            "B" {
                $Name += $FamilyName
                $Name += ", " + $initials
                $Name += if (-NOT([string]::IsNullOrEmpty($FamilyNamePrefix))) { " " + $FamilyNamePrefix }
            }
            "P" {
                $Name += $PartnerName
                $Name += ", " + $initials
                $Name += if (-NOT([string]::IsNullOrEmpty($PartnerNamePrefix))) { " " + $PartnerNamePrefix }
            }
            "BP" {
                $Name += $FamilyName + " - "
                $Name += if (-NOT([string]::IsNullOrEmpty($PartnerNamePrefix))) { $PartnerNamePrefix + " " }
                $Name += $PartnerName
                $Name += ", " + $initials
                $Name += if (-NOT([string]::IsNullOrEmpty($FamilyNamePrefix))) { " " + $FamilyNamePrefix }
            }
            "PB" {
                $Name += $PartnerName + " - "
                $Name += if (-NOT([string]::IsNullOrEmpty($FamilyNamePrefix))) { $FamilyNamePrefix + " " }
                $Name += $FamilyName
                $Name += ", " + $initials
                $Name += if (-NOT([string]::IsNullOrEmpty($PartnerNamePrefix))) { " " + $PartnerNamePrefix }
                
            }
            Default {
                $Name += $FamilyName
                $Name += ", " + $initials
                $Name += if (-NOT([string]::IsNullOrEmpty($FamilyNamePrefix))) { " " + $FamilyNamePrefix }           
            }
        }      
        return $Name
            
    }
    catch {
        throw("An error was found in the name convention algorithm: $($_.Exception.Message): $($_.ScriptStackTrace)")
    } 
}

function format-date {
    [CmdletBinding()]
    Param
    (
        [string]$date,
        [string]$InputFormat,
        [string]$OutputFormat
    )
    try {
        if (-NOT([string]::IsNullOrEmpty($date))) {    
            $dateString = get-date([datetime]::ParseExact($date, $InputFormat, $null)) -Format($OutputFormat)
        }
        else {
            $dateString = $null
        }

        return $dateString
    }
    catch {
        throw("An error was thrown while formatting date: $($_.Exception.Message): $($_.ScriptStackTrace)")
    }
    
}

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

try {
    # Account mapping
    $account = [PSCustomObject]@{
        SysId           = $null #null for new account instead of update
        Name            = GenerateName -person $p
        AdUsername      = $p.Accounts.MicrosoftActiveDirectory.samAccountName
        Username        = $p.Accounts.MicrosoftActiveDirectory.samAccountName
        UPN             = $p.Accounts.MicrosoftActiveDirectory.UserPrincipalName 
        Start           = format-date -date $p.PrimaryContract.StartDate  -InputFormat 'yyyy-MM-ddThh:mm:ssZ' -OutputFormat "yyyy-MM-dd"
        End             = format-date -date $p.PrimaryContract.EndDate -InputFormat 'yyyy-MM-ddThh:mm:ssZ' -OutputFormat "yyyy-MM-dd"
        Status          = 'N' # "A" = Active, "N" = Not active
        EmployeeId      = $p.ExternalId # $p.ExternalId for lookup. resolved in the sysID of the employee
        DisciplineSysId = $Null  # Additional Mapping file is needed between function name en MijnCaress disiplineName
        Password        = New-RandomPassword  # Will be encrypted
        MustChangePass  = 'T' # Note specification is required
    }

    write-verbose "account: $($account | convertto-json)"

    # Enable TLS1.2
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

    # Set debug logging
    switch ($($config.IsDebug)) {
        $true { $VerbosePreference = 'Continue' }
        $false { $VerbosePreference = 'SilentlyContinue' }
    }

    # Set to true if accounts in the target system must be updated
    $updatePerson = $config.updateOnCorrelate

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

    Write-Verbose "Encrypting Password"
    $PasswordPlainText = $account.Password
    $account.Password = ([string](ConvertTo-EncryptedString -StringToEncrypt $account.Password -EncryptionKey $config.EncryptionKey))
    

    Write-Verbose 'search for correct Discipline Name'
    $DisciplineMapping = Import-Csv $config.DisciplineMappingFile -Delimiter ';' #-Header FunctionName, DisciplineName
    $DisciplineName = ($DisciplineMapping | Where-Object { $_.functionCode -eq $DisciplineNameLookUpValue }).DisciplineName

    write-verbose "$($config.DisciplineMappingFile) contains $(($DisciplineMapping | measure-object).count) rows" 

    if ($null -eq $DisciplineName) {
        throw "No Discipline Name found for [$DisciplineNameLookUpValue]. Please verify your mapping and configuration"
    }
    elseif ( $DisciplineName.count -gt 1) {
        throw "Multiple Discipline names found [$($DisciplineName -join ', ')] for [$DisciplineNameLookUpValue]. Please verify your mapping and configuration"
    }
   
    # List is needed for lookup the ID.
    Write-Verbose 'Getting All disciplines'
    $DisciplineList = $caressService.GetDisciplines()
    $DisciplineSysId = ($DisciplineList | Where-Object { $_.Name -eq $DisciplineName }).SysId
    if ($null -eq $DisciplineSysId ) {
        throw "No DisiplineSysId is found on Name [$($DisciplineName)]"
    }

    $account.DisciplineSysId = $DisciplineSysId

    # List is needed for lookup the ID.
    Write-Verbose 'Getting All disciplines from mijnCaress'
    $DisciplineList = $caressService.GetDisciplines()
    write-verbose "DisciplineList contains $(($DisciplineList | measure-object).count) rows" 

    # Verify if a user must be created or correlated
    Write-Verbose "Getting All user accounts from resource [$($config.UserLocationFile)\users.csv]"
    $userList = Import-Csv -Path "$($config.UserLocationFile)\users.csv"

    write-verbose "$($config.UserLocationFile)\users.csv contains $(($userList | measure-object).count) rows" 


    #search for employee salary number first through REST-API (OPTIONAL)    
    Write-Verbose "Setup connection for mijnCaress REST-API"
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($config.certificatePath, $config.CertificatePassword) 
    $password = ConvertTo-SecureString -String "$($config.passwordAPI)" -AsPlainText -Force 
    $Credentials = New-Object System.Management.Automation.PSCredential ($config.usernameAPI, $password)

    try {

        #enddate filter to search both active and inactive users
        $employee = (Invoke-RestMethod -uri "$($config.urlBase)/employees?$searchField=$searchvalue&checkEmployeeOrganizationalUnitAuthorization=false&endDate=2200-01-01" -Certificate $certificate -Credential $Credentials).employees
        $employee = $employee | sort-object identifier -unique

        if (($employee | measure-object).count -gt 1) {
            write-verbose "$($employee | convertto-json)"
            Throw "multiple ($(($employee | measure-object).count)) employees with salaryEmployeeNr [$($account.EmployeeId)] found"
        }
    }
    catch {

        if ($_.ErrorDetails.Message) {
            $errorMessage = $_.ErrorDetails.Message | convertfrom-json
            Throw "Failed to find employee through rest API - $($errorMessage.ErrorMessage)"
        }
        else {
            Throw "Failed to find employee through rest API - $($_)"
        }
    }

    if ($employee) {
        Write-Verbose "Found employee Name: [$($employee.longName)] Id: [$($employee.Identifier)]"
        $account.EmployeeId = $employee.identifier
    }
    else {
        Throw "Employee not found"
    }
    #end REST-API section

    $employee = $caressService.GetEmployeeById($account.EmployeeId) # throws error if employee not found

    if ($employee) {
        Write-Verbose "Found employee Name: [$($employee.name)] employeeSysid: [$($employee.SysID)]"
        $account.EmployeeId = $employee.SysID
    }
    else {
        Throw "Employee not found"
    }

    [array]$useraccountsFoundOnEmployeeID = $userList.Where({ $_.EmployeeSysId -eq $employee.SysId })
    Write-Verbose "Found ($($useraccountsFoundOnEmployeeID.Count)) users account for employee [$($employee.Id)], account(s) [$($useraccountsFoundOnEmployeeID.Username -join ", ")]"

    $useraccountsOndifferentEmployeeID = $userList.Where({ $_.username -eq $account.Username -and $_.EmployeeSysId -ne $employee.SysId })
    if ($useraccountsOndifferentEmployeeID ) {
        throw "Account with username $($account.Username) allready exist on a different Employee [$($useraccountsOndifferentEmployeeID.EmployeeSysId)]"
    }
    
    write-verbose "selecting user based on username [$($account.Username)]"
    $userAccountFound = $useraccountsFoundOnEmployeeID.Where({ $_.username -eq $account.Username })

    if (-not($userAccountFound)) {
        $action = 'Create'
    }
    elseif ($updatePerson -eq $true) {
        $action = 'Update-Correlate'
    }
    else {
        $action = 'Correlate'
    }

    # Process
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
            $newUser.EmployeeSysId = $account.EmployeeId
            $newUser.DisciplineSysId = $DisciplineSysId

            if (-not($dryRun -eq $true)) {
                $createResponse = $caressService.SetUser($newUser)
                $accountReference = $createResponse
            }
            write-verbose "create newUser: $($newUser | convertto-json)"

            #replace password after create for PlainText
            $account.password = $PasswordPlainText
        }

        'Update-Correlate' {
            $account.SysId = $userAccountFound.SysId
            $account.status = $userAccountFound.status
            $account.MustChangePass = "F"

            Write-Verbose 'Updating and correlating mijnCaress account'
            [MijnCaress.TremSetUser]$setUser = [MijnCaress.TremSetUser]::new()
            
            $setUser.SysId = $userAccountFound.SysId
      
            #keep exisiting logindetails
            $setUser.Status = $null
            $setUser.Username = $null
            $setUser.password = $null
            $setUser.EmployeeSysId = $null


            $setUser.Start = $account.Start

            if ([string]::IsNullOrEmpty($account.End)) {
                $setUser.End = '2200-01-01' #2200; latest possible
            }
            else {
                $setUser.End = $account.End
            }
  
            $setuser.name = $account.name
            $setUser.MustChangePass = $account.MustChangePass
            $setUser.AdUsername = $account.AdUsername
            $setUser.UPN = $account.UPN            
            $setUser.DisciplineSysId = $DisciplineSysId
            
            if (-not($dryRun -eq $true)) {
                $null = $caressService.SetUser($setUser)
            }
            else {
                write-verbose "found user details: $($userAccountFound | convertto-json)"
                write-verbose "correlate/update setUser: $($setUser | convertto-json)"
            }
            $accountReference = $setUser.SysId
            $account.password = $null
            break
        }
        'Correlate' {
            Write-Verbose "Correlating mijnCaress account for: [$($p.DisplayName)]"
            $account.SysId = $userAccountFound.SysId
            $accountReference = $account.SysId

            $account.password = $null
            break
        }
    }
    $auditLogs.Add([PSCustomObject]@{
            Message = "$action account for: [$($p.DisplayName)] was successful. accountReference is: [$($accountReference)]"
            IsError = $false
        })
    $success = $true
}
catch {
    $success = $false
    $ex = $PSItem
    $errorMessage = "Could not $action mijnCaress account for: [$($p.DisplayName)]. Error: $($ex.Exception.Message)"

    Write-Verbose $errorMessage -Verbose
    $auditLogs.Add([PSCustomObject]@{
            Message = $errorMessage
            IsError = $true
        })
    # End
}
finally {
    if ($null -ne $CaressService) {
        $CaressService.DestroySession();
    }


    $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $accountReference
        Auditlogs        = $auditLogs
        Account          = $account

        # Optionally return data for use in other systems
        ExportData       = [PSCustomObject]@{
            AccountReference = $AccountReference
            Username         = $account.username
            name             = $account.name

        }
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
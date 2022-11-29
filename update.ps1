#####################################################
# HelloID-Conn-Prov-Target-MijnCaress-Update
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json

$aRef = $AccountReference | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()
# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

#RN_TEST:
if ($dryRun -eq $true) {
    $p.PrimaryContract.Context.InConditions = $true
}

if ($p.PrimaryContract.Context.InConditions -eq $true) {
    $DisciplineNameLookUpValue = $p.PrimaryContract.Title.code
    $DisciplineNameLookUpValueDetail = $p.PrimaryContract.Title.name
}
else {
    $contracts = $p.contracts | sort-object externalID
    write-verbose  "PrimaryContract not incondition, using first contract in list"

    foreach ($contract in $contracts) {
        if ([boolean]$contract.Context.InConditions -eq $true) {
            write-verbose  "Use contract $($contract.externalID) with title $($contract.Title.code)"

            $DisciplineNameLookUpValue = $contract.Title.code
            $DisciplineNameLookUpValueDetail = $contract.Title.name
            break
        }
    }
}

#region Support Functions

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

function format-length {
    [CmdletBinding()]
    Param
    (
        [string]$string,
        [int]$maxlength
    )
    try {
        if (-NOT([string]::IsNullOrEmpty($string))) {    
            $stringformat = $string.substring(0, [System.Math]::Min($maxlength, $string.length))
        }
        else {
            $stringformat = $null
        }

        return $stringformat
    }
    catch {
        throw("An error was thrown while formatting string: $($_.Exception.Message): $($_.ScriptStackTrace)")
    }
    
}
try {
    # Account mapping
    $account = [PSCustomObject]@{
        SysId           = $aRef
        Name            = format-length -string $(GenerateName -person $p) -maxlength 40
        AdUsername      = format-length -string $p.Accounts.ActiveDirectory.samAccountName -maxlength 20
        UPN             = $p.Accounts.ActiveDirectory.UserPrincipalName
        Start           = format-date -date $p.PrimaryContract.StartDate  -InputFormat 'yyyy-MM-ddThh:mm:ssZ' -OutputFormat "yyyy-MM-dd"
        End             = format-date -date $p.PrimaryContract.EndDate -InputFormat 'yyyy-MM-ddThh:mm:ssZ' -OutputFormat "yyyy-MM-dd"
        DisciplineSysId = $null  # Additional Mapping file is needed between function name en MijnCaress disiplineName
        MustChangePass  = 'F' # Note specification is required
    }

    #Get Previous User:
    Write-Verbose "Getting All user accounts from resource [$($config.UserLocationFile)\users.csv]"
    $userList = Import-Csv -Path "$($config.UserLocationFile)\users.csv"

    write-verbose "$($config.UserLocationFile)\users.csv contains $(($userList | measure-object).count) rows"

    $currentUser = $userList.Where({ $_.SysId -eq $aref })

    if (($currentUser | measure-object).count -ne 1) {
        Throw "Failed to get existing user with sysID $aref"
    }

    $previousAccount = [PSCustomObject]@{
        SysId           = $aRef
        Name            = $currentUser.Name
        AdUsername      = $currentUser.AdUsername
        UPN             = $currentUser.UPN
        Start           = format-date -date $currentUser.start -InputFormat 'yyyy-MM-dd-hh.mm.ss.000000' -OutputFormat "yyyy-MM-dd"
        End             = format-date -date $currentUser.end -InputFormat 'yyyy-MM-dd-hh.mm.ss.000000' -OutputFormat "yyyy-MM-dd"
        DisciplineSysId = $currentUser.DisciplineSysId
        MustChangePass  = 'F'
    }

    # Enable TLS1.2
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

    # Set debug logging
    switch ($($config.IsDebug)) {
        $true { $VerbosePreference = 'Continue' }
        $false { $VerbosePreference = 'SilentlyContinue' }
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

    Write-Verbose 'search for correct Discipline Name'
    $DisciplineMapping = Import-Csv $config.DisciplineMappingFile -Delimiter ';' -encoding UTF8  #-Header: FunctionName, FunctionCode, DisciplineName
    $DisciplineName = ($DisciplineMapping | Where-Object { $_.Functiecode -eq $DisciplineNameLookUpValue }).DisciplineName

    write-verbose "$($config.DisciplineMappingFile) contains $(($DisciplineMapping | measure-object).count) rows" 

    if ($null -eq $DisciplineName) {
        throw "No Discipline Name found for $DisciplineNameLookUpValueDetail [$DisciplineNameLookUpValue]. Please verify your mapping and configuration"
    }
    elseif ( $DisciplineName.count -gt 1) {
        throw "Multiple Discipline names found [$($DisciplineName -join ', ')] for [$DisciplineNameLookUpValue]. Please verify your mapping and configuration"
    }
   
    # List is needed for lookup the ID.
    Write-Verbose 'Getting All disciplines from services'
    $DisciplineList = $caressService.GetDisciplines()
    write-verbose "DisciplineList contains $(($DisciplineList | measure-object).count) rows" 

    $Discipline = $DisciplineList | Where-Object { $_.Name -eq $DisciplineName }

    $DisciplineSysId = $Discipline.SysId
    if ($null -eq $DisciplineSysId ) {
        throw "No DisiplineSysId is found on Name [$($DisciplineName)]"
    }

    $account.DisciplineSysId = $DisciplineSysId
    write-verbose "Found Discipline $($Discipline.name) [$($Discipline.SysId)] for $DisciplineNameLookUpValueDetail [$DisciplineNameLookUpValue]"
     


    $propertiesChanged = (Compare-Object @($previousAccount.PSObject.Properties) @($account.PSObject.Properties) -PassThru) | Sort-Object name -Unique

    if ($null -eq $propertiesChanged) {
        $update = $false
    }
    else {
        $update = $true
    }

    # Only update the changed properties
    [MijnCaress.TremSetUser] $setUser = [MijnCaress.TremSetUser]::new()
    foreach ($property in ($propertiesChanged)) {
        if ($property -ne "username") {            
            $setUser."$($property.name)" = $account.$($property.name)
            write-verbose "$($property.name) changed: $($previousAccount.$($property.name)) >> $($account.$($property.name)) "
        }
    }
    $setUser.SysId = $aRef
    $setUser.MustChangePass = $account.MustChangePass

    if ($propertiesChanged.name -match 'End') {
        # Write-Verbose "Getting current user accounts from disk [$($config.UserLocationFile)\users.csv]"
        # $userList = Import-Csv -Path "$($config.UserLocationFile)\users.csv"
        # $currectUserObject = $userList.Where({ $_.SysId -eq $aref })
        if ([string]::IsNullOrEmpty($account.End)) {
            $setUser.End = '2200-01-01'  #2200; latest possible
        }
    }



    if ($update) {
        Write-Verbose "Updating mijnCaress account: [$aRef] for: [$($p.DisplayName)]"
        write-verbose "setuser: $($setUser | convertto-json)"

        if (-not($dryRun -eq $true)) {
            $null = $caressService.SetUser($setUser)
        }

        $auditLogs.Add([PSCustomObject]@{
                Message = "Update account for: [$($p.DisplayName)] was successful."
                IsError = $false
            })
    }
    else {

        $auditLogs.Add([PSCustomObject]@{
                Message = "Update account for: [$($p.DisplayName)] was successful. (No changes found)"
                IsError = $false
            })

    }
    $success = $true
}
catch {
    $success = $false
    $ex = $PSItem
    $errorMessage = "Could not update mijnCaress account for: [$($p.DisplayName)]. Error: $($ex.Exception.Message)"

    Write-Verbose $errorMessage -Verbose
    $auditLogs.Add([PSCustomObject]@{
            Message = $errorMessage
            IsError = $true
        })
}
finally {
    $result = [PSCustomObject]@{
        AccountReference = $aRef
        Success          = $success
        previousAccount  = $previousAccount
        Account          = $account
        Auditlogs        = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
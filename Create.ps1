
$config = ConvertFrom-Json $configuration
$dR = $dryRun |  ConvertFrom-Json  
$p = $person | ConvertFrom-Json;

$success = $false;
$auditMessage = "Account for person " + $p.DisplayName + " not created or updated successfully";

$accountList = [System.Collections.Generic.list[object]]::new();
$aRefList = [System.Collections.Generic.list[object]]::new();

if ([Net.ServicePointManager]::SecurityProtocol -notmatch "Tls12") {
    [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
}

function New-DES{
    [CmdletBinding()]
    param( [Parameter(Mandatory=$true)]
        [string]
        $key
    )
    [System.Security.Cryptography.MD5CryptoServiceProvider] $md5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
    [System.Security.Cryptography.TripleDESCryptoServiceProvider] $des = [System.Security.Cryptography.TripleDESCryptoServiceProvider]::new()
    $des.Key = $md5.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($key))
    $des.IV =  new-object  -TypeName system.byte[] -ArgumentList $([int][Math]::Ceiling($des.BlockSize / 8))
    return $des
}

function ConvertTo-EncryptedString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $StringToEncrypt,    
   
        [Parameter(Mandatory=$true)]
        [string]
        $EncryptionKey
    )
    [System.Security.Cryptography.TripleDESCryptoServiceProvider] $des = New-DES -key $EncryptionKey
    [System.Security.Cryptography.ICryptoTransform] $cryptoTransform = $des.CreateEncryptor()
    $encryptionInput = [System.Text.Encoding]::Unicode.GetBytes($StringToEncrypt);
    $buffer = $cryptoTransform.TransformFinalBlock($encryptionInput,0,$encryptionInput.Length)   
    return [System.Convert]::ToBase64String($buffer);
}
<#function ConvertTo-DecryptedString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $StringToDecrypt,    
   
        [Parameter(Mandatory=$true)]
        [string]
        $EncryptionKey
    ) 
    [System.Security.Cryptography.TripleDESCryptoServiceProvider] $des = New-DES -key $EncryptionKey
    [System.Security.Cryptography.ICryptoTransform] $cryptoTransform = $des.CreateDecryptor()
    $b = [System.Convert]::FromBase64String($StringToDecrypt)
    [system.byte[]] $Decriptedoutput = $cryptoTransform.TransformFinalBlock($b, 0, $b.Length);
    [string] $decryptedString = [System.Text.Encoding]::Unicode.GetString($Decriptedoutput)
    return $decryptedString
} #>

foreach($contract in $p.contracts){
    $tmpAdUserName = $null
    if ($null -ne $p.accounts){
       if ($null -ne $p.accounts.MicrosoftActiveDirectory){           
            $tmpAdUserName = $p.Accounts.MicrosoftActiveDirectory.SamAccountName 
        }
    }
    [string] $newpassword = "testww_$($p.DisplayName)"
    [string] $encryptedPassword = ConvertTo-EncryptedString -StringToEncrypt $newpassword -EncryptionKey $config.EncryptionKey
    # [string] $DecryptedPassword = ConvertTo-DecryptedString -StringToDecrypt  $EncryptedPassword -EncryptionKey $config.EncryptionKey
    $account = [PSCustomObject]@{     
        Name           = $p.DisplayName        
        AdUsername     = $tmpAdUserName
        Username       = $p.DisplayName + "_" + $contract.ExternalID; #this must be a unique name      
        Start          = $contract.StartDate; # "YYYY-MM-dd"
        End            = $contract.EndDate; # "YYYY-MM-dd"
        Status         = "A"  # "A" = Active, "N" = Not active
        SysId          = 0            #  0 for new account instead of update      
        EmployeeId     = $p.ExternalId     # The employee number
        DisciplineName = "Administratie"  
        Password       = $EncryptedPassword 
        MustChangePass = "F"       #note specification is required         
    }
   $accountList.add($account)

}
# The list of to be created accounts is now determined and in $accountList

# First retreive the authenication token required for al subsequent calls to the system
# And store this in the connection object  

try {
    #serviceProxy = New-WebServiceProxy -uri "$($config.UrlSoap)?wsdl"  -NameSpace "MijnCaress"
    $serviceProxy = New-WebServiceProxy -uri $config.wsdlFileSoap  -NameSpace "MijnCaress"

    $caressService = [MijnCaress.IinvUserManagementservice]::new();
    $caressService.Url = $config.urlSoap

    if ( -not [string]::IsNullOrEmpty($Config.ProxyAddress)) {
        $caressService.Proxy = [System.Net.WebProxy]::new($config.ProxyAddress);
    }     

    if ( -not [string]::IsNullOrEmpty($Config.CertificateSoap)){
        [System.Security.Cryptography.X509Certificates.X509Certificate] $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromCertFile($Config.CertificateSoap);
        $null = $caressService.ClientCertificates.Add($certificate);
    }

    [string] $authToken = $CaressService.CreateSession($config.UsernameSoap,$config.PasswordSoap) 
    
    if (-not [string]::IsNullOrEmpty($authToken)){

        [MijnCaress.AuthHeader] $auth =  [MijnCaress.AuthHeader]::new()
        $auth.sSessionId = $authToken;
        $auth.sUserName = $config.UsernameSoap;     
        $caressService.AuthHeaderValue = $auth              
    }
    else {         
        $message = "Could not retreive authentication token from $($caressService.Url)  for user $($config.UsernameSoap)";      
        throw ($message)                 
    }  

    # so now we have a token, create the account
    foreach ($account in $AccountList){ 
    
        [MijnCaress.TremSetUser] $newUser =  [MijnCaress.TremSetUser]::new()       
        $newUser.Username = $account.Username
        $newUser.Name = $account.Name
        $newUser.Start = $account.Start       
        $newUser.End = $account.End 
        $newUser.Status = $account.Status
        $newUser.AdUsername = $account.AdUsername 
        $newUser.Password = $account.password
        $newUser.MustChangePass = $account.MustChangePass
        
        # Write-Verbose -verbose -Message $account
        if ($null -ne $account.EmployeeId){
            try{
                [MijnCaress.TremEmployee] $employee = $caressService.GetEmployeeById($account.EmployeeId)            
            }
            catch [System.Net.Webexception] {
                $success = $false;
                $auditMessage = "Account for person " + $p.DisplayName + " not created successfully. Could not find associated employee with id $($account.EmployeeId). Message: $($_.Exception.Message)";      
                $result = [PSCustomObject]@{ 
                    Success          =  $success           
                    AuditDetails     = $auditMessage;
                    Account          = $account;
                };
                Write-Output $result | ConvertTo-Json -Depth 10
                [System.Collections.Generic.KeyNotFoundException] $notFoundExeption = [System.Collections.Generic.KeyNotFoundException]::new($auditMessage)
                $notFoundExeption.Source = "HelloIDUserScript"                    
                throw ($notFoundExeption)    
            }   
        }
        if ($null -ne $employee)
        {          
                $newUser.EmployeeSysId = $employee.SysId
        }                         
                    
        [MijnCaress.TremDiscipline[]] $Disciplines =  $caressService.GetDisciplines()
        if ($null -ne $Disciplines)
        {
            foreach ($Discipline in $Disciplines)
            {
                if ($Discipline.Name -eq $account.DisciplineName)
                {
                    $newUser.DisciplineSysId = $Discipline.SysId
                    break;
                }
            }
        }           
        # Write-Verbose -verbose -Message ($newUser  | ConvertTo-Json -Depth 10)
        if(-Not($dR -eq $true)) {
            [bool] $accountExists = $false
            [System.Net.Webexception] $originalException = $null
            try{
                $sysId = $CaressService.Setuser($newUser)
                $Success = $True
                $auditMessage = "Account " + $newUser.Username + " for person " + $p.DisplayName + " created successfully."; 
            }
            catch [System.Net.Webexception]{
                if  ($_.Exception.Response.StatusCode -ne 403){
                    throw $_
                }
                # account probably already existed, so try an update instead of an create
                $accountExists = $true  
                $originalException = $_Exception                                        
            }

            if($accountExists -eq $true) {
                [MijnCaress.TremUser[]] $currentUsers = $CaressService.Getusers()
                foreach ($curUser in $currentUsers){ 
                    if ($curUser.Username -eq $newUser.Username){
                        $newUser.SysId = $curUser.SysId
                        break;
                    }
                }
            }
            if  ($newUser.SysId -eq 0 ){
                # User not found so unable to both create or update
                throw $originalException
            }                   
            # $newUser.SysId now has a value so setuser will perform an update                         
            $sysId = $CaressService.Setuser($newUser)
            $Success = $True
            $auditMessage = "Account " + $newUser.Username + " for person " + $p.DisplayName + " created successfully.";                 
        }

        $aRef = @{userName = $account.Username
        SysID = $sysid} 
        $aRefList.add($aRef)    
    }
}
catch [System.Collections.Generic.KeyNotFoundException]{
    if ($_.Exception.Source -ne "HelloIDUserScript"){
        throw $_
    }
    exit
}
finally
{
    $CaressService.DestroySession();
}

$result = [PSCustomObject]@{ 
    Success          = $success;
    ErrorCode        = 0;
    AccountReference = $aRefList
    AuditDetails     = $auditMessage;
    Account          = $AccountList[0]
};

Write-Output $result | ConvertTo-Json -Depth 10


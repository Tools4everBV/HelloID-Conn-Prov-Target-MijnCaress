## HelloID-Conn-Prov-Target-MijnCaress
This connector is still a work in progress

# functional description

- Creates and updates user accounts in MijnCaress
- Collects existing groups as entitlements, and assignes group memberships via the grant/revoke scripts
- Connects the user account to pre-existing Employee objects in MijnCaress.

Note, it will NOT create the Employee objects in MijnCaress, those are typically synchronized form HR to MijnCaress by MijnCaress itself



# Prerequisites
- an configured local HellId Provisioning agent running powershell version 5
Connection info to be provided by PinkRoccade on activating the web api for a specific implementation:
- an user account and password for an administrive account in your MijnCaress instance. 
- A SSL client certificate (.cer) file. For connecting to the MijnCaress api.
- An Encryption key, used for encrypting the passwords of new user accounts created/updated by HelloID  

# Configuration settings

- Soap web service url 
    Example:  "https://<root url>/soap/InvokableUserManagement/IinvUserManagement"
    The soap endpoint to connect to.
- Soap ssl certificate (Cer) 
    Example: "C:\ProgramData\Tools4ever\HelloID\Provisioning\mijncaress\Certificaat.cer"
    The location of the SSl Client certificate user for the https connection.
- Soap wsdl file location
    Example: "C:\ProgramData\Tools4ever\HelloID\Provisioning\mijncaress\IinvUserManagementservice.wsdl"      
    The location of the wsdl file with the web service interface specification.  This location needs to be accessible from the computer running the helloid provisioning agent. Copy the .wsdl file available in this git repo to the specified location.
- User name (Soap) 
    The user name of the account with wich the HelloID provisioning agent connects to Mijncaress to perform all operations.  
- Password
    Password of the above connection account
- Proxy Address
    Example "http//localhost:8888"
    Optional proxy server address
- Encryption key
     A long string representing the Encryption key used for encrypting the passwords of the Mijncaress user accounts, when they are sent to the MijnCaress api.  


# peculiarities

- There can be more than 1 MijnCaress user account coupled to the same employee. Therefore the source user account information is assumed to be in the Contracts  section of the person object that is to be created or updated.
This means that person create and person update scripts in hello id each both may create and update user accounts, and they use the same .ps1 script in this implementation
- The fields Username, Name, Password and Start are mandatory in the api when creating new user accounts.
- The field "MustChangePass" is required to be present on user account updates in the api.
- The EmployeeId is taken from the $p.ExternalId field.

# Description of the available ps1 scripts

- Create.ps1

It creates an $accountList variable of all the accounts that must be created or updated (from the info in the person and contracts).  For each contract, it will create a new user, or update an existing account if the user account already exists.  
For updating persons, this same script can be used 

- Entitlements.ps1
Collects all the user groups

-Grant.ps1
Grants the entitlement to all user accounts of the user

Change the first line in the script to  $action = "Revoke"  to change it in a revoke script





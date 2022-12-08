# HelloID-Conn-Prov-Target-mijnCaress


| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-MijnCaress/blob/main/assets/mijnCaress-logo-zonder-tekst.png" style="height:200px">
</p>

## Table of contents

- [Introduction](#Introduction)
- [Getting started](#Getting-started)
  + [Connection settings](#Connection-settings)
  + [Prerequisites](#Prerequisites)
  + [Remarks](#Remarks)
- [Setup the connector](@Setup-The-Connector)
- [Getting help](#Getting-help)
- [HelloID Docs](#HelloID-docs)

## Introduction

_HelloID-Conn-Prov-Target-mijnCaress_ is a _target_ connector. mijnCaress provides a set of REST APIs that allow you to programmatically interact with its data. The connector contains **User and Authorization management** and relies on an existing employee object in mijnCaress. Managing Employees is out of scope.


## Getting started

By using this connector you will have the ability to create one of the following items in mijnCaress:

- Create user account
- Enable user account
- Disable user account
- Delete user account  *(Same as disable + add an enddate)*
- Manage permissions **UserGroups** (grant / revoke)

### Connection settings

The following settings are required to connect to the API.

| Setting      | Description                        | Mandatory   |
| ------------ | -----------                        | ----------- |
| UrlSoap     | The soap endpoint to connect to. Example: "https://\<Customer>.mijnCaress.nl/soap/InvokableUserManagement/IinvUserManagement"  | Yes         |
| CertificateSoap     | The fullpath of the SSL certificate (.pfx) file| Yes         |
| CertificatePassword     | The password of the SSL certificate | Yes         |
| WsdlFileSoap     | The location of the wsdl file with the web service interface specification. This location needs to be accessible from the computer running the helloid provisioning agent. Copy the .wsdl file available in this git repo to the specified location.| Yes         |
| UsernameSoap     | The UserName to connects to mijnCaress  | Yes         |
| PasswordSoap     | The Password to connect to mijnCaress | Yes         |
| Encryptionkey      | This Key is a supplier Key. A long string representing the Encryption key used for encrypting the passwords of the mijnCaress user accounts.              | Yes         |
| IsDebug      | When toggled, debug logging will be displayed      | Yes         |
| UserLocationFile      | A location that is accessible by the directory agent. To create a lookup file with the existing users and authorizations in mijnCaress Example: C:\Workingdir (These files are created in the resource script)     | Yes         |
| DisciplineMappingFile  | The location of the mapping file between Function Title and mijnCaress discipline *C:\mijnCaress\DisciplineMapping.csv*.  An Example of a mapping file can be found in the assets folder.         | Yes         |

### Configuration Settings
 Make sure to set the Concurrent Action limited to one and runs on a local agent server, because of a possible error with removing the Caress Session. In our test environment, it happened that the wrong session was closed.

###Script Settings

```powershell
# Specitfy the HelloID property to map to a mijnCaress Discipline
$DisciplineNameLookUpValue = $p.PrimaryContract.Title.Name

# Specitfy the HelloID correlationfield and value
$correlationField = "salaryEmployeeNr"
$correlationvalue = $account.EmployeeId
```


### Prerequisites

- A SSL certificate (.pfx) file. For connecting to the mijnCaress webservice.
- User credentials to access the mijnCaress Webservice
- Take note of the settings you can find in the connection Settings.
- An Encryption key, used for encrypting and decrypting passwords of new users created by HelloID
- Determine the Property EmployeeId with contains a link to the employee Object. And determine the property to correlate existing user accounts. The connector currently correlate users on the username and optional on the salaryNumber through the rest-API
- A mapping file between a HelloID person's function or title and a MijnCaress Discipline. In the assets folder you can find a CSV example file and a stand-alone script to retrieve the disciplines.

### Remarks
- In mijnCaress it is possible to have multiple users accounts for a single employee. But this is not commonly used across mijnCaress implementation. The connector is created based on the primary contract, which results in 1 HelloID person having 1 mijnCaress account.
- The errors returned by the webservice do not always describe the actual issue. For instance
- This error may be occurring: 
  - **"Access violation at address 00000000027E92E4 in module 'CaressApplicatieServer.exe'. Read of address FFFFFFFFFFFFFFFF"**. This is returned whether there is some wrong within input like the "name" property contains too many characters or a special character.
    - name max = 40
    - adusername max = 20
  - **"HTTP Status 500 – Internal Server ErrorType Exception ReportDescription The server encountered an unexpected condition that prevented it from fulfilling the request.Exceptionjava.lang.NullPointerException Note The full stack trace of the root cause is available in the server logs.Apache Tomcat/x.x.xx"** This is returned when the response body is too big, caused by, for example, too many function lines.
- The fields Username, Name, UPN, Password and Start are mandatory in the API when creating new user accounts.
- The MustChangePassword Property is always a mandatory field for updating an account. You must specify "T" or "F"
- The MustChangePassword Property is turned off when a update event is triggerd, it's not possible to get the current state.
- You cannot request a single user account. The webservice contains only a List request. This request can take up to 50 seconds to retrieve the complete list of users. Therefore, the connector works with a local cache file where the existing users are saved. This file is created and updated in the resource script before each enforcement.

- You can add the same group multiple times to an user account. And the revoke web call removes a group one by one. To minimal incorrect group assignments the grant scripts checks first if the user is already granted to the usergroup, and if so the actual grant is skipped. But keep this in mind when implementing the connector

- You cannot clear a property. You can only update properties. This means when a property must cleared you have to send a new value. For the end date, you can send a date in the future until 2200-01-01 The connector solves the end date problem. And it will set the date 2200-01-01 if exsiting MijnCaress account has an Enddate and the HelloID account does not have an end date.


## Getting help

> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/

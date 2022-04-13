# HelloID-Conn-Prov-Target-mijnCaress

| :warning: Warning |
|:---------------------------|
| Note that this connector is **'a work in progress'** and therefore not ready to use in your  production environment.       |

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

<p align="center">
  <img src="https://www.mijncaress.nl/wp-content/uploads/2021/01/mijncaresslogoretina.png">
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
- Manage permissions (grant / revoke)

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
| Encryptionkey      | A long string representing the Encryption key used for encrypting the passwords of the mijnCaress user accounts, when they are sent to the mijnCaress API.                 | Yes         |
| IsDebug      | When toggled, debug logging will be displayed      | Yes         |
| UserLocationFile      | A location that is accessible by the directory agent. To create a lookup file with the existing users from mijnCaress Example: C:\Workingdir\usercache.csv         | Yes         |
| DisciplineMappingFile  | The location of the mapping file between Function Title and mijnCaress discipline *C:\mijnCaress\DisciplineMapping.csv*.  An Example of a mapping file can be found in the assets folder.         | Yes         |

### Configuration Settings
 Make sure to set the Concurrent Action limited to one and runs on a local agent server, because of a possible error with removing the Caress Session. In our test environment, it happened that the wrong session was closed.

###Script Settings

```powershell
# Specitfy the HelloID property to map to a mijnCaress Discipline
$DisciplineNameLookUpValue = $p.PrimaryContract.Title.Name
```


### Prerequisites

- A SSL certificate (.pfx) file. For connecting to the mijnCaress webservice.
- User credentials to access the mijnCaress Webservice
- Take note of the settings you can find in the connection Settings.
- An Encryption key, used for encrypting the passwords of new user accounts created by HelloID
- Determine the Property EmployeeId with contains a link to the employee Object. And determine the property to correlate existing user accounts. The connector currently uses the username.
- A mapping file between a HelloID person's function or title and a MijnCaress Discipline. In the assets folder. You can find a CSV example file and a stand-alone script to retrieve the disciplines.

### Remarks
- If the "UPN" property is empty on the user account you want to update. It is a mandatory property. When the "UPN" property contains already a value it's optional.
- The property UPN is not in the current WSDL (saved in this repo) so it cannot be set via PowerShell. The class TremSetUser does contains the property. When this property is needed the WSDL needs to be updated.

- In mijnCaress it is possible to have multiple users accounts for a single employee. But this is not commonly used across mijnCaress implementation. The connector is created based on the primary contract, which results in 1 HelloID person having 1 mijnCaress account.
- The errors returned by the webservice do not always describe the actual issue. For instance, this error may be occurring: **"Access violation at address 00000000027E92E4 in module 'CaressApplicatieServer.exe'. Read of address FFFFFFFFFFFFFFFF"**. This is returned whether there is some wrong within input like the "name" property contains too many characters.
- The fields Username, Name, Password and Start are mandatory in the API when creating new user accounts.
- You cannot request a single user account. The webservice contains only a List request. This request can take up to 50 seconds to retrieve the complete list of users. Therefore, the connector works with a local cache file where the existing users are saved. This file is created and updated in the resource script before each enforcement.

Under investigation:
- You can add the same group multiple times to the same user account. And the revoke web call removes a group one by one. *(Send a query to the supplier for explanation)*
- The MustChangePassword Property is a Mandatory field for updating an account. You must specify "T" or "F" *(Send a query to the supplier for explanation)*
- You cannot clear a property, you can only update properties *(Send a query to the supplier for explanation)*


## Setup the connector

> _How to setup the connector in HelloID._ Are special settings required. Like the _primary manager_ settings for a source connector.

## Getting help

> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/

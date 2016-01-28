# DSCAutomation Module

A suite of tools for fully automated deployments of a DSC Pull server and its clients.

### Changelog

#### 1.0.1
- Fix LCM CertificateID configuration on Pull server  

#### 1.0.0 
- Initial release closely based on the rsBoot POC by Rackspace Windows Automation team.
- Created a shared library of functions and cmdlets for use as part of the pull server and client management process
- Convert all management scripts to functions
- Moved all MOF management tasks to run as part of a scheduled job, outside of the PULL DSC configuration 
- Support integrated Arnie API service for PULL server configuration sync with GitHub and managed client registration
- Registration client certificate now used as part of new client registrations
- New functions to support for secrets encryption of pull server settings and client databags
- Improvements to `boot.ps1` bootstrap script for building new pull servers and their clients
- New housekeeping task to remove client artefacts that have not checked in for 7 days

## Example usage

### Manual deployment

**Server**

To build a pull server, use the following command and replace the <highlighted> parameters with suitable values: 
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/DSCAutomation/1.0.1/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
& 'C:\Boot.ps1' -PullServerConfig 'rsPullServer.ps1' -GitOAuthToken "<YourGitOAuthToken>" -GitOrgName "<GitOrgName" -GitRepoName "<ConfigRepoName>" -GitRepoBranch "<ConfigRepoBranch>" -Verbose
```
To use a DNS name for your pull server, please remember to provide this optional parameter at the time of executing boot script: `-PullServerAddress "pull.domain.local"` 

**Client**

Before you can bootstrap a client, you need to retrieve the auto-generated registration certificate from the pull server using this command:
```PoSh
Get-DSCClientRegistrationCert
```
The above will generate a base64-encoded string that contains the registration certificate which then needs to be passed to client bootstrap script in order to authenticate it with the pull server. Copy the full text output of this command and use on the client as part of its bootstrap command: 

```PoSh
$RegKey = @'
<Client registration certificate base64 string as provided by Get-DSCClientRegistrationCert on PULL server>
'@
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/DSCAutomation/1.0.1/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
& c:\boot.ps1 -PullServerAddress '<PullServerIP_or_FQDN>' -ClientConfig 'client.ps1' -Verbose -RegistrationKey $RegKey

```


### Deployment with a pre-bootstrap script

You can specify a script (located in '<DSCAutomation Module root>/scripts' folder) to execute before most of the bootstrap code runs, in cases where you have to wait on other environment components to complete.
*Client*
```PoSh
& c:\boot.ps1 -PullServerAddress '<PullServerIP_or_FQDN>' -ClientConfig 'client.ps1' -Verbose -RegistrationKey $RegKey -PreBootScript @{"RackspaceCloud.ps1" = ""}
```

**Notes on PreBoot option:**

PreBoot scripts can be passed parameters too as a hashtable if the script requires these:
```
-PreBootScript @{"RackspaceCloud.ps1" = @{"param1" = "value"; "param2" = "value"}}
``` 

We can also pass multiple PreBoot scripts to be executed in particular order and with their own parameters:

```
-PreBootScript [ordered]@{"s1.ps1" = @{"param1" = "test";"param2" = "test2"};
					      "s2.ps1" = @{"param2" = "test"}};
```
The above will first execute the scripts in this order:
```
> s1.ps1 -param1 "test" -param2 "test2"
> s2.ps1 -param2 "test"
```

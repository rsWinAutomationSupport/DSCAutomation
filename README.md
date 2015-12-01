# DSCAutomation Module

A suite of tools for fully automated deployment of a DSC Pull server and clients.

### Changelog

- Initial release based on the rsBoot proof of concept. 

## Example usage

### Basic or manual deployment
#### IP address for Pull server
*Server*
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/DSCAutomation/staging/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                    "branch_rsConfigs" = "<source_config_branch";
                    "mR" = "<config_repo_name>";
                    "git_username" = "<gir_org/username>";
                    "gitBr" = "v1.0.3";
                    "git_oAuthToken" = "..................";
                    "shared_key" = ".................."
                    }
& 'C:\boot.ps1' -PullServerConfig 'rsPullServer.ps1' -BootParameters $BootParameters -Verbose
```
*Client*
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/ModulePOC/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                        "dsc_config" = "Template-Client.ps1";
                        "shared_key" = "..................";
                        "PreBoot" = @{"RackspaceCloud.ps1" = ""}
                   }
& 'C:\boot.ps1' -PullServerAddress "0.0.0.0" -BootParameters $BootParameters -Verbose
```

#### Using DNS address for Pull server:
*Server*
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/DSCAutomation/staging/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                    "branch_rsConfigs" = "<source_config_branch";
                    "mR" = "<config_repo_name>";
                    "git_username" = "<gir_org/username>";
                    "gitBr" = "v1.0.3";
                    "git_oAuthToken" = "..................";
                    "shared_key" = ".................."
                    }
& 'C:\boot.ps1' -PullServerAddress "pull.domain.local" -PullServerConfig 'rsPullServer.ps1' -BootParameters $BootParameters -Verbose
```
*Client*
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/DSCAutomation/staging/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                        "dsc_config" = "Template-Client.ps1";
                        "shared_key" = "..................";
                   }
& 'C:\boot.ps1' -PullServerAddress "pull.domain.local" -BootParameters $BootParameters -Verbose
```

### Deployment with a prebootstrap script

*Server*
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/DSCAutomation/staging/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                    "branch_rsConfigs" = "<source_config_branch";
                    "mR" = "<config_repo_name>";
                    "git_username" = "<gir_org/username>";
                    "gitBr" = "v1.0.3";
                    "git_oAuthToken" = "..................";
                    "shared_key" = "..................";
					"PreBoot" = @{"RackspaceCloud.ps1" = ""};
                    }
& 'C:\boot.ps1' -PullServerConfig 'rsPullServer.ps1' -BootParameters $BootParameters -Verbose
```
*Client*
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/DSCAutomation/staging/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                    "dsc_config" = "Template-Client.ps1";
                    "shared_key" = "..................";
                    "PreBoot" = @{"RackspaceCloud.ps1" = ""}
                   }
& 'C:\boot.ps1' -PullServerAddress "0.0.0.0" -BootParameters $BootParameters -Verbose
```

**Notes on PreBoot option:** 
PreBoot scripts can be passed parameters too as a hashtable:
```
"PreBoot" = @{"RackspaceCloud.ps1" = @{"param1" = "test"; "param2" = "test2"}}
``` 

We can also pass multiple PreBoot scripts to be executed in particular order and with their own parameters:

```
"PreBoot" = [ordered]@{"s1.ps1" = @{"param1" = "test";"param2" = "test2"};
					   "s2.ps1" = @{"param2" = "test"}};
```
The above will first execute the scripts in this order:
```
> s1.ps1 -param1 "test" -param2 "test2"
> s2.ps1 -param2 "test"
```
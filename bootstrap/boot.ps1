<#
.Synopsis
   Bootstrap script for initialising a DSC Pull server or one of its clients.
.DESCRIPTION
   Bootstrap script for initialising a DSC Pull server or one of its clients.
.EXAMPLE
   boot.ps1 -PullConfig "rsPullServer.ps1" -BootParameters @{} -Verbose

   Bootstrap a DSC Pull server
.EXAMPLE
   boot.ps1 -BootParameters @{} -Verbose
   
   Bootstrap a Client
#>
#requires -Version 4.0

[CmdletBinding()]
Param
(
    [string]
    $InstallPath = (Join-Path $env:ProgramFiles -ChildPath DSCAutomation),

    # URL for the Zip file to download the main DSCAutomation module
    [string]
    $BootModuleZipURL = "https://github.com/rsWinAutomationSupport/DSCAutomation/archive/aa-updates.zip",

    [string]
    $BootModuleName = "DSCAutomation",

    [string]
    $DSCbootMofFolder = (Join-Path "$env:windir\Temp" -ChildPath DSCBootMof),

    [int]
    $PullServerPort = 8080,

    [string]
    $NetworkTestTarget = "github.com",

    [string]
    $ClientRegCertName = "DSC Client Registration Cert",

    [string]
    $LogName = "DSCAutomation",

    [string]
    $PreBootScript,

    # Enable WinRM on the system
    [switch]
    $AddWinRMListener = $false,

    [Parameter(ParameterSetName="PullServer", Mandatory=$true)]
    [string]
    $PullServerConfig,

    [Parameter(ParameterSetName="PullServer", Mandatory=$true)]
    [string]
    $GitOAuthToken,

    [Parameter(ParameterSetName="PullServer", Mandatory=$true)]
    [string]
    $GitOrgName,

    [Parameter(ParameterSetName="PullServer", Mandatory=$true)]
    [string]
    $GitRepoName,

    [Parameter(ParameterSetName="PullServer", Mandatory=$true)]
    [string]
    $GitRepoBranch,

    [Parameter(ParameterSetName="PullServer", Mandatory=$false)]
    [string]
    $GitSourceUrl = "https://github.com/git-for-windows/git/releases/download/v2.6.2.windows.1/Git-2.6.2-64-bit.exe",

    [Parameter(ParameterSetName="Pullserver", Mandatory=$false)]
    [string]
    $GitInstallDir  = "$env:ProgramFiles\Git\",

    [Parameter(ParameterSetName="PullServer", Mandatory=$false)]
    [string]
    $GitPackageName = "Git version 2.6.2",

    [Parameter(ParameterSetName="PullServer", Mandatory=$false)]
    [string]
    $PackageManagerTag = "1.0.4",

    [Parameter(ParameterSetName="PullServer", Mandatory=$false)]
    [string]
    $NodeDataPath = (Join-Path $InstallPath -ChildPath NodeData.json),

    [Parameter(ParameterSetName="PullServer", Mandatory=$false)]
    [string]
    $RegQueueName = "DSCAutomation",

    [Parameter(ParameterSetName="PullServer", Mandatory=$false)]
    [string]
    $ClientDSCCertName = "$($env:COMPUTERNAME)_dsccert",

    [Parameter(ParameterSetName="Client",Mandatory=$true)]
    [string]
    $RegistrationKey,

    [Parameter(ParameterSetName="Client",Mandatory=$true)]
    [string]
    $ClientConfig,

    [Parameter(ParameterSetName="Client",Mandatory=$false)]
    [int]
    $ConfigurationModeFrequencyMins = 30,

    [Parameter(ParameterSetName="Client",Mandatory=$false)]
    [int]
    $RefreshFrequencyMins = 30,

    # Client: Valid FQDN Hostname or IP Address of the pull server
    # PullServer: Valid FQDN, not required if using IPs
    [Parameter(ParameterSetName="PullServer", Mandatory=$false)]
    [Parameter(ParameterSetName="Client", Mandatory=$true)]
    [string]
    $PullServerAddress
)

#########################################################################################################
#region Local environment configuration
#########################################################################################################

# Bootstrap log configuration
$TimeDate = (Get-Date -Format ddMMMyyyy_hh-mm-ss).ToString()
$LogPath = (Join-Path $env:SystemRoot -ChildPath "Temp\DSCBootstrap_$TimeDate.log")

Start-Transcript -Path $LogPath -Force

Write-Verbose "Configuring local environment..."
Write-Verbose "Setting LocalMachine execurtion policy to RemoteSigned"
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force

Write-Verbose "Setting environment variables"
[Environment]::SetEnvironmentVariable('defaultPath',$InstallPath,'Machine')

Write-Verbose " - Install path: $InstallPath"
Write-Verbose " - NodeInfoPath location: $NodeInfoPath"

if (-not(Test-Path $InstallPath))
{
    Write-Verbose "Creating configuration directory: $InstallPath"
    New-Item -Path $InstallPath -ItemType Directory
}
else
{
    Write-Verbose "Configuration directory already exists"
}

Write-Verbose "Setting folder permissions for $InstallPath"
Write-Verbose " - Disable persmission inheritance on $InstallPath"
$objACL = Get-ACL -Path $InstallPath
$objACL.SetAccessRuleProtection($True, $True)
Set-ACL $InstallPath $objACL

Write-Verbose " - Removing BUILTIN\Users access to $InstallPath"
$colRights = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute" 
$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None 
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None 
$objType =[System.Security.AccessControl.AccessControlType]::Allow 
$objUser = New-Object System.Security.Principal.NTAccount("BUILTIN\Users") 
$objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
    ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType) 
$objACL = Get-ACL -Path $InstallPath
$objACL.RemoveAccessRuleAll($objACE) 
Set-ACL $InstallPath $objACL
#endregion

#########################################################################################################
#region Bootstrap DSC Configuration definitions for Pull Server (PullBoot) and Client (ClientBoot)
#########################################################################################################

#region Initial Pull Server DSC Configuration
Configuration PullBoot
{  
    param 
    (
        [hashtable] $BootParameters
    )
    node $env:COMPUTERNAME 
    {
        File CreateInstallDir
        {
            DestinationPath = $BootParameters.InstallPath
            Ensure = 'Present'
            Type = 'Directory'
        }
        Script DSCAutomationLog
        {
            GetScript = { 
                $LogName = $using:BootParameters.LogName
                return @{
                    "LogName" = $LogName
                    "Present" = ([bool](Get-EventLog -List | Where-Object -FilterScript {$_.Log -eq $LogName}))
                }
            }
            SetScript = {
                $LogName = $using:BootParameters.LogName
                New-Eventlog -source $LogName -logname $LogName
            }
            TestScript = {
                $LogName = $using:BootParameters.LogName
                return ([bool](Get-EventLog -List | Where-Object -FilterScript {$_.Log -eq $LogName}))
            }
        }
        Script GetWMF4 
        {
            SetScript = {
                $Uri = 'http://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu'
                Write-Verbose "Downloading WMF4"
                Invoke-WebRequest -Uri $Uri -OutFile 'C:\Windows\temp\Windows6.1-KB2819745-x64-MultiPkg.msu' -UseBasicParsing
            }

            TestScript = {
                if( $PSVersionTable.PSVersion.Major -ge 4 ) 
                {
                    return $true
                }
                if( -not (Test-Path -Path 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu') ) 
                {
                    Write-Verbose "WMF4 Installer not found locally"
                    return $false
                }
                else
                {
                    return $true
                }
            }

            GetScript = {
                return @{
                    'Result' = 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu'
                }
            }
        }
        Script InstallWMF4 
        {
            SetScript = {
                Write-Verbose "Installing WMF4"
                Start-Process -Wait -FilePath 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu' -ArgumentList '/quiet' -Verbose
                Write-Verbose "Setting DSC reboot flag"
                Start-Sleep -Seconds 30
                $global:DSCMachineStatus = 1 
            }
            TestScript = {
                if($PSVersionTable.PSVersion.Major -ge 4) 
                {
                    return $true
                }
                else 
                {
                    Write-Verbose "Current PowerShell version is lower than the requried v4"
                    return $false
                }
            }
            GetScript = {
                return @{'Result' = $PSVersionTable.PSVersion.Major}
            }
            DependsOn = '[Script]GetWMF4'
        }
        Package InstallGit 
        {
            Name      = $BootParameters.GitPackageName
            Path      = $BootParameters.GitSourceUrl
            ProductId = ""
            Arguments = "/VERYSILENT /DIR $($BootParameters.GitInstallDir)"
            Ensure    = 'Present'
        }
        Environment GitPath
        {
            Ensure    = "Present"
            Name      = "Path"
            Value     = (Join-Path $($BootParameters.GitInstallDir) "bin")
            Path      = $true
            DependsOn = "[Package]InstallGit"
        }
        Script UpdateGitConfig 
        {
            SetScript = {
                # Ensure that current path variable is up-to-date
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                
                Write-Verbose "Configuring git client user name and e-mail settings"
                Start-Process -Wait 'git.exe' -ArgumentList "config --system user.email $env:COMPUTERNAME@localhost.local"
                Start-Process -Wait 'git.exe' -ArgumentList "config --system user.name $env:COMPUTERNAME"
            }
            TestScript = {
                # Ensure that current path variable is up-to-date
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                $GitConfig = & git config --list

                if( [bool]($GitConfig -match "user.email=$env:COMPUTERNAME") -and [bool]($GitConfig -match "user.name=$env:COMPUTERNAME") )
                {
                    return $true
                }
                else
                {
                    Write-Verbose "Git client user email and name are not set as required"
                    return $false
                }
            }
            GetScript = {
                # Ensure that current path variable is up-to-date
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                $GitConfig = & git config --list
                @{"Result" = $($GitConfig -match $env:COMPUTERNAME)}
            }
            DependsOn = '[Environment]GitPath'
        }
        Script Clone_rsConfigs 
        {
            SetScript = {
                # Ensure that current path variable is up-to-date
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                # doing this only to help code readability
                $BootParams = $using:BootParameters
                $ConfigRepoURL = "https://$($BootParams.GitOAuthToken)@github.com/$($BootParams.GitOrgName)/$($BootParams.GitRepoName).git"
                $gitArguments = "clone --branch $($BootParams.GitRepoBranch) $ConfigRepoURL"
                
                Set-Location $BootParams.InstallPath -Verbose
                $RepoPath = Join-Path -Path $BootParams.InstallPath -ChildPath $BootParams.GitRepoName
                if (Test-Path $RepoPath)
                {
                    Write-Verbose "Existing config folder found - deleting..."
                    Remove-Item $RepoPath -Force -Recurse
                }

                Write-Verbose "Cloning DSC configuration repository"
                Start-Process -Wait 'git.exe' -ArgumentList $gitArguments
            }
            TestScript = {
                # We will always return false to make sure that we run the Set script every time
                return $false
            }
            GetScript = {
                $BootParams = $using:BootParameters
                return @{'Result' = (Test-Path -Path $(Join-Path $BootParams.InstallPath $BootParams.GitRepoName) -PathType Container)}
            }
            DependsOn = '[Script]UpdateGitConfig'
        }
        File rsPlatformDir 
        {
            SourcePath      = (Join-Path $BootParameters.InstallPath "$($BootParameters.GitRepoName)\rsPlatform")
            DestinationPath = 'C:\Program Files\WindowsPowerShell\Modules\rsPlatform'
            Type            = 'Directory'
            Recurse         = $true
            MatchSource     = $true
            Ensure          = 'Present'
            DependsOn       = '[Script]Clone_rsConfigs'
        }
        Script ClonersPackageSourceManager 
        {
            SetScript = {
                # Ensure that current path variable is up-to-date
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                # doing this only to help code readability
                $BootParams = $using:BootParameters
                Set-Location 'C:\Program Files\WindowsPowerShell\Modules\'
                Write-Verbose "Cloning the rsPackageSourceManager module"
                Start-Process -Wait 'git.exe' -ArgumentList "clone --branch $($BootParams.PackageManagerTag) https://github.com/rsWinAutomationSupport/rsPackageSourceManager.git"
            }
            TestScript = {
                return ([bool](Get-DscResource rsGit -ErrorAction SilentlyContinue))
            }
            GetScript = {
                return @{'Result' = ([bool] (Get-DscResource rsGit -ErrorAction SilentlyContinue ))}
            }
            DependsOn = '[File]rsPlatformDir'
        }
        #Creates PullServer Certificate that resides on DSC endpoint
        Script CreatePullServerCertificate 
        {
            SetScript = {
                $PullServerAddress = $using:BootParameters.PullServerAddress
                if( -not ($PullServerAddress) -or ($PullServerAddress -as [ipaddress]))
                {
                    $PullServerAddress = $env:COMPUTERNAME
                }
                Import-Module -Name $using:BootParameters.BootModuleName -Force

                Write-Verbose "Checking for exisitng pull server cert"
                $PullCert = Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}
                if ($PullCert -eq $null)
                {
                    Write-Verbose "Generating pull server certificate..."
                    $EndDate = (Get-Date).AddYears(25) | Get-Date -Format MM/dd/yyyy
                    New-SelfSignedCertificateEx -Subject "CN=$PullServerAddress" `
                                                -NotAfter $EndDate `
                                                -StoreLocation LocalMachine `
                                                -StoreName My `
                                                -Exportable `
                                                -KeyLength 2048
                    # Update the cert object for use later in the process
                    $PullCert = Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}
                }
                else
                {
                    Write-Verbose "Existing pull server cert found"
                }
                Write-Verbose "Checking validity of current pull server cert"
                $RootStorePullCert = Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}
                if ($PullCert.Thumbprint -ne $RootStorePullCert.Thumbprint)
                {
                    if ($RootStorePullCert -ne $null)
                    {
                        Write-Verbose "Removing existing matching certs in root store..."
                        Get-ChildItem -Path Cert:\LocalMachine\Root\ | 
                        Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"} | 
                        Remove-Item
                    }
                    Write-Verbose "Copying registration cert to root store..."
                    $PublicKey = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $PublicKey.Import($PullCert.RawData)
                    $Store = Get-item Cert:\LocalMachine\Root\
                    $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    $Store.Add($PublicKey)
                    $Store.Close()
                }
                else
                {
                    Write-Verbose "Pull server certificate is valid"
                }
                # Always force an export of pull cert's public key when Set runs
                $PublicKeyFile = (Join-Path $using:BootParameters.InstallPath -childpath "$PullServerAddress.cer")
                Write-Verbose "Exporting pull server cert public key to $PublicKeyFile..."
                Export-Certificate -Cert $PullCert -FilePath $PublicKeyFile -Force
            }
            TestScript = {
                $PullServerAddress = $using:BootParameters.PullServerAddress
                if( -not ($PullServerAddress) -or ($PullServerAddress -as [ipaddress]))
                {
                    $PullServerAddress = $env:COMPUTERNAME
                }
                Write-Verbose "Checking for Pull server certificate..."
                $ExisitngCert = Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}
                if ($ExisitngCert -ne $null)
                {
                    Write-Verbose "Pull server certificate found, checking for cert in root cert store..."
                    $RootStorePullCert = Get-ChildItem -Path Cert:\LocalMachine\root\ | Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}
                    if ($ExisitngCert.Thumbprint -eq $RootStorePullCert.Thumbprint)
                    {
                        $PublicKeyFile = (Join-Path $using:BootParameters.InstallPath -childpath "$PullServerAddress.cer")
                        if ( -not (Test-Path $PublicKeyFile))
                        {
                            Write-Verbose "Missing pull cert public key file"
                            return $false
                        }
                        else
                        {
                            return $true
                        }
                    }
                    else
                    {
                        Write-Verbose "Pull server certificate not found in system ROOT cert store"
                        return $false
                    }
                }
                else
                {
                    Write-Verbose "Pull server certificate not found"
                    return $false
                }
            }
            GetScript = {
                $PullServerAddress = $using:BootParameters.PullServerAddress
                if( -not ($PullServerAddress) -or ($PullServerAddress -as [ipaddress]))
                {
                    $PullServerAddress = $env:COMPUTERNAME
                }
                return @{
                    'Result' = (Get-ChildItem -Path Cert:\LocalMachine\My\ | 
                                Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}).Thumbprint
                }
            }
        }
        #Create Client registration certificate (Shared secret replacement)
        Script CreateRegistrationCertificate 
        {
            SetScript = {
                $ClientRegCertName = $using:BootParameters.ClientRegCertName
                # Check that we have a registration cert
                Write-Verbose "Checking for exisitng registration cert"
                $ExisitngRegistrationCert = Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"}
                if ($ExisitngRegistrationCert -eq $null)
                {
                    Write-Verbose "Generating client Registration certificate..."
                    $EndDate = (Get-Date).AddYears(25) | Get-Date -Format MM/dd/yyyy
                    New-SelfSignedCertificateEx -Subject "CN=$ClientRegCertName" `
                                                -NotAfter $EndDate `
                                                -StoreLocation LocalMachine `
                                                -StoreName My `
                                                -Exportable `
                                                -KeyLength 2048
                    # Update the existing cert object for use later in the process
                    $ExisitngRegistrationCert = Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"}
                }
                else
                {
                    Write-Verbose "Existing registration cert found"
                }
                # Check that existing cert is valid and exists in root
                Write-Verbose "Checking validity of current registration cert"
                $RootRegistrationCert = Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"}
                if ($ExisitngRegistrationCert.Thumbprint -ne $RootRegistrationCert.Thumbprint)
                {
                    
                    if ($RootRegistrationCert -ne $null)
                    {
                        Write-Verbose "Removing existing matching certs in root store..."
                        Get-ChildItem -Path Cert:\LocalMachine\Root\ | 
                        Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"} | 
                        Remove-Item
                    }
                    Write-Verbose "Copying registration cert to root store..."
                    $PublicKey = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $PublicKey.Import($ExisitngRegistrationCert.RawData)
                    $Store = Get-item Cert:\LocalMachine\Root\
                    $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    $Store.Add($PublicKey)
                    $Store.Close()
                }
                else
                {
                    Write-Verbose "Client Registration certificate is valid"
                }
                Write-Verbose "Checking that current registration cert is in Trusted store"
                $TrustedRegistrationCert = Get-ChildItem -Path Cert:\LocalMachine\TrustedPeople\ | Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"}
                if ($ExisitngRegistrationCert.Thumbprint -ne $TrustedRegistrationCert.Thumbprint)
                {
                    if ($TrustedRegistrationCert -ne $null)
                    {
                        Write-Verbose "Removing existing trusted cert..."
                        Get-ChildItem -Path Cert:\LocalMachine\TrustedPeople\ | 
                        Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"} | 
                        Remove-Item
                    }
                    Write-Verbose "Copying the new certificate to trusted store..."
                    $PublicKey = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $PublicKey.Import($ExisitngRegistrationCert.RawData)
                    $Store = Get-item Cert:\LocalMachine\TrustedPeople\
                    $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    $Store.Add($PublicKey)
                    $Store.Close()
                }
                else
                {
                    Write-Verbose "Client Registration certificate is already in system TrustedPeople cert store"
                }
            }
            TestScript = {
                $ClientRegCertName = $using:BootParameters.ClientRegCertName
                $ExisitngRegistrationCert = Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"}
                if ($ExisitngRegistrationCert -ne $null)
                {
                    $rootRegistrationCert = Get-ChildItem -Path Cert:\LocalMachine\root\ | Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"}
                    if ($ExisitngRegistrationCert.Thumbprint -eq $rootRegistrationCert.Thumbprint)
                    {
                        $TrustedRegistrationCert = Get-ChildItem -Path Cert:\LocalMachine\TrustedPeople\ | Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"}
                        if ($ExisitngRegistrationCert.Thumbprint -eq $TrustedRegistrationCert.Thumbprint)
                        {
                            return $true
                        }
                        else
                        {
                            Write-Verbose "Client Registration certificate cannot be verified - not in system TrustedPeople cert store"
                            return $false
                        }
                
                    }
                    else
                    {
                        Write-Verbose "Client Registration certificate cannot be verified - not in system ROOT cert store"
                        return $false
                    }
                }
                else
                {
                    Write-Verbose "Client Registration certificate not found"
                    return $false
                }
            }
            GetScript = {
                $ClientRegCertName = $using:BootParameters.ClientRegCertName
                return @{
                    'Result' = (Get-ChildItem -Path Cert:\LocalMachine\My\ | 
                                Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"}).Thumbprint
                }
            }
        }
        WindowsFeature IIS 
        {
            Ensure = 'Present'
            Name = 'Web-Server'
        }
        WindowsFeature DSCServiceFeature 
        {
            Ensure = 'Present'
            Name = 'DSC-Service'
            DependsOn = '[WindowsFeature]IIS'
        }
        LocalConfigurationManager
        {
            AllowModuleOverwrite           = 'True'
            ConfigurationModeFrequencyMins = 30
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded             = 'True'
            RefreshMode                    = 'PUSH'
            RefreshFrequencyMins           = 30
        }
    } 
}
#endregion
#region Initial Client DSC Configuration
Configuration ClientBoot 
{  
    param 
    (
        [hashtable] $BootParameters
    )
    node $env:COMPUTERNAME 
    {
        File DevOpsDir
        {
            DestinationPath = $BootParameters.InstallPath
            Ensure = 'Present'
            Type = 'Directory'
        }
        Script DSCAutomationLog
        {
            GetScript = { 
                $LogName = $using:BootParameters.LogName
                return @{
                    "LogName" = $LogName
                    "Present" = ([bool](Get-EventLog -List | Where-Object -FilterScript {$_.Log -eq $LogName}))
                }
            }
            SetScript = {
                $LogName = $using:BootParameters.LogName
                New-Eventlog -source $LogName -logname $LogName
            }
            TestScript = {
                $LogName = $using:BootParameters.LogName
                return ([bool](Get-EventLog -List | Where-Object -FilterScript {$_.Log -eq $LogName}))
            }
        }
        Script GetWMF4 
        {
            SetScript = {
                $Uri = 'http://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu'
                Write-Verbose "Downloading WMF4"
                Invoke-WebRequest -Uri $Uri -OutFile 'C:\Windows\temp\Windows6.1-KB2819745-x64-MultiPkg.msu' -UseBasicParsing
            }

            TestScript = {
                if( $PSVersionTable.PSVersion.Major -ge 4 ) 
                {
                    return $true
                }
                if( -not (Test-Path -Path 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu') ) 
                {
                    Write-Verbose "WMF4 Installer not found locally"
                    return $false
                }
                else
                {
                    return $true
                }
            }

            GetScript = {
                return @{
                    'Result' = 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu'
                }
            }
        }
        Script InstallWMF4 
        {
            SetScript = {
                Write-Verbose "Installing WMF4"
                Start-Process -Wait -FilePath 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu' -ArgumentList '/quiet' -Verbose
                Write-Verbose "Setting DSC reboot flag"
                Start-Sleep -Seconds 30
                $global:DSCMachineStatus = 1 
            }
            TestScript = {
                if($PSVersionTable.PSVersion.Major -ge 4) 
                {
                    return $true
                }
                else 
                {
                    Write-Verbose "Current PowerShell version is lower than the requried v4"
                    return $false
                }
            }
            GetScript = {
                return @{'Result' = $PSVersionTable.PSVersion.Major}
            }
            DependsOn = '[Script]GetWMF4'
        }
        Script CreateDSCClientCertificate 
        {
            SetScript = {
                Import-Module -Name $using:BootParameters.BootModuleName -Force
                $EndDate = (Get-Date).AddYears(25) | Get-Date -Format MM/dd/yyyy
                $CertificateSubject = "CN=$($using:BootParameters.ClientDSCCertName)"

                Get-ChildItem -Path Cert:\LocalMachine\My\ |
                Where-Object -FilterScript {$_.Subject -eq $CertificateSubject} | 
                Remove-Item -Force -Verbose -ErrorAction SilentlyContinue

                New-SelfSignedCertificateEx -Subject $CertificateSubject `
                                            -NotAfter $EndDate `
                                            -StoreLocation LocalMachine `
                                            -StoreName My `
                                            -Exportable `
                                            -KeyLength 2048 `
                                            -EnhancedKeyUsage 1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2
            }
            TestScript = {
                $CertificateSubject = "CN=$($using:BootParameters.ClientDSCCertName)"
                $ClientCert = [bool](Get-ChildItem -Path Cert:\LocalMachine\My\ | 
                                        Where-Object -FilterScript {$_.Subject -eq $CertificateSubject})
                if($ClientCert)
                {
                    return $true
                }
                else 
                {
                    return $false
                }
            }
            GetScript = {
                $CertificateSubject = "CN=$($using:BootParameters.ClientDSCCertName)"
                $Result = (Get-ChildItem -Path Cert:\LocalMachine\My\ | 
                                Where-Object -FilterScript {$_.Subject -eq $CertificateSubject}).Thumbprint
                return @{
                    'Result' = $Result
                }
            }
        }
        # If PullServerAddress was an IP, set a HOSTS entry to resolve PullServer hostname
        Script SetHostFile 
        {
            SetScript = {
                if($($using:BootParameters.PullServerAddress) -as [ipaddress])
                {
                    $HostFilePath = "$($env:windir)\system32\drivers\etc\hosts"
                    $HostsFile = (Get-Content -Path $HostFilePath)
                    $HostFileContents = $HostsFile.where({$_ -notmatch $($using:BootParameters.PullServerAddress) -AND $_ -notmatch $($using:BootParameters.PullServerName)})
                    $HostFileContents += "$($using:BootParameters.PullServerAddress)    $($using:BootParameters.PullServerName)"
                    Set-Content -Value $HostFileContents -Path $HostFilePath -Force -Encoding ASCII
                }
            }
            TestScript = {
                if($($using:BootParameters.PullServerAddress) -as [ipaddress])
                {
                    $HostsFile = (Get-Content -Path "$($env:windir)\system32\drivers\etc\hosts")
                    $HostEntryExists = [bool]$HostsFile.where{$_ -match "$($using:BootParameters.PullServerAddress)    $($using:BootParameters.PullServerName)"}
                    return $HostEntryExists
                }
                else
                {
                    return $true
                }
            }
            GetScript = {
                $HostsFile = (Get-Content -Path "$($env:windir)\system32\drivers\etc\hosts")
                $HostEntry = $HostsFile.where{$_ -match "$($using:BootParameters.PullServerAddress)    $($using:BootParameters.PullServerName)"}
                return @{
                    'Result' = $HostEntry
                }
            }
        }
        # Retrieve the public key of pull server cert and store in root store
        Script GetPullPublicCert 
        {
            SetScript = {
                $Uri = "https://$($using:BootParameters.PullServerAddress):$($using:BootParameters.PullServerPort)"
                Write-Verbose "Trying to connect to $Uri"
                do 
                {
                    $rerun = $true
                    try 
                    {
                        Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue -UseBasicParsing
                    }
                    catch 
                    {
                        if($($_.Exception.message) -like '*SSL/TLS*')
                        {
                            Write-Verbose "Sucessfully connected to Pull server"
                            $rerun = $false 
                        }
                        else 
                        {
                            Write-Verbose "Failed to connect to the Pull server - sleeping for 10 seconds..."
                            Start-Sleep -Seconds 10
                        }
                    }
                }
                while($rerun)
                
                $webRequest = [Net.WebRequest]::Create($Uri)
                try 
                {
                    $webRequest.GetResponse() 
                }
                catch
                {
                }
                $cert = $webRequest.ServicePoint.Certificate
                
                # Remove existing Pull server certificates that may cause a conflict
                Get-ChildItem -Path Cert:\LocalMachine\Root\ |
                Where-Object -FilterScript {$_.Subject -eq $cert.Issuer} |
                Remove-Item
                
                Write-Verbose "Adding PullServer Root Certificate to Cert:\LocalMachine\Root"
                $store = Get-Item Cert:\LocalMachine\Root
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadWrite')
                $store.Add($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
                $store.Close()
            }
            TestScript = {
                $Uri = "https://$($using:BootParameters.PullServerAddress):$($using:BootParameters.PullServerPort)"
                Write-Verbose "Contacting $Uri"
                do 
                {
                    $rerun = $true
                    try 
                    {
                        Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue -UseBasicParsing
                    }
                    catch 
                    {
                        Write-Verbose "Error retrieving configuration: $($_.Exception.message)"
                        if($($_.Exception.message) -like '*SSL/TLS*') 
                        {
                            $rerun = $false 
                        }
                        else
                        {
                            Start-Sleep -Seconds 10 
                        }
                    }
                }
                while($rerun)
                $webRequest = [Net.WebRequest]::Create($Uri)
                try 
                {
                    $webRequest.GetResponse() 
                }
                catch
                {
                }
                $cert = $webRequest.ServicePoint.Certificate
                $CertMatch = (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq ($cert.GetCertHashString()) ).count
                if($CertMatch -eq 0)
                {
                    return $false
                }
                else
                {
                    return $true
                }
            }
            GetScript = {
                $Uri = "https://$($using:BootParameters.PullServerAddress):$($using:BootParameters.PullServerPort)"
                $webRequest = [Net.WebRequest]::Create($uri)
                try 
                {
                    $webRequest.GetResponse() 
                }
                catch
                {
                }
                $cert = $webRequest.ServicePoint.Certificate
                return @{
                    'Result' = (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq ($cert.GetCertHashString()))
                }
            }
            DependsOn = @('[Script]SetHostFile')
        }
        
        <# This section is to be replaced with Arnie-based registration API request
        # Retreieve all key local client variable and push them to Pull server via MSMQ to register
        Script SendClientPublicCert
        {
            SetScript = {
                $nodeinfo = Get-Content $using:NodeInfoPath -Raw | ConvertFrom-Json
                $ClientPublicCert = ((Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq "CN=$env:COMPUTERNAME`_enc").RawData)
                $MessageBody = @{'Name' = "$env:COMPUTERNAME"
                                'uuid' = $($nodeinfo.uuid)
                                'dsc_config' = $($nodeinfo.dsc_config)
                                'shared_key' = $($nodeinfo.shared_key)
                                'PublicCert' = "$([System.Convert]::ToBase64String($ClientPublicCert))"
                                'NetworkAdapters' = $($nodeinfo.NetworkAdapters)
                } | ConvertTo-Json

                [Reflection.Assembly]::LoadWithPartialName('System.Messaging') | Out-Null
                do 
                {
                    try 
                    {
                        $msg = New-Object System.Messaging.Message
                        $msg.Label = 'execute'
                        $msg.Body = $MessageBody
                        $queueName = "FormatName:DIRECT=HTTPS://$($using:PullServerName)/msmq/private$/rsdsc"
                        $queue = New-Object System.Messaging.MessageQueue ($queueName, $False, $False)                        
                        Write-Verbose "Trying to register with pull server: $queueName"
                        $queue.Send($msg)
                        Write-Verbose "Waiting 60 seconds for pull server to generate mof file..."
                        Start-Sleep -Seconds 60
                        $Uri = "https://$($using:PullServerName):$($using:PullServerPort)/PSDSCPullServer.svc/Action(ConfigurationId=`'$($nodeinfo.uuid)`')/ConfigurationContent"
                        Write-Verbose "Checking if client configuration has been generated..."
                        Write-Verbose "Using the following URI: $Uri"
                        $statusCode = (Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue -UseBasicParsing).statuscode
                    }
                    catch 
                    {
                        Write-Verbose "Error retrieving configuration: $($_.Exception.message)"
                    }
                }
                while($statusCode -ne 200)
                Write-Verbose "Looks like client mof file has been generated on the pull server!"
            }
            TestScript = {
                # We really want to run this every time
                Return $false
                }
            GetScript = {
                # Not terribly relevant in this instance
                return @{
                    'Result' = $true
                }
            }
            DependsOn = @('[WindowsFeature]MSMQ','[Script]GetPullPublicCert','[Script]CreateEncryptionCertificate','[Script]SetHostFile')
        }
        #>
        LocalConfigurationManager
        {
            AllowModuleOverwrite = 'True'
            ConfigurationID = $BootParameters.ConfigID
            CertificateID = (Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -EQ "CN=$($BootParameters.ClientDSCCertName)").Thumbprint
            ConfigurationModeFrequencyMins = $BootParameters.ConfigurationModeFrequencyMins
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = 'True'
            RefreshMode = 'Pull'
            RefreshFrequencyMins = $BootParameters.RefreshFrequencyMins
            DownloadManagerName = 'WebDownloadManager'
            DownloadManagerCustomData = (@{ServerUrl = "https://$($BootParameters.PullServerName):$($BootParameters.PullServerPort)/PSDSCPullServer.svc"; AllowUnsecureConnection = "false"})
        }
    } 
}
#endregion
function Install-PlatformModules 
{
# We cannot run this code directly until the rsPlatform module is installed, 
# so we'll create it as string and call it later
@'
    Configuration InstallPlatformModules 
    {
        Import-DscResource -ModuleName rsPlatform
        Node $env:COMPUTERNAME
        {
            rsPlatform Modules
            {
                Ensure = 'Present'
            }
        }
    }
    InstallPlatformModules -OutputPath 'C:\Windows\Temp' -Verbose
    Start-DscConfiguration -Path 'C:\Windows\Temp' -Wait -Verbose -Force
'@ | Invoke-Expression -Verbose
}

#endregion

#########################################################################################################
#region Helper functions
#########################################################################################################

#endregion

#########################################################################################################
#region Create a task to persist bootstrap accross reboots
#########################################################################################################
Write-Verbose "Preparing to create 'DSCBoot' task"

# Setup a variable to hold parameters with which bootstrap was invoked for use as part of task action
foreach( $key in $PSBoundParameters.Keys)
{
    $arguments += "-$key $($PSBoundParameters[$key]) "
}
if (Get-ScheduledTask -TaskName 'DSCBoot' -ErrorAction SilentlyContinue)
{
    Write-Verbose "Removing existing 'DSCBoot' task..."
    Unregister-ScheduledTask -TaskName DSCBoot -Confirm:$false
}
$Action = New-ScheduledTaskAction –Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -file $PSCommandPath $arguments"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
$Settings = New-ScheduledTaskSettingsSet
$Task = New-ScheduledTask -Action $Action -Principal $Principal -Trigger $Trigger -Settings $Settings
Write-Verbose "Creating the 'DSCBoot' task"
Register-ScheduledTask DSCBoot -InputObject $Task
#endregion

#########################################################################################################
#region Download & install the bootstrap PS module
#########################################################################################################
Write-Verbose "Checking connectivity to '$NetworkTestTarget'..."
if (-not (Test-Connection $NetworkTestTarget -Quiet))
{
    do
    {
        Write-Host "Waiting for network connectivity to '$NetworkTestTarget' to be established..."
        Sleep -Seconds 20
    }
    until (-not (Test-Connection $NetworkTestTarget -Quiet))
}

$WinTemp = "$env:SystemRoot\Temp"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$ModuleFileName = $BootModuleZipURL.Split("/")[-1]
$ZipPath = "$WinTemp\$ModuleFileName"

$PSModuleLocation = "$Env:ProgramFiles\WindowsPowerShell\Modules\"

Write-Verbose "Downloading the Bootstrap PS module to $ZipPath"
Invoke-WebRequest -Uri $BootModuleZipURL -OutFile $ZipPath
Unblock-File -Path $ZipPath

# Retreive Archive root folder name
$ZipRootName = ([System.IO.Compression.ZipFile]::OpenRead($ZipPath).Entries.FullName[0]).Trim("/")
# Extract archive to temporary location
if (Test-Path "$WinTemp\$ZipRootName")
{
    Remove-Item -LiteralPath "$WinTemp\$ZipRootName" -Recurse -Force
}
[System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $WinTemp)

Rename-Item "$WinTemp\$ZipRootName" -NewName "$WinTemp\$BootModuleName"

$ModuleFolder = Join-Path $PSModuleLocation -Childpath $BootModuleName
if (Test-Path "$PSModuleLocation\$BootModuleName")
{
    Write-Verbose "Found existing $BootModuleName module instance, removing it..."
    Remove-Item -Path "$PSModuleLocation\$BootModuleName" -Recurse -Force
}
Write-Verbose "Installing $BootModuleName module"
Move-Item -Path "$WinTemp\$BootModuleName" -Destination $PSModuleLocation
Write-Verbose "Importing $ModuleName module"
Import-Module -Name $BootModuleName -Force
#endregion

#########################################################################################################
#region Execute pre-bootstrap scripts
#########################################################################################################
if ($BootParameters.PreBoot -ne $null)
{
    Invoke-PreBootScript -Scripts $BootParameters.PreBoot -Verbose
}
#endregion

#########################################################################################################
#region Execute main bootstrap process
#########################################################################################################
# Set folder for DSC boot mof files
$DSCbootMofFolder = (Join-Path $WinTemp -ChildPath DSCBootMof)

# Build the full bootstrap parameter set ($BootParameters) as a hashtable for use later
$BootParameters = @{}
($MyInvocation.MyCommand.Parameters).Keys | 
    Foreach {$value = (Get-Variable -Name $_ -EA SilentlyContinue).Value
        if( $value.length -gt 0 ) 
        {
            $BootParameters.Add("$_","$value")
        }
    }

# WinRM listener configuration
if ($AddWinRMListener)
{
    if( (Get-ChildItem WSMan:\localhost\Listener | Where-Object Keys -eq "Transport=HTTP").count -eq 0 )
    {
        Write-Verbose "Configuring WinRM listener"
        New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*";Transport="http"}
    }
}

# Determine if we're building a Pull server or a client
if ($PullServerConfig)
{
    Write-Verbose "##############################################################"
    Write-Verbose "Initiating DSC Pull Server bootstrap..."
    Write-Verbose "##############################################################"

    # Overwrite $PullServerAddress with pull server's hostname if it was provided as an IP (Needed for SSL to work)
    if( -not ($PullServerAddress) -or ($PullServerAddress -as [ipaddress]))
    {
        $PullServerAddress = $env:COMPUTERNAME
        # Add the PullServeraddress value to the BootParameters set
        $BootParameters.Add('PullServerAddress',$PullServerAddress)
    }

    Write-Verbose "Starting Pull Server Boot DSC configuration run"
    PullBoot -BootParameters $BootParameters -OutputPath $DSCbootMofFolder

    Write-Verbose "Applying initial Pull Server boot LCM configuration"
    Set-DscLocalConfigurationManager -Path $DSCbootMofFolder -Verbose

    Write-Verbose "Applying initial Pull Server Boot configuration"
    Start-DscConfiguration -Path $DSCbootMofFolder -Wait -Verbose -Force
    Write-Verbose "Running DSC config to install extra DSC modules as defined in rsPlatform"
    Install-PlatformModules

    # Create Pull server configuration file
    $CertThumbprint = (Get-ChildItem Cert:\LocalMachine\My | 
                        Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}).Thumbprint
    
    # Procecss bootstrap parameters and save only settings we need to commit to the main configuration file
    $SettingKeyFilterSet = @(
                             "InstallPath",
                             "ClientRegCertName",
                             "GitRepoName",
                             "GitOrgName",
                             "GitRepoBranch",
                             "GitOAuthToken",
                             "PullServerPort",
                             "NodeDataPath",
                             "PullServerConfig",
                             "PullServerAddress",
                             "LogName",
                             "RegQueueName"
                            )
    $DSCSettings = @{}
    $BootParameters.GetEnumerator() | foreach {  
        if ($SettingKeyFilterSet -contains $($_.Name))
        {
            $DSCSettings.Add($_.Name,$_.Value)
        }
    }
    # Encrypt the values of each setting using pull server's certificate and save to disk
    Protect-DSCAutomationSettings -CertThumbprint $CertThumbprint -Settings $DSCSettings -Path "$InstallPath\DSCAutomationSettings.xml" -Verbose

    $PullServerDSCConfigPath = "$InstallPath\$GitRepoName\$PullServerConfig"
    if (-not (Test-Path $PullServerDSCConfigPath))
    {
        Throw "Pull Server configuration file not found!"
    }
    Write-Verbose "Executing final Pull server DSC script from configuration repository"
    Write-Verbose "Configuration file: $PullServerDSCConfigPath"
    try
    {
        & "$PullServerDSCConfigPath" -Verbose
    }
    catch
    {
        Write-Verbose "Error in Pull Server DSC configuration: $($_.Exception)"
    }
}
else
{
    Write-Verbose "##############################################################"
    Write-Verbose "Initiating DSC Client bootstrap..."
    Write-Verbose "##############################################################"

    # Create Pull server name boot parameter for use in temp DSC config Hosts file management is address is an IP
    if($PullServerAddress -as [ipaddress])
    {       
        Write-Verbose "Pull Server Address provided seems to be an IP - trying to resovle hostname..."
        # Attempt to resolve Pull server hostname by checking Common Name property of Pull public certificate key
        $PullUrl = ("https://",$PullServerAddress,":",$PullServerPort -join '')
        do 
        {
            $webRequest = [Net.WebRequest]::Create($PullUrl)
            try 
            {
                $webRequest.GetResponse()
            }
            catch
            {
            }
            $PullServerName = $webRequest.ServicePoint.Certificate.Subject -replace '^CN\=','' -replace ',.*$',''
            if( !($PullServerName))
            {
                Write-Verbose "Failed to resolve Pull server Name - sleeping for 10 seconds..."
                Start-Sleep -Seconds 10 
            }
        }
        while(!($PullServerName))
        Write-Verbose "Resolved Pull server Name: $PullServerName"

        $BootParameters.Item('PullServerName') = $PullServerName
    }
    else
    {
        $BootParameters.Item('PullServerName') = $PullServerAddress
    }

    # Check if we already have a node configuration ID and generate one if required
    $ConfigID = (Get-DscLocalConfigurationManager).ConfigurationID
    if ($ConfigID -eq $null)
    {
        Write-Verbose "Generating client configuration ID..."
        $BootParameters.Add('ConfigID',[Guid]::NewGuid().Guid)
    }
    else
    {
        Write-Verbose "Using an existing client configuration ID..."
        $BootParameters.Add('ConfigID',$ConfigID)
    }
   
    Write-Verbose "Executing client DSC boot configuration..."
    ClientBoot  -BootParameters $BootParameters  -OutputPath $DSCbootMofFolder -Verbose
    Start-DscConfiguration -Force -Path $DSCbootMofFolder -Wait -Verbose
    
    Write-Verbose "Configure Client LCM"
    # Set-DscLocalConfigurationManager -Path $DSCbootMofFolder -Verbose

    # Procecss additional bootstrap parameters that are needed for our DSC clients
    $SettingKeyFilterSet = @(
                             "InstallPath",
                             "ClientRegCertName",
                             "PullServerPort",
                             "ClientDSCCertName",
                             "LogName"
                            )
    $DSCSettings = @{}
    $BootParameters.GetEnumerator() | foreach {  
    if ($SettingKeyFilterSet -contains $($_.Name))
        {
            $DSCSettings.Add($_.Name,$_.Value)
        }
    }
    
    # Encrypt the values of each setting using client's certificate and save to disk
    $CertThumbprint = (Get-ChildItem Cert:\LocalMachine\My | Where-Object -FilterScript {$_.Subject -eq "CN=$ClientDSCCertName"}).Thumbprint
    Protect-DSCAutomationSettings -CertThumbprint $CertThumbprint -Settings $DSCSettings -Path "$InstallPath\DSCAutomationSettings.xml" -Verbose
    
    <#    
    Write-Verbose "Applying final Client DSC Configuration from Pull server - $PullServerName"
    Update-DscConfiguration -Wait -Verbose
    #>
}

if (Get-ScheduledTask -TaskName 'DSCBoot' -ErrorAction SilentlyContinue)
{
    Write-Verbose "Removing the 'DSCBoot' task..."
    Unregister-ScheduledTask -TaskName DSCBoot -Confirm:$false
}

Stop-Transcript

Write-Verbose "The bootstrap process has completed"
#endregion

# Import all local functions dependencies
Get-Item (Join-Path -Path $PSScriptRoot -ChildPath 'functions\*.ps1') | 
    ForEach-Object {
        Write-Verbose ("Importing sub-module {0}." -f $_.FullName)
        . $_.FullName
    }

# Executes pre-DSCbootstrap scripts from module scripts folder
function Invoke-PreBootScript
{
    [CmdletBinding()]
    Param
    (
        # Hashtable that contains filename of the script to run and any parameters it requires: @{"script.ps1" = "-param test"}
        [hashtable] $Scripts
    )

    $ScriptPath = $(Join-Path -Path $PSScriptRoot -ChildPath "scripts")
    ForEach ($item in $scripts.GetEnumerator())
    {
        $Script = $item.Name
        $Parameters = $item.Value
        $FullScriptPath = $(Join-Path -Path $ScriptPath -ChildPath $Script)
        if (Test-Path $FullScriptPath)
        {
            Write-Verbose "Executing script: $script"
            & $FullScriptPath @Parameters
        }
        else
        {
            Write-Verbose "Script '$Script' was not found at $ScriptPath"
        }
    }
}

<#
.Synopsis
   Save DSC Automation settings to a file
.DESCRIPTION
   This function will encrypt the values within a hashtable object (-Settings) using an existing certificate and save the output on the file system.
.EXAMPLE
   Protect-DSCAutomationSettings -CertThumbprint <cert-thumbprint> -Settings <settings hashtable> -Path <output destination> -Verbose
#>
function Protect-DSCAutomationSettings
{
    [CmdletBinding()]
    param
    (
        # Destination path for DSC Automation secure settings file
        [string]
        $Path = (Join-Path ([System.Environment]::GetEnvironmentVariable("DSCAutomationPath","Machine")) "DSCAutomationSettings.xml"),

        # Certificate hash with which to ecrypt the settigns
        [Parameter(Mandatory=$true)]
        [string]
        $CertThumbprint,

        # Contents of the settings file
        [Parameter(Mandatory=$true)]
        [hashtable]
        $Settings,

        # Force overwirte of existing settings file
        [Parameter(Mandatory=$false)]
        [switch]
        $Force = $false
    )

    # Create the certificate object whith which to secure the AES key
    $CertObject = Get-ChildItem Cert:\LocalMachine\My\$CertThumbprint

    # Create RNG Provider Object to help with AES key generation
    $rngProviderObject = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    
    # Generates a random AES encryption $key that is sized correctly
    $key = New-Object byte[](32)
    $rngProviderObject.GetBytes($key)
    
    # Process all Key/Value pairs in the supplied $settings hashtable and encrypt the value
    $DSCAutomationSettings = @{}
    $Settings.GetEnumerator() | Foreach {
        # Convert the current value ot secure string
        $SecureString = ConvertTo-SecureString -String $_.Value -AsPlainText -Force
    
        # Convert the secure string to an encrypted string, so we can save it to a file
        $encryptedSecureString = ConvertFrom-SecureString -SecureString $SecureString -Key $key

        # Encrypt the AES key we used earlier with the specified certificate
        $encryptedKey = $CertObject.PublicKey.Key.Encrypt($key,$true)
    
        # Populate the secure data object and add it to $Settings
        $result = @{
            $_.Name = @{
                "encrypted_data" = $encryptedSecureString;
                "encrypted_key"  = [System.Convert]::ToBase64String($encryptedKey);
                "thumbprint"     = [System.Convert]::ToBase64String([char[]]$CertThumbprint)
            }
        }
        $DSCAutomationSettings += $result
    }
    
    # Make a backup in case of there being an existing settings file - skip of Force switch set
    if ((Test-Path $Path) -and ($Force -ne $true))
    {
        Write-Verbose "Existing settings file found - making a backup..."
        $TimeDate = (Get-Date -Format ddMMMyyyy_hhmmss).ToString()
        Move-Item $Path -Destination ("$Path`-$TimeDate.bak") -Force -Verbose:($PSBoundParameters['Verbose'] -eq $true)
    }
    
    # Save the encrypted databag as a native PS hashtable object
    Write-Verbose "Saving encrypted settings file to $Path"
    Export-Clixml -InputObject $DSCAutomationSettings -Path $Path -Force -Verbose:($PSBoundParameters['Verbose'] -eq $true)
}

<#
.Synopsis
   Decrypt the encrypted DSCAutomation settings file values
.DESCRIPTION
   This function will access the encrypted DSC Automation settings file, then use pull server's certificate to decrypt the AES key 
   for each setting value in order to generate and return a set of PSCredential objects
.EXAMPLE
   Unprotect-DSCAutomationSettings
.EXAMPLE
   Unprotect-DSCAutomationSettings -Path 'C:\folder\file.xml'
#>
function Unprotect-DSCAutomationSettings
{
    [CmdletBinding()]
    param
    (
        # Source path for the secure settings file to override the default location
        [string]
        $Path = (Join-Path ([System.Environment]::GetEnvironmentVariable("DSCAutomationPath","Machine")) "DSCAutomationSettings.xml")
    )

    Write-Verbose "Importing the settings databag from $Path"
    If ( -not (Test-Path -Path $Path))
    {
        return $null
    }
    # Import the encrypted data file
    $EncrytedSettings = Import-Clixml -Path $Path
    # Create a hashtable object to hold the decrypted credentials
    $DecryptedSettings = New-Object 'System.Collections.Generic.Dictionary[string,pscredential]'
    if($EncrytedSettings -ne $null) 
    {
        # Process each set of values for each Key in the hashtable
        foreach ( $Name in $EncrytedSettings.GetEnumerator() )
        {
            $Item = $Name.Value
            # Convert Thumbprint value from Base64 to string
            $CertThumbprint = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Item.thumbprint))
            # Retrieve the certificate used to encrypt the AES key used to encrypt the data
            $decryptCert = Get-ChildItem Cert:\LocalMachine\My\ | Where-Object { $_.Thumbprint -eq $CertThumbprint }
            If ( -not $decryptCert ) 
            {
                $Param = $Name.Name
                Write-Verbose "Certificate with Thumbprint $Thumbprint for $Param data could not be found. Skipping..."
                Continue
            }
            try
            {
                # Use the private key of certificate to decrypt the encryption key
                $key = $decryptCert.PrivateKey.Decrypt([System.Convert]::FromBase64String($item.encrypted_key), $true)
                # Use the key we just decrypted to convert the data to a secure string object
                $secString = ConvertTo-SecureString -String $item.encrypted_data -Key $key
            }
            finally
            {
                if ($key)
                {
                    # Overwrite $key variable with zeros to remove it fully from memory
                    [array]::Clear($key, 0, $key.Length)
                }
            }
            # Add the newly decrypted PSCredential object to the collection
            $DecryptedSettings[$Name.Name] = New-Object pscredential($Name.Name, $secString)
        }
    }
    return $DecryptedSettings
}

<#
.Synopsis
   Retrieve the decrypted string from an encrypted databag.
.DESCRIPTION
   Use Unprotect-DSCAutomationSettings to decrypt the databag and retrieve the plain-text value for the specified setting.
.EXAMPLE
   Get-DSCSettingValue 'LogName'
.EXAMPLE
   Get-DSCSettingValue -Key 'PullServerAddress' -Path 'C:\folder\file.xml'
.EXAMPLE
   Get-DSCSettingValue -Key 'LogName', 'GitRepoName'
.EXAMPLE
   Get-DSCSettingValue -ListAvailable
#>
function Get-DSCSettingValue
{
    [CmdletBinding(DefaultParameterSetName='GetValues')]
    Param
    (
        # Key help description
        [Parameter(ParameterSetName='GetValues', Mandatory=$true, Position=0)]
        [string[]]
        $Key,

        # Path help description
        [Parameter(Mandatory=$false)]
        [string]
        $Path,

        # List all available settings
        [Parameter(ParameterSetName='ListKeys', Mandatory=$true, Position=0)]
        [switch]
        $ListAvailable = $false
    )
    # Decrypt contents ofthe DSCAutomation configuration file
    if ($PSBoundParameters.ContainsKey('Path'))
    {
        $DSCSettings = Unprotect-DSCAutomationSettings -Path $Path -Verbose:($PSBoundParameters['Verbose'] -eq $true)
    }
    else
    {
        $DSCSettings = Unprotect-DSCAutomationSettings -Verbose:($PSBoundParameters['Verbose'] -eq $true)
    }

    if ($ListAvailable.IsPresent)
    {
        # Retrieve a list of all parameter names stored in configuration file
        $Result = @()
        foreach ($Item in $DSCSettings.Keys)
        {
            $Result += $Item
        }
    }
    else
    {
        # Retrieve the plain-text value for each setting that is part of $Key parameter
        $Result = @{}
        foreach ($Item in $Key)
        {
            if ($DSCSettings[$Item] -ne $null)
            {
                $Value = $DSCSettings[$Item].GetNetworkCredential().Password
                $Result[$Item] = $Value
            }
            else
            {
                $Result[$Item] = $null
            }
        }
    }
    return $Result
}

<#
.Synopsis
   Retrieve base64 encoded certificate key to pass to DSC clients for registration
.DESCRIPTION
   This cmdlet will access the Pull server's local certificate store, retrieve the registration certificate that is 
   generated at pull server build time and export this certificate as a Base64 string for use during new DSC client registration process.
.EXAMPLE
   Get-DSCClientRegistrationCert
.EXAMPLE
   Get-DSCClientRegistrationCert '<Custom Registration Certificate Name>'
#>
function Get-DSCClientRegistrationCert
{
    [CmdletBinding()]
    Param
    (
        # Name of the regstration certificate if different from default
        [string]
        $ClientRegCertName
    )
    # Try to identify the cert name if one was not provided
    if (-not ($PSBoundParameters.ContainsKey('ClientRegCertName')))
    {
        $ClientRegCertName = (Get-DSCSettingValue "ClientRegCertName").ClientRegCertName
    }
    
    $RegCertThumbprint = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq "CN=$ClientRegCertName"}).Thumbprint

    $Cert = [System.Convert]::ToBase64String((Get-Item Cert:\LocalMachine\My\$RegCertThumbprint).Export('PFX', ''))

    return $Cert
}

<#
.Synopsis
   Initiate Pull server configuration sync
.DESCRIPTION
   Initiate a configuration sync and generate updated MOF file for Pull server. By default, it will access DSCAutomation Settings that were generated during bootstrap.
   Many parameters can be overriden if required.
.EXAMPLE
   Invoke-DSCPullConfigurationSync
.EXAMPLE
   Invoke-DSCPullConfigurationSync -UseLog
#>
function Invoke-DSCPullConfigurationSync
{
    [CmdletBinding()]
    Param
    (
        # Name of the DSC configuration file (normally Pull server config)
        [string]
        $PullServerConfig = (Get-DSCSettingValue "PullServerConfig").PullServerConfig,
        
        # DSC Automation install directory
        [string]
        $InstallPath = (Get-DSCSettingValue "InstallPath").InstallPath,
        
        # Name of the configuration git repository
        [string]
        $GitRepoName = (Get-DSCSettingValue "GitRepoName").GitRepoName,

        # Enable extra logging to the event log
        [switch]
        $UseLog = $true,

        # Name of the event log to use for logging
        [string]
        $LogName = (Get-DSCSettingValue "LogName").LogName,

        # Path to folder where to store the checksum file
        [string]
        $HashPath = (Join-Path $InstallPath "Temp"),

        # Force pull server configuration generation
        [switch]
        $Force = $false
    )

    $LogSourceName = $MyInvocation.MyCommand.Name
    if (($UseLog) -and -not ([System.Diagnostics.EventLog]::SourceExists($LogSourceName)) ) 
    {
        [System.Diagnostics.EventLog]::CreateEventSource($LogSourceName, $LogName)
    }

    if ($UseLog) 
    {
        Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 2001 -EntryType Information -Message "Starting Configuration repo sync task"
    }

    # Ensure that we are using the most recent $path variable
    $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    
    # Delay Pull server conf regen until ongoing LCM run completes
    Write-Verbose "Checking LCM State..."
    $LCMStates = @("Idle","PendingConfiguration")
    $LCMState = (Get-DscLocalConfigurationManager).LCMState
    if ($LCMStates -notcontains $LCMState)
    {
        if ($UseLog)
        {
            Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 2002 -EntryType Information -Message "Waiting for LCM to go into idle state"
        }
        Do
        {
            $LCMState = (Get-DscLocalConfigurationManager).LCMState
            Write-Verbose "LCM State is $LCMState "
            Sleep -Seconds 5
            $LCMState = (Get-DscLocalConfigurationManager).LCMState
        } while ($LCMStates -notcontains $LCMState)
    }
    Write-Verbose "Getting latest changes to configuration repository..."
    # Setup our path variables
    $ConfDir = Join-Path $InstallPath $GitRepoName
    $PullConf = Join-Path $ConfDir $PullServerConfig
    Push-Location -Path $ConfDir
    & git pull
    Pop-Location

    # Check pull server DSC configuration
    $CurrentHash = (Get-FileHash $PullConf).hash
    $HashFilePath = (Join-Path $HashPath $($PullServerConfig,'checksum' -join '.'))
    if( -not (Test-ConfigFileHash -file $PullConf -hash $HashFilePath) -or ($Force))
    {
        Write-Verbose "Executing Pull server DSC configuration"
        if ($UseLog)
        {
            Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 2003 -EntryType Information -Message "Executing Pull server DSC configuration"
        }
        & $PullConf
        Set-Content -Path $HashFilePath -Value (Get-FileHash -Path $PullConf).hash
    }
    else
    {
        Write-Verbose "Skipping processing of Pull server configuration because it has not been modified"
        if ($UseLog)
        {
            Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 2003 -EntryType Information -Message "Skipping processing of Pull server configuration because it has not been modified"
        }
    }
    if ($UseLog)
    {
        Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 2005 -EntryType Information -Message "Configuration synchronisation is complete"
    }
}

<#
.Synopsis
   Compare file hash to one stored in a file 
.DESCRIPTION
   Function that compares a file hash to one that was created previously - returns a bool value. Used for detecting changes to DSC configuration files.
   Generating has files: Set-Content -Path <hashfilepath> -Value (Get-FileHash -Path <sourcefile>).hash
.EXAMPLE
   Test-ConfigFileHash -file <targetfile> -hash <hashfile>
#>
Function Test-ConfigFileHash
{
    param (
        # Full path to the target file
        [String]
        $file,
        
        # Full path to the file that contains the checksum for comparison
        [String]
        $hash
    )
        
    if ( !(Test-Path $hash) -or !(Test-Path $file))
    {
        return $false
    }        
    if( (Get-FileHash $file).hash -eq (Get-Content $hash))
    {
        return $true
    }
    else
    {
        return $false
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Submit-DSCClientRegistration
{
    [CmdletBinding()]
    Param
    (
        # ConfigID help description
        [Parameter(Mandatory=$false)]
        $ConfigID = (Get-DSCSettingValue -Key "ConfigID").ConfigID,

        # ClientConfig help description
        [Parameter(Mandatory=$false)]
        $ClientConfig = (Get-DSCSettingValue -Key "ClientConfig").ClientConfig,

        # ClientRegCertName help description
        [Parameter(Mandatory=$false)]
        $ClientRegCertName = (Get-DSCSettingValue -Key "ClientRegCertName").ClientRegCertName,

        # ClientDSCCertName help description
        [Parameter(Mandatory=$false)]
        $ClientDSCCertName = (Get-DSCSettingValue -Key "ClientDSCCertName").ClientDSCCertName,

        # PullServerName help description
        [Parameter(Mandatory=$false)]
        $PullServerName = (Get-DSCSettingValue -Key "PullServerName").PullServerName,

        # PullServerPort help description
        [Parameter(Mandatory=$false)]
        $Port = 443,

        # Default timeout value to use when sending requests (default: 
        [Parameter(Mandatory=$false)]
        $TimeoutSec = 10
    )

    $ClientDSCCert = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$ClientDSCCertName" }).RawData
    $Property = @{
                "ConfigID" = $ConfigID
                "ClientName" = $env:COMPUTERNAME
                "ClientDSCCert" = ([System.Convert]::ToBase64String($ClientDSCCert))
                "ClientConfig" = $ClientConfig
                }
    $AuthCert = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$ClientRegCertName" })
    $RegistrationUri = "https://$($PullServerName):$($Port)/Arnie.svc/secure/ItsShowtime"
    $Body = New-Object -TypeName psobject -Property $Property | ConvertTo-Json
    try 
    {
        Write-Verbose "Trying to send client registration data to Pull server..."
        $ClientRegResult = Invoke-RestMethod -Method Post -Uri $RegistrationUri -TimeoutSec $TimeoutSec -Certificate $AuthCert -Body $Body -ContentType "application/json"  | ConvertFrom-Json
        if ($ClientRegResult.ConfigID -eq $ConfigID)
        {
            Write-Verbose "Client registration data submitted to Pull server successfully"
            return "Success"
        }
        else
        {
            Throw "Failed to submit client registration data - ensure that Pull server is configured correctly."
        }
    }
    catch [System.Management.Automation.RuntimeException]
    {
        Write-Verbose "Error submitting client registration: $($_.Exception.message)"
        Write-Verbose "Target pull server URI: $RegistrationUri"
    }
    catch 
    {
        Write-Verbose "Client registration request failed with: $($_.Exception.message)"
        Write-Verbose "Please verify connectivity to and check functionality of the pull server"
        Write-Verbose "Target pull server URI: $RegistrationUri"
    }
}

<#
.Synopsis
   Process Pull server's registration queue
.DESCRIPTION
   Reads client registration messages in the registration queue and adds the client registration data to the local node database and installs the client certificates.
.EXAMPLE
   Invoke-DSCClientRegistration
#>
function Invoke-DSCClientRegistration
{
    [CmdletBinding()]
    Param
    (
        # Full path to registered client data file
        [string]
        $NodeDataPath = (Get-DSCSettingValue NodeDataPath)["NodeDataPath"],

        [string]
        $InstallPath = (Get-DSCSettingValue InstallPath)["InstallPath"],
                
        [string]
        $QueueName = (Get-DSCSettingValue RegQueueName)["RegQueueName"]
    )

    [Reflection.Assembly]::LoadWithPartialName("System.Messaging") | Out-Null
    $queue = New-Object System.Messaging.MessageQueue ".\private$\$QueueName"
    $queue.Formatter.TargetTypeNames = ,"System.String"
    $GenerateMof = $false

    do
    {
        $msg = $null
        try
        {
            $msg = $queue.Receive((New-TimeSpan -Seconds 2))
        }
        catch [System.Messaging.MessageQueueException]
        {
            if ( $_.Exception.ToString().Contains("Timeout for the requested operation has expired.") )
            {
                Write-Verbose "No messages found after specified timeout"
            }
            else
            {
                throw $_
            }
        }

        if ($msg)
        {
            Write-Verbose "$($msg.Count) message(s) received"
            $bodyJson = $msg.Body
            $body = $bodyJson | ConvertFrom-Json
            $registrationCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certData = [System.Convert]::FromBase64String($body.ClientDSCCert)
            try
            {
                $registrationCert.Import($certData)
                Write-Verbose "Cert Import successful, Thumbprint: $($registrationCert.Thumbprint)"
            }
            catch [System.Security.Cryptography.CryptographicException]
            {
                Write-Verbose "Could not import Certificate from message"
            }

            if ( $registrationCert.Thumbprint )
            {
                $destinationCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $registrationCert.Thumbprint }
                if ( $destinationCert )
                {
                    Write-Verbose "Client Certificate already exists in destination store"
                }
                else
                {
                    Write-Verbose "Adding Client Certificate to destination store"
                    $store = Get-Item -Path Cert:\LocalMachine\My
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
                    $store.Add($registrationCert)
                    $store.Close()
                }
                
                $CertificatesFolderPath = Join-Path -Path $installPath -ChildPath "Certificates"
                if ( -not (Test-Path -Path $CertificatesFolderPath) )
                {
                    New-Item -Path $CertificatesFolderPath -ItemType Directory
                }
                $destinationFile = "$CertificatesFolderPath\$($body.ConfigID).cer"
                $saveClientCertificate = $false
                if ( (Test-Path $destinationFile) )
                {
                    Write-Verbose "Destination Certificate file already exists"
                    $destinationFileCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $destinationFileCertBytes = [System.IO.File]::ReadAllBytes($destinationFile)
                    $destinationFileCert.Import($destinationFileCertBytes)
                    if ( $registrationCert.Thumbprint -eq $destinationFileCert.Thumbprint )
                    {
                        Write-Verbose "Destination Certificate file thumbprint and Client Certificate thumbprint match, no action required"
                    }
                    else
                    {
                        Write-Verbose "Destination Certificate file thumbprint and Client Certificate Thumbprint do not match"
                        $saveClientCertificate = $true
                    }

                }
                else
                {
                    Write-Verbose "Client Certificate does not exist"
                    $saveClientCertificate = $true
                }

                if ( $saveClientCertificate )
                {
                    Write-Verbose "Saving Client Certificate to $destinationFile"
                    $CertificateFileData = $registrationCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    [System.IO.File]::WriteAllBytes($destinationFile, $CertificateFileData)
                }
            }
            $nodesData = Get-Content $NodeDataPath -Raw | ConvertFrom-Json
            if ( $nodesData.Nodes.ConfigID -notcontains $body.ConfigID )
            {
                Write-Verbose "ConfigID not found in NodesData, adding new entry"
                $nodesData.Nodes += New-Object -TypeName psobject -Property @{
                            'NodeName'     = $body.ClientName
                            'ConfigID'     = $body.ConfigID
                            'ClientConfig' = $body.ClientConfig
                            'timestamp'    = (Get-Date -Format u)
                        }
                Set-Content -Path $NodeDataPath -Value ($nodesData | ConvertTo-Json)
                $GenerateMof = $true
            }
            else 
            {
                Write-Verbose "ConfigID found in NodesData, updating existing entry"
                $currentNode = $nodesData.Nodes | Where-Object { $_.ConfigID -eq $body.ConfigID }
                foreach($property in $currentNode.PSObject.Properties) {
                    if($body.PSObject.Properties.Name -contains $property.Name) 
                    {
                        ($nodesData.Nodes  | Where-Object { $_.ConfigID -eq $body.ConfigID } ).$($property.Name) = $body.$($property.Name)
                    }
                }
                ($nodesData.Nodes  | Where-Object { $_.ConfigID -eq $body.ConfigID } ).timestamp = (Get-Date -Format u)
                Set-Content -Path $NodeDataPath -Value ($nodesData | ConvertTo-Json)
                $GenerateMof = $true
            }
        }
    } while ($msg)

    if ($GenerateMof)
    {
        Start-DSCClientMOFGeneration -Verbose:($PSBoundParameters['Verbose'] -eq $true)
    }
}

<#
.Synopsis
   Remove old client MOF files
.DESCRIPTION
   Used as part of MOF file lifecycle management to remove old mof files and their checksums
.EXAMPLE
   Remove-ClientMofFiles -ConfigID <dsc client uuid> -MOFDestPath <path where mof files are stored>
.EXAMPLE
   Remove-ClientMofFiles -ConfigID <dsc client uuid> 
#>
function Remove-ClientMofFiles
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $ConfigID,

        # Name of the event log to use for logging
        [string]
        $LogName = (Get-DSCSettingValue "LogName")["LogName"],

        # Enable extra logging to the event log
        [switch]
        $UseLog = $true,

        [Parameter(Mandatory=$false)]
        [string]
        $MOFDestPath = "$env:ProgramFiles\WindowsPowerShell\DscService\Configuration"
    )
    $LogSourceName = $MyInvocation.MyCommand.Name
    if (($UseLog) -and -not ([System.Diagnostics.EventLog]::SourceExists($LogSourceName)) ) 
    {
        [System.Diagnostics.EventLog]::CreateEventSource($LogSourceName, $LogName)
    }

    $MofFile = (($MofPath,$ConfigID -join '\'),'mof' -join '.')
    $MofFileHash = ($MofFile,'checksum' -join '.')
        
    if( Test-Path $MofFile )
    {
        Remove-Item $MofFile -Force -ErrorAction SilentlyContinue -Verbose:($PSBoundParameters['Verbose'] -eq $true)
    }
        
    if( Test-Path $MofFileHash )
    {
        Remove-Item $MofFileHash -Force -ErrorAction SilentlyContinue -Verbose:($PSBoundParameters['Verbose'] -eq $true)
    }
    if ($UseLog)
    {
        Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 1100 -EntryType Information -Message "Removed client mof files `n $MofFile `n $MofFileHash"
    }
}

<#
.Synopsis
   Generate client MOF files
.DESCRIPTION
   Process nodeData file and generate/re-generate mof files where needed.
.EXAMPLE
   Start-DSCClientMOFGeneration
#>
function Start-DSCClientMOFGeneration
{
    [CmdletBinding()]
    Param
    (
        # Full path to registered client data file
        [string]
        $NodeDataPath = (Get-DSCSettingValue NodeDataPath)["NodeDataPath"],
        
        [string]
        $MOFDestPath = "$env:ProgramFiles\WindowsPowerShell\DscService\Configuration",

        [string]
        $InstallPath = (Get-DSCSettingValue InstallPath)["InstallPath"],

        [string]
        $ConfigPath = (Join-Path $InstallPath ((Get-DSCSettingValue GitRepoName)["GitRepoName"])),
        
        [string]
        $ConfigHashPath = (Join-Path $InstallPath "temp"),

        # Name of the event log to use for logging
        [string]
        $LogName = (Get-DSCSettingValue "LogName")["LogName"],

        [string]
        $PullConfig = (Get-DSCSettingValue PullServerConfig)["PullServerConfig"]
    )

    $LogSourceName = $MyInvocation.MyCommand.Name
    if ( -not ([System.Diagnostics.EventLog]::SourceExists($LogSourceName)) ) 
    {
        [System.Diagnostics.EventLog]::CreateEventSource($LogSourceName, $LogName)
    }

    Write-Verbose "Reading the node data file.."
    $NodesData = Get-Content $NodeDataPath -Raw | ConvertFrom-Json

    # Remove mof & checksums that no longer exist in client data file
    # First create an exclusions list with correct format
    $exclusions = $NodesData.Nodes.ConfigID | ForEach-Object { $_,"mof" -join ".";$_,"mof.checksum" -join "."}

    # Remove the 
    $removalList = Get-ChildItem $MOFDestPath -Exclude $exclusions
    if( $removalList )
    {
        Write-Verbose "Removing mof files for non-existent clients..."
        Remove-Item -Path $removalList.FullName -Force -Verbose:($PSBoundParameters['Verbose'] -eq $true)
    }

    # Check configurations for updates by comparing each config file and its hash
    $configs = ($nodesData.Nodes.ClientConfig | Where-Object {$_.ClientConfig -ne $PullConfig} | Sort -Unique)

    # Remove affected mof files if the main DSC client config file has been updated and generate new config file checksum
    foreach( $config in $configs )
    {
        $confFile = Join-Path $configPath $config
        if ($configHashPath)
        {
            $confHash = Join-Path $configHashPath $($config,'checksum' -join '.')
        }
        else
        {
            $confHash = Join-Path $configPath $($config,'checksum' -join '.')
        }     
        if (Test-Path $confFile)
        {
            if( !(Test-ConfigFileHash -file $confFile -hash $confHash) )
            {
                Write-Verbose "$confFile has been modified - regenerating affected mofs..."
                Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 3010 -EntryType Information -Message "$confFile has been modified - regenerating affected mofs..."
                foreach( $server in $($allServers | Where-Object ClientConfig -eq $config) )
                {
                    Write-Verbose "Removing outdated mof file for $($server.ClientName) - $($server.ConfigID)"
                    Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 3011 -EntryType Information -Message "Removing outdated mof file for $($server.ClientName) - $($server.ConfigID)"
                    Remove-ClientMofFiles -ConfigID $($server.ConfigID) -MOFDestPath $MOFDestPath
                }

                Write-Verbose "Generating new checksum for $confFile"
                Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 3012 -EntryType Information -Message "Generating new checksum for $confFile"
                Set-Content -Path $confHash -Value (Get-FileHash -Path $confFile).hash
            }
        }
        else
        {
            # A bit of checksum house keeping 
            if ( Test-Path $confHash )
            {
                Write-Verbose "Removing $confHash"
                Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 3013 -EntryType Information -Message "Removing $confHash"
                Remove-Item -Path $confHash -Force -Verbose:($PSBoundParameters['Verbose'] -eq $true)
            }
        }
    }

    # Generate new or replace outdated mof and checksum files
    foreach( $server in $nodesData.Nodes )
    {
        $confFile = Join-Path $ConfigPath $server.ClientConfig
        $mofFile = (($mofDestPath,$server.ConfigID -join '\'),'mof' -join '.')
        $mofFileHash = ($mofFile,'checksum' -join '.')

        if (Test-Path $confFile)
        {
            if( !(Test-Path $MofFile) -or !(Test-Path $MofFileHash) -or !(Test-ConfigFileHash -file $mofFile -hash $mofFileHash))
            {
                try
                {
                    Write-Verbose "Recreating mofs for $($server.NodeName)"
                    Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 3021 -EntryType Information -Message "Recreating mofs for $($server.NodeName)"
                    Remove-ClientMofFiles -ConfigID $($server.ConfigID) -MOFDestPath $MOFDestPath
                    Write-Verbose "Calling $confFile `n $($server.NodeName) `n $($server.ConfigID)"
                    Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 3022 -EntryType Information -Message "Calling $confFile `n $($server.NodeName) `n $($server.ConfigID)"
                    & $confFile -Node $server.NodeName -ConfigID $server.ConfigID -Verbose
                }
                catch 
                {
                    Write-Verbose "Error creating mof for $($server.NodeName) using $confFile `n$($_.Exception.message)"
                    Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 3023 -EntryType Error -Message "Error creating mof for $($server.NodeName) using $confFile `n$($_.Exception.message) `n $_"
                }
            }
        }
        else
        {
            # Remove left-over mofs for any servers with missing dsc configuration
            Write-Verbose "WARNING: $($server.NodeName) dsc configuration file not found: $confFile"
            Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 3030 -EntryType Warning -Message "DSC configuration file for $($server.NodeName) not found: $confFile"
            Remove-ClientMofFiles -ConfigID $($server.ConfigID) -MOFDestPath $MOFDestPath
        }
    }
}

<#
.Synopsis
   Remove old client nodes and related assets
.DESCRIPTION
   Used to remove old client nodes and their certificates/mof files from pull server
.EXAMPLE
   Example of how to use this cmdlet
#>
function Invoke-DSCHouseKeeping
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        [string]
        $InstallPath = (Get-DSCSettingValue "InstallPath")["InstallPath"],

        [string]
        $configHashPath = (Join-Path $InstallPath "temp"),

        # Name of the event log to use for logging
        [string]
        $LogName = (Get-DSCSettingValue "LogName")["LogName"],

        [string]
        $MOFDestPath = "$env:ProgramFiles\WindowsPowerShell\DscService\Configuration",

        # Number of days to keep old client records
        [int]
        $Age = 30
    )
    
    $LogSourceName = $MyInvocation.MyCommand.Name
    if ( -not ([System.Diagnostics.EventLog]::SourceExists($LogSourceName)) ) 
    {
        [System.Diagnostics.EventLog]::CreateEventSource($LogSourceName, $LogName)
    }


        <# Moved this from Start-DSCClientMOFGeneration
        {
            # Remove left-over mofs for any servers with missing dsc configuration
            Write-Verbose "WARNING: $($server.NodeName) dsc configuration file not found: $confFile"
            Write-Eventlog -LogName $LogName -Source $LogSourceName -EventID 3030 -EntryType Warning -Message "DSC configuration file for $($server.NodeName) not found: $confFile"
            Remove-ClientMofFiles -ConfigID $($server.ConfigID) -MOFDestPath $MOFDestPath
        #>
}
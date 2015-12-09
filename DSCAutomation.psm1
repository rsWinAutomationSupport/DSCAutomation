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

# For DSC Clients, takes $PullServerAddress and sets PullServerIP and PullServerName variables
# If PullServerAddress is an IP, PullServerName is derived from the CN on the PullServer endpoint certificate
function Get-PullServerInfo
{
    param
    (
        [string] $PullServerAddress,
        [int] $PullPort,
        [int] $SleepSeconds = 10
    )

    # Check if PullServeraddress is a hostname or IP
    if($PullServerAddress -match '[a-zA-Z]')
    {
        $PullServerName = $PullServerAddress
    }
    else
    {
        $PullServerAddress | Set-Variable -Name PullServerIP -Scope Global
        # Attempt to get the PullServer's hostname from the certificate attached to the endpoint. 
        # Will not proceed unless a CN name is found.
        $uri = "https://$PullServerAddress`:$PullServerPort"
        do
        {
            $webRequest = [Net.WebRequest]::Create($uri)
            try 
            {
                Write-Verbose "Attempting to connect to Pull server and retrieve its public certificate..."
                $webRequest.GetResponse()
            }
            catch 
            {
            }
            Write-Verbose "Retrieveing Pull Server Name from its certificate"
            $PullServerName = $webRequest.ServicePoint.Certificate.Subject -replace '^CN\=','' -replace ',.*$',''
            if( -not($PullServerName) )
            {
                Write-Verbose "Could not retrieved server name from certificate - sleeping for $SleepSeconds seconds..."
                Start-Sleep -Seconds $SleepSeconds
            }
        } while ( -not($PullServerName) )
    }
    return $PullServerName
}

# Executes main Boot configuration of the DSC Bootstraping process
function Enable-WinRM
{
    if( (Get-ChildItem WSMan:\localhost\Listener | Where-Object Keys -eq "Transport=HTTP").count -eq 0 )
    {
        New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*";Transport="http"}
    }
}

function Protect-DSCAutomationSettings 
{
    [CmdletBinding()]
    param
    (
        # Destination path for DSC Automation secure settings file
        [string]
        $Path = (Join-Path ([System.Environment]::GetEnvironmentVariable("defaultPath","Machine")) "DSCAutomationSettings.xml"),

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
        Move-Item $Path -Destination ("$Path`-$TimeDate.bak") -Force
    }
    
    # Save the encrypted databag as a native PS hashtable object
    Write-Verbose "Saving encrypted settings file to $Path"
    Export-Clixml -InputObject $DSCAutomationSettings -Path $Path -Force
}

function Unprotect-DSCAutomationSettings
{
    [CmdletBinding()]
    param
    (
        # Source path for the secure settings file
        [string]
        $Path = (Join-Path ([System.Environment]::GetEnvironmentVariable("defaultPath","Machine")) "DSCAutomationSettings.xml")
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
   Uses Unprotect-DSCAutomationSettings to decrypt the databag and retrieve the plain-text value for the specified setting.
.EXAMPLE
   Get-DSCSettingValue 'NodeInfoPath'
.EXAMPLE
   Get-DSCSettingValue -Key 'PullServerAddress' -Path 'C:\folder\file.xml'
.EXAMPLE
   Get-DSCSettingValue -Key 'NodeInfoPath', 'GitRepoName'
#>
function Get-DSCSettingValue
{
    [CmdletBinding()]
    Param
    (
        # Key help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Key,
        # Path help description
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string]
        $Path
    )
    # Decrypt contents ofthe DSCAutomation configuration file
    if ($PSBoundParameters.ContainsKey('Path'))
    {
        $DSCSettings = Unprotect-DSCAutomationSettings -Path $Path
    }
    else
    {
        $DSCSettings = Unprotect-DSCAutomationSettings
    }
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

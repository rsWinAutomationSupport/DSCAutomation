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
    [OutputType([int])]
    Param
    (
        # Full path to registered client data file
        [string]
        $NodeDataPath = (Get-DSCSettingValue NodeDataPath)["NodeDataPath"],

        [string]
        $InstallPath = (Get-DSCSettingValue InstallPath)["InstallPath"],
        
        [string]
        $MOFDestPath = "$env:ProgramFiles\WindowsPowerShell\DscService\Configuration",
        
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
                return
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
                $destinationFile = "$CertificatesFolderPath\$($body.ConfigID).cer"
                if ( (Test-Path $destinationFile) )
                {
                    Write-Verbose "Destination Certificate file already exists"
                }
                else
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
                            'timestamp'    = Get-Date
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
                ($nodesData.Nodes  | Where-Object { $_.ConfigID -eq $body.ConfigID } ).timestamp = Get-Date
                Set-Content -Path $NodeDataPath -Value ($nodesData | ConvertTo-Json)
                $GenerateMof = $true
            }
        }
    } while ($msg)

    if ($GenerateMof)
    {
        # Execute Start-DSCmofGeneration
    }
}


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
function Process-DSCClientRegistrations
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Full path to registered client data file
        [Parameter(Mandatory=$true)]
        [string]
        $ClientDataPath,
        
        [string]
        $MOFDestPath = "$env:ProgramFiles\WindowsPowerShell\DscService\Configuration",
        
        [string]
        $ClientConfigPath,
        
        [string]
        $ClientConfigHashPath,
        
        [string]
        $QueueName = "dscregistration",

        [Parameter(Mandatory=$true)]
        [string]
        $CertificatesFolderPath
    )

    [Reflection.Assembly]::LoadWithPartialName("System.Messaging") | Out-Null
    $queue = New-Object System.Messaging.MessageQueue ".\private$\$QueueName"
    $queue.Formatter.TargetTypeNames = ,"System.String"
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
            $certData = [System.Convert]::FromBase64String($body.publicCert)
            try
            {
                $registrationCert.Import($certData)
                Write-Verbose "Cert Import successful, Thumbprint: $($cert.Thumbprint)"
            }
            catch [System.Security.Cryptography.CryptographicException]
            {
                Write-Verbose "Could not import Certificate from message"
                #$_
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
                
                $destinationFile = "$CertificatesFolderPath\$($body.uuid).cer"
                if ( (Test-Path $destinationFile) )
                {
                    Write-Verbose "Destination Certificate file already exists"
                }
                else
                {
                    $CertificateFileData = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    [System.IO.File]::WriteAllBytes($destinationCert, $CertificateFileData)
                }
            }
        }


     } while ($msg)

}


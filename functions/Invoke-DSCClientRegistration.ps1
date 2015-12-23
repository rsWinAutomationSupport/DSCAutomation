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
function Invoke-DSCClientRegistration
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
        $QueueName = "dscregistration"
    )

    Begin
    {
    }
    Process
    {
    }
    End
    {
    }
}


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
function Invoke-DSCPullConfigurationSync
{
    [CmdletBinding()]
    Param
    (
        # Full path to registered client data file
        [Parameter(Mandatory=$true)]
        [string]
        $PullServerConfig = (Get-DSCSettingValue = "PullServerConfig"),
        
        [string]
        $InstallPath = (Get-DSCSettingValue "InstallPath"),
        
        [string]
        $GitRepoName = (Get-DSCSettingValue "GitRepoName")
    )
    Start-Transcript -Path "$env:SystemRoot\temp\dsc_sync_task_result.txt" -Force
    # Delay Pull server conf regen until ongoing LCM run completes
    $LCMStates = @("Idle","PendingConfiguration")
    $LCMtate = (Get-DscLocalConfigurationManager).LCMState
    if ($LCMStates -notcontains $LCMtate)
    {
        Do
        {
            Sleep -Seconds 5
            $LCMtate = (Get-DscLocalConfigurationManager).LCMState
        } while ($LCMStates -notcontains $LCMtate)
        ExecutePullConf -PullServerConfig $PullServerConfig -InstallPath $InstallPath -GitRepoName $GitRepoName
    }
    else
    {
        ExecutePullConf -PullServerConfig $PullServerConfig -InstallPath $InstallPath -GitRepoName $GitRepoName
    }
    
        Stop-Transcript
    }

function ExecutePullConf
{
    Param
    (
        # Full path to registered client data file
        [Parameter(Mandatory=$true)]
        [string]
        $PullServerConfig,
        
        [string]
        $InstallPath,
        
        [string]
        $GitRepoName
    )
    # Ensure that we are using the most recent $path variable
    $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    $ConfDir = Join-Path $InstallPath $GitRepoName
    $PullConf = Join-Path $ConfDir $PullServerConfig
    
    ### Pull latest changes to configuration repository
    Set-Location $ConfDir
    git pull

    ### run Pull config to update DSC config
    & $PullConf
}

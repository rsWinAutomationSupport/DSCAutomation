[CmdletBinding()]
Param
(
    # Default Rackspace provisioning wait timeout set to about 30 minutes
    [int]$Timeout = 1800,

    # Switch to add extra RackConnect v2 API checks
    [bool] $RCv2,

    # Seconds to wait between attempting the checks again
    [int] $SleepTime = 30
)

# Retrieve local xen information
function Get-rsXenInfo
{
    param
    (
        [string] $value
    )

    $CitrixXenStoreBase = Get-WmiObject -n root\wmi -cl CitrixXenStoreBase
    $sid = $CitrixXenStoreBase.AddSession("MyNewSession")
    $session = gwmi -n root\wmi -q "select * from CitrixXenStoreSession where SessionId=$($sid.SessionId)"
    $data = $session.GetValue($value).value -replace "`"", ""
    return $data
}

$AutomationComlete = $false
do 
{
    Write-Verbose "Checking for rax_service_level_automation status..."
    if ((Get-rsXenInfo -value "vm-data/user-metadata/rax_service_level_automation") -ne "Complete")
    {
        Write-Verbose "rax_service_level_automation has not yet completed"
        $AutomationComlete = $false
        Write-Verbose "Waiting for rax_service_level_automation for 60 seconds..."
        Start-Sleep -Seconds $SleepTime
        $Timeout = ($Timeout - $SleepTime)
    }
    else
    {
        $AutomationComlete = $true
        Write-Verbose "rax_service_level_automation complete."
    }
} 
while (($AutomationComlete -eq $false) -or ($Timeout -lt 0))

if ($RCv2)
{
    $RCv2Status = Get-rsXenInfo -value "vm-data/user-metadata/rackconnect_automation_status"
    Write-Verbose "RackConnect status: $RCv2Status"
}

if (($automationComlete -eq $false) -or ($Timeout -lt 0))
{
    Write-Verbose "Timed out while waiting for Rackspace Cloud Automation - some or all Rackspace cloud automation steps did not complete."
}
else
{
    Write-Verbose "Rackspace Service Automation has completed"
}
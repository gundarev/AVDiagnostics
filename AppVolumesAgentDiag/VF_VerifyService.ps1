param($serviceName)
. .\supportfunctions.ps1
$serviceStatus = Get-Service $serviceName -ErrorAction:SilentlyContinue
If ($serviceStatus)
{
    if($serviceStatus.Status -eq 'Running')
    {
    update-diagrootcause -Detected $false -Id  'RC_ServiceNotRunning' -InstanceId $serviceName
        
    }
    else
    {
        update-diagrootcause -Detected  $true -Id  'RC_ServiceNotRunning' -InstanceId $serviceName
        $serviceStartupType = Get-ServiceStartup $serviceStatus
        if($serviceStartupType -ne 'Automatic')
        {
            update-diagrootcause -Detected  $true -id 'RC_ServiceDisabled' -InstanceId $serviceName
        }
    }
}
else
{
    update-diagrootcause -Detected  $true -id 'RC_ServiceNotInstalled' -InstanceId $serviceName
}


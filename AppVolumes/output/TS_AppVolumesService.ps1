$debug = $true
# Load Common Library:
$ComputerName = $Env:computername
$OSVersion = [Environment]::OSVersion.Version
. ./utils_cts.ps1

Import-LocalizedData -BindingVariable AppVolumesService
Write-DiagProgress -Activity $AppVolumesService.ID_ServiceCheck -Status $AppVolumesService.ID_ServiceCheckDesc
$serviceName = 'sppsvc'
'TS_AppVolumesService started'|WriteTo-StdOut
$RootCauseDetected = $false

$serviceStatus = Get-Service $serviceName -ErrorAction:SilentlyContinue
If ($serviceStatus)
{
    if($serviceStatus.Status -eq 'Running')
    {
        ReportIssue $false 'RC_AppVolumesServiceNotRunning'
    }
    else
    {
        ReportIssue $true 'RC_AppVolumesServiceNotRunning'
        $serviceStartupType = Get-ServiceStartup $serviceStatus
        if($serviceStartupType -ne 'Automatic')
        {
            ReportIssue $true 'RC_AppVolumesServiceDisabled'
        }
    }
}
else
{
    ReportIssue $true 'RC_AppVolumesServiceNotInstalled'
}

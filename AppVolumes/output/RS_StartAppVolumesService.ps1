. ./utils_cts.ps1
SkipSecondExecution
Write-DiagProgress -activity "Attempting to start App Volumes Service"
$serviceName = 'sppsvc'
[string]$startupType = (Get-WmiObject -query "select * from win32_baseService where Name='$serviceName'").StartMode


if($startupType -ne "auto")
{
    (Get-WmiObject -query "select * from win32_baseService where Name='$serviceName'").changeStartMode("automatic")
}

Start-Service $serviceName

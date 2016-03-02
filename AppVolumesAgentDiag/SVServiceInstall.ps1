# Resolver Script - This script fixes the root cause. It only runs if the Troubleshooter detects the root cause.
# Key cmdlets: 
# -- get-diaginput invokes an interactions and returns the response
# -- write-diagprogress displays a progress string to the user
Write-DiagProgress -Activity 'Checking InstallDir' -Status 'Checking HKLM\SOFTWARE\Wow6432Node\CloudVolumes\Agent\InstallDir' 
$installDir = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Wow6432Node\CloudVolumes\Agent' -Name 'InstallDir'  -ErrorAction:SilentlyContinue
if ($installDir)
{
    $svservicePath = Join-Path -Path $installDir -ChildPath 'svservice.exe'
    if (Test-Path -Path $($svservicePath))
    {
        $manager_locationResult = Get-DiagInput -Id 'manager_location' 
        $manager_portResult = Get-DiagInput -Id 'manager_port' 
        $manager_sslResult = [int]::Parse($(Get-DiagInput -Id 'manager_ssl'))
        $output= Invoke-Command -ScriptBlock { param ($myarg) & """$svservicePath"" $myarg" } -ArgumentList  "install auto vcenter off ${manager_locationResult}:$manager_portResult"
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\svservice' -Name 'SSL' -Value $manager_sslResult -PropertyType 'DWord' -Force
    }
}


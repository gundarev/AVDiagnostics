# Copyright ?2008, Microsoft Corporation. All rights reserved.

# You may use this code and information and create derivative works of it,
# provided that the following conditions are met:
# 1. This code and information and any derivative works may only be used for
# troubleshooting a) Windows and b) products for Windows, in either case using
# the Windows Troubleshooting Platform
# 2. Any copies of this code and information
# and any derivative works must retain the above copyright notice, this list of
# conditions and the following disclaimer.
# 3. THIS CODE AND INFORMATION IS PROVIDED ``AS IS'' WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. IF THIS CODE AND
# INFORMATION IS USED OR MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION
# WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.



Import-LocalizedData -BindingVariable VirtualizationStrings

Write-DiagProgress -Activity $VirtualizationStrings.ID_Virtualization -Status $VirtualizationStrings.ID_VirtualizationObtaining



$VirtualizationInfo = new-object PSObject

$Script:MicrosoftVirtualizationEnv = $false
$Script:VMWareVirtualizationEnv = $false
$Script:VirtualMachineSoftware = ""
$Script:VMIntegrationsInstalled = $false
$Script:VMToolsInstalled = $false

Function DetectMSVirtualizationSoftware()
{
    $VMBugRegPath = "HKLM:SYSTEM\CurrentControlSet\Services\vmbus"
    if(Test-Path $VMBugRegPath)
    {
        $VMBugStart = (Get-ItemProperty -Path $VMBugRegPath).Start
        if(($VMBugStart -eq 0) -or ($VMBugStart -eq 1))
        {
            $Script:VirtualMachineSoftware = "Hyper-V"
            $VMService = Get-WmiObject -query "Select Name from Win32_Service where Name = 'vmickvpexchange'"
            if($VMService -ne $null)
            {
                $Script:VMIntegrationsInstalled = $true
            }
        }
        else
        {
            $Script:VirtualMachineSoftware = "Virtual Server"
            Get-WmiObject -query "Select Name, Started from Win32_Service where Name = 'VPCMap'" |
                ForEach-Object { 
                    if($_.Started -eq $true) 
                    { 
                        $Script:VirtualMachineSoftware = "Virtual PC"
                    }
                    else
                    {
                        $Script:VirtualMachineSoftware = "Virtual Server"
                    }
                }
            $VMService = Get-WmiObject -query "Select Name, Started from Win32_Service where Name = '1-vmsrvc'"
            if($VMService -ne $null)
            {
                $Script:VMIntegrationsInstalled = $true
            }
        }
    }
}

Function DetectVMWareVirtualizationSoftware()
{
    $Script:VirtualMachineSoftware = "VMWare"
    $VMService = Get-WmiObject -query "Select Name, Started from Win32_Service where Name = 'VMTools'"
    if($VMService -ne $null)
    {
        $Script:VMToolsInstalled = $true
    }
}

Function DetectVirtualizationEnv()
{
    $Manufacturer = (Get-wmiobject -class 'Win32_ComputerSystem').Manufacturer
    if($Manufacturer.Contains("Microsoft"))
    {
        $Script:MicrosoftVirtualizationEnv = $true
        DetectMSVirtualizationSoftware
    }
    elseif($Manufacturer.Contains("VMware"))
    {
        $Script:VMWareVirtualizationEnv = $true
        DetectVMWareVirtualizationSoftware
    }
}

DetectVirtualizationEnv



if($Script:MicrosoftVirtualizationEnv -or $Script:VMWareVirtualizationEnv)
{
    add-member -inputobject $VirtualizationInfo -membertype noteproperty -name "Virtual Machine Software" -value $Script:VirtualMachineSoftware
    if($Script:MicrosoftVirtualizationEnv)
    {
        add-member -inputobject $VirtualizationInfo -membertype noteproperty -name "Integration Services Installed" -value $Script:VMIntegrationsInstalled
        if($RootCauseDetected)
        {
            add-member -inputobject $VirtualizationInfo -membertype noteproperty -name "Windows Azure" -value $true
        }
        else
        {
            add-member -inputobject $VirtualizationInfo -membertype noteproperty -name "Windows Azure" -value $false
        }
    }
    elseif($Script:VMWareVirtualizationEnv)
    {
        add-member -inputobject $VirtualizationInfo -membertype noteproperty -name "VMTools installed" -value $Script:VMToolsInstalled
    }
	
    $VirtualizationInfo | ConvertTo-Xml2 | update-diagreport -id ("zzz_Virtualization Report") -name ("Virtual Environment Information") -verbosity informational
}

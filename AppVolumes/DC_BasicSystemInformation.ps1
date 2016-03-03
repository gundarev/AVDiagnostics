
PARAM($MachineName = $null)

if ($MachineName -ne $null) 
{
    $AddToHeader = "$MachineName - "
    if ($ComputerName -eq $MachineName)
    {
        $MachineName = '.'
    }
}
else 
{
    $AddToHeader = ''
    $MachineName = '.'
}

Import-LocalizedData -BindingVariable DC_Strings

Write-DiagProgress -Activity $DC_Strings.ID_CollectActivity -Status ($AddToHeader + $DC_Strings.ID_CollectingData)

$OS_Summary = New-Object -TypeName PSObject                  # Operating System Summary
$CS_Summary = New-Object -TypeName PSObject                  # Computer System Summary

$WMIOS = $null

$error.Clear()

$WMIOS = Get-WmiObject -Class 'win32_operatingsystem' -ComputerName $MachineName -ErrorAction SilentlyContinue

if ($error.Count -ne 0) 
{
    $errorMessage = $error[0].Exception.Message
    $errorCode = '0x{0:X}' -f $error[0].Exception.ErrorCode
    'Error' +  $errorCode + ": $errorMessage connecting to $MachineName" | WriteTo-StdOut
    $error.Clear()
}

# Get all data from WMI

if ($WMIOS -ne $null) 
{
    #if WMIOS is null - means connection failed. Abort script execution.

    $WMICS = Get-WmiObject -Class 'win32_computersystem' -ComputerName $MachineName
    $WMIProcessor = Get-WmiObject -Class 'Win32_processor' -ComputerName $MachineName

    Write-DiagProgress -Activity $DC_Strings.ID_CollectActivity -Status ($AddToHeader + $DC_Strings.ID_FormattingData)

    $OSProcessorArch = $WMIOS.OSArchitecture
    $OSProcessorArchDisplay = ' ' + $OSProcessorArch
    #There is no easy way to detect the OS Architecture on pre-Windows Vista Platform
    if ($OSProcessorArch -eq $null)
    {
        if ($MachineName -eq '.') 
        {
            #Local Computer
            $OSProcessorArch = $Env:PROCESSOR_ARCHITECTURE
        }
        else 
        {
            $RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$MachineName)
            $OSProcessorArch = ($RemoteReg.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment')).GetValue('PROCESSOR_ARCHITECTURE')
        }

        if ($OSProcessorArch -ne $null) 
        {
            switch ($OSProcessorArch) {
                'AMD64' 
                {
                    $ProcessorArchDisplay = ' (64-bit)'
                }
                'i386' 
                {
                    $ProcessorArchDisplay = ' (32-bit)'
                }
                'IA64' 
                {
                    $ProcessorArchDisplay = ' (64-bit - Itanium)'
                }
                default 
                {
                    $ProcessorArchDisplay = " ($ProcessorArch)"
                }
            }
        }
        else 
        {
            $OSProcessorArchDisplay = ''
        }
    }


    # Build OS Summary
    # Name
    Add-Member -InputObject $OS_Summary -MemberType noteproperty -Name 'Machine Name' -Value $WMIOS.CSName
    Add-Member -InputObject $OS_Summary -MemberType noteproperty -Name 'OS Name' -Value ($WMIOS.Caption + ' Service Pack ' + $WMIOS.ServicePackMajorVersion + $OSProcessorArchDisplay)
    Add-Member -InputObject $OS_Summary -MemberType noteproperty -Name 'Build' -Value ($WMIOS.Version)
    Add-Member -InputObject $OS_Summary -MemberType noteproperty -Name 'Time Zone/Offset' -Value (Replace-XMLChars -RAWString ((Get-WmiObject -Class Win32_TimeZone).Caption + '/' + $WMIOS.CurrentTimeZone))

    # Install Date
    #$date = [DateTime]::ParseExact($wmios.InstallDate.Substring(0, 8), "yyyyMdd", $null)
    #add-member -inputobject $OS_Summary -membertype noteproperty -name "Install Date" -value $date.ToShortDateString()
    Add-Member -InputObject $OS_Summary -MemberType noteproperty -Name 'Last Reboot/Uptime' -Value ($WMIOS.ConvertToDateTime($WMIOS.LastBootUpTime).ToString() + ' (' + (GetAgeDescription(New-TimeSpan -Start $WMIOS.ConvertToDateTime($WMIOS.LastBootUpTime))) + ')')
	
    # Build Computer System Summary
    # Name
    Add-Member -InputObject $CS_Summary -MemberType noteproperty -Name 'Computer Model' -Value ($WMICS.Manufacturer + ' ' + $WMICS.model)
	
    $numProcs = 0
    $ProcessorType = ''
    $ProcessorName = ''
    $ProcessorDisplayName = ''

    foreach ($WMIProc in $WMIProcessor) 
    {
        $ProcessorType = $WMIProc.manufacturer
        switch ($WMIProc.NumberOfCores) 
        {
            1 
            {
                $numberOfCores = 'single core'
            }
            2 
            {
                $numberOfCores = 'dual core'
            }
            4 
            {
                $numberOfCores = 'quad core'
            }
            $null 
            {
                $numberOfCores = 'single core'
            }
            default 
            {
                $numberOfCores = $WMIProc.NumberOfCores.ToString() + ' core' 
            } 
        }
		
        switch ($WMIProc.Architecture)
        {
            0 
            {
                $CpuArchitecture = 'x86'
            }
            1 
            {
                $CpuArchitecture = 'MIPS'
            }
            2 
            {
                $CpuArchitecture = 'Alpha'
            }
            3 
            {
                $CpuArchitecture = 'PowerPC'
            }
            6 
            {
                $CpuArchitecture = 'Itanium'
            }
            9 
            {
                $CpuArchitecture = 'x64'
            }
        }
		
        if ($ProcessorDisplayName.Length -eq 0)
        {
            $ProcessorDisplayName = ' ' + $numberOfCores + " $CpuArchitecture processor " + $WMIProc.name
        }
        else 
        {
            if ($ProcessorName -ne $WMIProc.name) 
            {
                $ProcessorDisplayName += '/ ' + ' ' + $numberOfCores + " $CpuArchitecture processor " + $WMIProc.name
            }
        }
        $numProcs += 1
        $ProcessorName = $WMIProc.name
    }
    $ProcessorDisplayName = "$numProcs" + $ProcessorDisplayName
	
    Add-Member -InputObject $CS_Summary -MemberType noteproperty -Name 'Processor(s)' -Value $ProcessorDisplayName
	
    if ($WMICS.Domain -ne $null) 
    {
        Add-Member -InputObject $CS_Summary -MemberType noteproperty -Name 'Machine Domain' -Value $WMICS.Domain
    }
	
    if ($WMICS.DomainRole -ne $null) 
    {
        switch ($WMICS.DomainRole) {
            0 
            {
                $RoleDisplay = 'Workstation'
            }
            1 
            {
                $RoleDisplay = 'Member Workstation'
            }
            2 
            {
                $RoleDisplay = 'Standalone Server'
            }
            3 
            {
                $RoleDisplay = 'Member Server'
            }
            4 
            {
                $RoleDisplay = 'Backup Domain Controller'
            }
            5 
            {
                $RoleDisplay = 'Primary Domain controller'
            }
        }
        Add-Member -InputObject $CS_Summary -MemberType noteproperty -Name 'Role' -Value $RoleDisplay
    }
	
    if ($WMIOS.ProductType -eq 1) 
    {
        #Client
        $AntivirusProductWMI = Get-WmiObject -Query 'select companyName, displayName, versionNumber, productUptoDate, onAccessScanningEnabled FROM AntivirusProduct' -Namespace 'root\SecurityCenter' -ComputerName $MachineName
        if ($AntivirusProductWMI.displayName -ne $null) 
        {
            $AntivirusDisplay = $AntivirusProductWMI.companyName + ' ' + $AntivirusProductWMI.displayName + ' version ' + $AntivirusProductWMI.versionNumber
            if ($AntivirusProductWMI.onAccessScanningEnabled) 
            {
                $AVScanEnabled = 'Enabled'
            }
            else 
            {
                $AVScanEnabled = 'Disabled'
            }
            if ($AntivirusProductWMI.productUptoDate) 
            {
                $AVUpToDate = 'Yes'
            }
            else 
            {
                $AVUpToDate = 'No'
            }
            #$AntivirusStatus = "OnAccess Scan: $AVScanEnabled" + ". Up to date: $AVUpToDate" 
	
            Add-Member -InputObject $OS_Summary -MemberType noteproperty -Name 'Anti Malware' -Value $AntivirusDisplay
        }
        else 
        {
            $AntivirusProductWMI = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $MachineName
            if ($AntivirusProductWMI -ne $null) 
            {	
                $X = 0
                $Antivirus = @()
                $AntivirusProductWMI | ForEach-Object -Process {
                    $ProductVersion = $null
                    if ($_.pathToSignedProductExe -ne $null)
                    {
                        $AVPath = [System.Environment]::ExpandEnvironmentVariables($_.pathToSignedProductExe)
                        if (($AVPath -ne $null) -and (Test-Path $AVPath))
                        {
                            $VersionInfo = (Get-ItemProperty $AVPath).VersionInfo
                            if ($VersionInfo -ne $null)
                            {
                                $ProductVersion = ' version ' + $VersionInfo.ProductVersion.ToString()
                            }
                        }
                    }
					
                    $Antivirus += "$($_.displayName) $ProductVersion"
                }
                if ($Antivirus.Count -gt 0)
                {
                    Add-Member -InputObject $OS_Summary -MemberType noteproperty -Name 'Anti Malware' -Value ([string]::Join('<br/>', $Antivirus))
                }
            }
        }
    }
	
    if ($MachineName -eq '.') 
    {
        #Local Computer
        $SystemPolicies = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $EnableLUA = $SystemPolicies.EnableLUA
        $ConsentPromptBehaviorAdmin = $SystemPolicies.ConsentPromptBehaviorAdmin
    }
    else 
    {
        $RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$MachineName)
        $EnableLUA  = ($RemoteReg.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')).GetValue('EnableLUA')
        $ConsentPromptBehaviorAdmin = ($RemoteReg.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')).GetValue('ConsentPromptBehaviorAdmin')
    }
	
    if ($EnableLUA) 
    {
        $UACDisplay = 'Enabled'
	
        switch ($ConsentPromptBehaviorAdmin) {
            0 
            {
                $UACDisplay += ' / ' + $DC_Strings.ID_UACAdminMode + ': ' + $DC_Strings.ID_UACNoPrompt
            }
            1 
            {
                $UACDisplay += ' / ' + $DC_Strings.ID_UACAdminMode + ': ' + $DC_Strings.ID_UACPromptCredentials
            }
            2 
            {
                $UACDisplay += ' / ' + $DC_Strings.ID_UACAdminMode + ': ' + $DC_Strings.ID_UACPromptConsent
            }
            5 
            {
                $UACDisplay += ' / ' + $DC_Strings.ID_UACAdminMode + ': ' + $DC_Strings.ID_UACPromptConsentApp
            }
        }
    }
    else 
    {
        $UACDisplay = 'Disabled'
    }
	
    Add-Member -InputObject $OS_Summary -MemberType noteproperty -Name $DC_Strings.ID_UAC -Value $UACDisplay
	
    if ($MachineName -eq '.') 
    {
        #Local Computer only. Will not retrieve username from remote computers
        Add-Member -InputObject $OS_Summary -MemberType noteproperty -Name 'Username' -Value ($Env:USERDOMAIN + '\' + $Env:USERNAME)
    }
	
    #System Center Advisor Information
    $SCAKey = 'HKLM:\SOFTWARE\Microsoft\SystemCenterAdvisor'
    if (Test-Path($SCAKey))
    {
        $CustomerID = (Get-ItemProperty -Path $SCAKey).CustomerID
        if ($CustomerID -ne $null)
        {
            "System Center Advisor detected. Customer ID: $CustomerID" | writeto-stdout
            $SCA_Summary = New-Object -TypeName PSObject
            $SCA_Summary | Add-Member -MemberType noteproperty -Name 'Customer ID' -Value $CustomerID
            $SCA_Summary |
            ConvertTo-Xml2 |
            Update-DiagReport -Id ('01_SCACustomerSummary') -Name 'System Center Advisor' -Verbosity Informational
        }		
    }

    Add-Member -InputObject $CS_Summary -MemberType NoteProperty -Name 'RAM (physical)' -Value (FormatBytes -bytes $WMICS.TotalPhysicalMemory -precision 1)
	
    $OS_Summary |
    convertto-xml2 |
    Update-DiagReport -Id ('00_OSSummary') -Name ($AddToHeader + 'Operating System')  -Verbosity informational
    $CS_Summary |
    ConvertTo-Xml |
    Update-DiagReport -Id ('01_CSSummary') -Name ($AddToHeader + 'Computer System') -Verbosity informational

} 

# SIG # Begin signature block
# MIIX6wYJKoZIhvcNAQcCoIIX3DCCF9gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8DFnfvvBQVutBpeMCzazBgce
# dvygghMaMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggUqMIIEEqADAgECAhAMSIndHZLwex40TI0VYAhsMA0GCSqGSIb3DQEBCwUAMHYx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xNTAzBgNVBAMTLERpZ2lDZXJ0IFNIQTIgSGlnaCBBc3N1
# cmFuY2UgQ29kZSBTaWduaW5nIENBMB4XDTE2MDIxOTAwMDAwMFoXDTE3MDYyMzEy
# MDAwMFowaTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEzARBgNV
# BAcTClBsZWFzYW50b24xFzAVBgNVBAoTDkRlbmlzIEd1bmRhcmV2MRcwFQYDVQQD
# Ew5EZW5pcyBHdW5kYXJldjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AOOJcuMjKuhSovJyrzLRh+5XH7spIA45zBk9mPHX7j7U+X7O2/iIEEDUc8p0Qy7I
# ycW+39d0p9e2c5kle2iT2QnN/pqdDvZbndHnvF2xFFh5hl3MqqrYGmUcue7Vlu9r
# zIYjAgAniic/a53qC92Wnpk7pydHS/Hl0DgFEn3RDR961CzeNtclF2lp3SuTD+io
# v9twVlb/L0oEjjFNxuUgHAlgqdCFIAWJlcTQggK/bBKb/QWtqjF927L7lgRVtzRy
# V4oJPt4oacqvIrTedy0e02aV4WUFPZposSIg7cKQx7pmJHAB5NJvJUB9Eth5/d5C
# BDhW1myurwBBDY8gHy0hX00CAwEAAaOCAb8wggG7MB8GA1UdIwQYMBaAFGedDyAJ
# DMyKOuWCRnJi/PHMkOVAMB0GA1UdDgQWBBRC9mOHh9Y1O82w1feeNT6ZZIm2wzAO
# BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwbQYDVR0fBGYwZDAw
# oC6gLIYqaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItaGEtY3MtZzEuY3Js
# MDCgLqAshipodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hhMi1oYS1jcy1nMS5j
# cmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAwEwKjAoBggrBgEFBQcCARYcaHR0cHM6
# Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBBAEwgYgGCCsGAQUFBwEBBHww
# ejAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFIGCCsGAQUF
# BzAChkZodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEySGln
# aEFzc3VyYW5jZUNvZGVTaWduaW5nQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZI
# hvcNAQELBQADggEBAHBv2po0TrjQsjpUwDl9RWKK+9hEPyWFCKib8LR3xOYtAhav
# 5tpHYIkZSXDSnnp4JABmq0ss2A6gk6J5yXWDkAwdq8UAoGgvxpprrgSEhGdy6JMO
# Atow/xqx5PAVrXZVgxk7xgUOSPN6v5VaDdRkrtUTyiFih6njVLGThR/DEHQUOmyC
# 2bUjjAGMtKJ2NMvrPNCJGSEqtbi8Y1Us1QPrn2dcHmbqbS0rPgVpSlaMBP09uX4I
# QPwKLOd2vSfE/oLjOUu6qDeayEmq1/t6hIgzpN93Ml+QgbaNKHWzHqcJc1oYn1y+
# k8+wRdhZANH57sxxaV3AebCdyIaamEDjvk/CNFowggVPMIIEN6ADAgECAhALfhCQ
# PDhJD/ovZ5qHoae5MA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xKzAp
# BgNVBAMTIkRpZ2lDZXJ0IEhpZ2ggQXNzdXJhbmNlIEVWIFJvb3QgQ0EwHhcNMTMx
# MDIyMTIwMDAwWhcNMjgxMDIyMTIwMDAwWjB2MQswCQYDVQQGEwJVUzEVMBMGA1UE
# ChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTUwMwYD
# VQQDEyxEaWdpQ2VydCBTSEEyIEhpZ2ggQXNzdXJhbmNlIENvZGUgU2lnbmluZyBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALRKXn0HD0HexPV2Fja9
# cf/PP09zS5zRDf5Ky1dYXoUW3QIVVJnwjzwvTQJ4EGjI2DVLP8H3Z86YHK4zuS0d
# pApUk8SFot81sfXxPKezNPtdSMlGyWJEvEiZ6yhJU8M9j8AO3jWY6WJR3z1rQGHu
# BEHaz6dcVpbR+Uy3RISHmGnlgrkT5lW/yJJwkgoxb3+LMqvPa1qfYsQ+7r7tWaRT
# fwvxUoiKewpnJMuQzezSTTRMsOG1n5zG9m8szebKU3QBn2c13jhJLc7tOUSCGXlO
# GrK1+7t48Elmp8/6XJZ1kosactn/UJJTzD7CQzIJGoYTaTz7gTIzMmR1cygmHQgw
# OwcCAwEAAaOCAeEwggHdMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD
# AgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMH8GCCsGAQUFBwEBBHMwcTAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEkGCCsGAQUFBzAChj1odHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZS
# b290Q0EuY3J0MIGPBgNVHR8EgYcwgYQwQKA+oDyGOmh0dHA6Ly9jcmw0LmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVlJvb3RDQS5jcmwwQKA+oDyG
# Omh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VF
# VlJvb3RDQS5jcmwwTwYDVR0gBEgwRjA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUH
# AgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCgYIYIZIAYb9bAMwHQYD
# VR0OBBYEFGedDyAJDMyKOuWCRnJi/PHMkOVAMB8GA1UdIwQYMBaAFLE+w2kD+L9H
# AdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBCwUAA4IBAQBqDv9+E3wGpUvALoz5U2QJ
# 4rpYkTBQ7Myf4dOoL0hGNhgp0HgoX5hWQA8eur2xO4dc3FvYIA3tGhZN1REkIUvx
# J2mQE+sRoQHa/bVOeVl1vTgqasP2jkEriqKL1yxRUdmcoMjjTrpsqEfSTtFoH4wC
# VzuzKWqOaiAqufIAYmS6yOkA+cyk1LqaNdivLGVsFnxYId5KMND66yRdBsmdFret
# SkXTJeIM8ECqXE2sfs0Ggrl2RmkI2DK2gv7jqVg0QxuOZ2eXP2gxFjY4lT6H98fD
# r516dxnZ3pO1/W4r/JT5PbdMEjUsML7ojZ4FcJpIE/SM1ucerDjnqPOtDLd67Gft
# MYIEOzCCBDcCAQEwgYowdjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTE1MDMGA1UEAxMsRGlnaUNl
# cnQgU0hBMiBIaWdoIEFzc3VyYW5jZSBDb2RlIFNpZ25pbmcgQ0ECEAxIid0dkvB7
# HjRMjRVgCGwwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFP0YbrWsx/re6C5goKeQ+F0n8ocgMA0G
# CSqGSIb3DQEBAQUABIIBAMvu+/mIoAZZ8CByIj0iGdfIukyLSXqsHj4rsnZHAG/4
# R4MIoI/HD/eNc4JwThOn2Erlp6k+Mv2YR6JFRb1+w+5ltGsj6XfkQJNCYYe5ssi2
# JKAlFxi7TI3Fvu2GD/2fSMgCgAKUFJSO35InbRglz45T8F3e44XBd1IzMMKK0I5G
# SSIPGoVARhsE5D8RHesfhouSporMTWk/VYaKe0Qho9wHkR+xJCLSvwZ2NluERhR+
# us3RHk0Ft7HsWmPnoNlqlBIQwdOvEdGta0MRI4dx1+71vmtJ0U5kfHCsI4Q+d7/I
# NWHLUzt+vbswlwZCG5X/P5ECAILxARN4+ShE9c1Yc7yhggILMIICBwYJKoZIhvcN
# AQkGMYIB+DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50
# ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcg
# U2VydmljZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0w
# GAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYwMzAz
# MDQyMTU3WjAjBgkqhkiG9w0BCQQxFgQUMQjVS8HakVG5NlCspjgW2DUkcOcwDQYJ
# KoZIhvcNAQEBBQAEggEAWBeFKpDg26lrurA+LSRkKl0eO2VXmfl89lXXB+/kI0Cp
# ANiLFjeroXbhklL2HCi1vyyLRsfu56XpDg/WThe1HGljD+vfYuJBbA98nDaB3PqE
# WvMJSW7dttfRBUIGEx4Tz3Dl6uTKg7GgOv+hWDFpaKTd9Fzg+s2vws7x8b0F18dx
# E/L2CQS5eg8Sdd+T73Gzg/HasbfHJskeLLbaK/2d9QVJt/dyWv2ig9AjH2xMB586
# XFPCcTFZW0xNE8Q0L8rV0QA4RaJAWn29CSxkVmOiyY8InVNeSAqIs457hbOAuYCn
# 7Yp84Z9L+piH8ik8jIFvbjXQU89MqYlxT08F9C0WmA==
# SIG # End signature block

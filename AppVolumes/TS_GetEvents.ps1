#************************************************
# TS_GetEvents.ps1
# Version 2.3.5
# Date: 05-13-2013
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script is used to export machine event logs in different formats, such as EVT(X), CSV and TXT
#************************************************

PARAM($EventLogNames="AllWMI", 
	  $OutputFormats="",
	  $ExclusionList="", 
	  $Days="", 
	  $EventLogAdvisorAlertXMLs ="",
	  $SectionDescription="Event Logs",
	  $Prefix=$null,
	  $Suffix=$null,
	  $Query=$Null,
	  $After,
	  $Before,
	  [switch] $DisableRootCauseDetection)

Import-LocalizedData -BindingVariable GetEventsStrings

Write-DiagProgress -Activity $GetEventsStrings.ID_EVENTLOG -Status $GetEventsStrings.ID_ExportingLogs

$DisplayToAdd = ''

if (-not (Test-Path($PWD.Path + "\EventLogs")))
{
	md ($PWD.Path + "\EventLogs")
}

$OutputPath = $PWD.Path + "\EventLogs"

if (($OSVersion.Major -lt 6) -and ($EventLogNames -eq "AllEvents")) #Pre-WinVista
{
	$EventLogNames = "AllWMI"
}

if ($Days -ne "")
{
	$Days = "/days:$Days"
	$DisplayToAdd = " ($Days days)"
	
	if ($Query -ne $null) {"WARNING: Query argument cannot be used in conjunction with -Days and will be ignored" | WriteTo-StdOut -IsError -ShortFormat -InvokeInfo $MyInvocation}
	if (($After -ne $null) -or ($Before -ne $null) ) {"WARNING: -After or -Before arguments cannot be used in conjunction with -Days and will be ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation}
}
elseif ($Query -ne $null)
{
	$Query = "`"/query:$Query`""
	if (($After -ne $null) -or ($Before -ne $null)) {"WARNING: -After or -Before arguments cannot be used in conjunction with -Query and will be ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation}
}
elseif (($After -ne $null) -and ($Before -ne $null) -and ($Before -le $After))
{
	"WARNING: -Before argument contains [$Before] and cannot be earlier than -After argument: [$After] and therefore it will ignored." | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation
	$After = $null
}

if ((($After -ne $null) -or ($Before -ne $null)) -and ($OSVersion.Major -ge 6))
{
	if (($After -ne $null) -and (($After -as [DateTime]) -eq $null))
	{
		"-After argument type is [" + $After.GetType() + "] and contains value [$After]. This value cannot be converted to [datetime] and will be ignored" | WriteTo-StdOut -IsError
		$After = $null
	}
	
	if (($Before -ne $null) -and (($Before -as [DateTime]) -eq $null))
	{
		"-Before argument type is [" + $Before.GetType() + "] and contains value [$Before]. This value cannot be converted to [datetime] and will be ignored" | WriteTo-StdOut -IsError
		$Before = $null
	}
	
	if (($After -ne $null) -or ($Before -ne $null))
	{
		$DisplayToAdd = " (Filtered)"
		$TimeRange = @()

		if ($Before -ne $null)
		{
			$BeforeLogString = "[Before: $Before $($Before.Kind.ToString())]"
			if ($Before.Kind -ne [System.DateTimeKind]::Utc)
			{
				$Before += [System.TimeZoneInfo]::ConvertTimeToUtc($Before)
			}
			$TimeRange += "@SystemTime <= '" + $Before.ToString("o") + "'"
		}
		
		if ($After -ne $null)
		{
			$AfterLogString = "[After: $After $($After.Kind.ToString())]"
			if ($After.Kind -ne [System.DateTimeKind]::Utc)
			{
				$After += [System.TimeZoneInfo]::ConvertTimeToUtc($After)
			}
			$TimeRange += "@SystemTime >= '" + $After.ToString("o") + "'"
		}

		"-Before and/ or -After arguments to TS_GetEvents were used: $BeforeLogString $AfterLogString" | WriteTo-StdOut

		$Query = "*[System[TimeCreated[" + [string]::Join(" and ", $TimeRange) + "]]]"
		$Query = "`"/query:$Query`""
	}
}
elseif ((($After -ne $null) -or ($Before -ne $null)) -and ($OSVersion.Major -lt 6))
{
	"WARNING: Arguments -After or -Before arguments are supported only on Windows Vista or newer Operating Systems and therefore it will ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation
	$After = $null
	$Before = $null
}

switch ($EventLogNames)	
{
	"AllEvents" 
	{
		#Commented line below since Get-WinEvent requires .NET Framework 3.5 - which is not always installed on server media
		#$EventLogNames = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} | Select-Object LogName
		$EventLogNames = wevtutil.exe el
	}
	"AllWMI" 
	{
		$EventLogList = Get-EventLog -List | Where-Object {$_.Entries.Count -gt 0} | Select-Object @{Name="LogName"; Expression={$_.Log}}
		$EventLogNames = @()
		$EventLogList | ForEach-Object {$EventLogNames += $_.LogName}
	}
}

if ($OutputFormats -eq "") 
{
	$OutputFormatCMD = "/TXT /CSV /evtx /evt"
} 
else 
{
	ForEach ($OutputFormat in $OutputFormats) 
	{
		$OutputFormatCMD += "/" + $OutputFormat + " "
	}
}

$EventLogAdvisorXMLCMD = ""

if (($EventLogAdvisorAlertXMLs -ne "") -or ($Global:EventLogAdvisorAlertXML -ne $null))
{
	$EventLogAdvisorXMLFilename = Join-Path -Path $PWD.Path -ChildPath "EventLogAdvisorAlerts.XML"
	"<?xml version='1.0'?>" | Out-File $EventLogAdvisorXMLFilename
	
	if ($EventLogAdvisorAlertXMLs -ne "")
	{
		ForEach ($EventLogAdvisorXML in $EventLogAdvisorAlertXMLs) 
		{
			#Save Alerts to disk, then, use file as command line for GetEvents script
			$EventLogAdvisorXML | Out-File $EventLogAdvisorXMLFilename -append
		}
	}
	
	if ($Global:EventLogAdvisorAlertXML -ne $null)
	{
		if (Test-Path $EventLogAdvisorXMLFilename)
		{
			"[GenerateEventLogAdvisorXML] $EventLogAdvisorXMLFilename already exists. Merging content."
			[xml] $EventLogAdvisorXML = Get-Content $EventLogAdvisorXMLFilename
			
			ForEach ($GlobalSectionNode in $Global:EventLogAdvisorAlertXML.SelectNodes("/Alerts/Section"))
			{
			
				$SectionName = $GlobalSectionNode.SectionName
				$SectionElement = $EventLogAdvisorXML.SelectSingleNode("/Alerts/Section[SectionName = `'$SectionName`']")
				if ($SectionElement -eq $null)
				{
					$SectionElement = $EventLogAdvisorXML.CreateElement("Section")						
					$X = $EventLogAdvisorXML.SelectSingleNode('Alerts').AppendChild($SectionElement)
					
					$SectionNameElement = $EventLogAdvisorXML.CreateElement("SectionName")
					$X = $SectionNameElement.set_InnerText($SectionName)						
					$X = $SectionElement.AppendChild($SectionNameElement)
					
					$SectionPriorityElement = $EventLogAdvisorXML.CreateElement("SectionPriority")
					$X = $SectionPriorityElement.set_InnerText(30)
					$X = $SectionElement.AppendChild($SectionPriorityElement)
				}
				
				ForEach ($GlobalSectionAlertNode in $GlobalSectionNode.SelectNodes("Alert"))
				{
					$EventLogName = $GlobalSectionAlertNode.EventLog
					$EventLogSource = $GlobalSectionAlertNode.Source
					$EventLogId = $GlobalSectionAlertNode.ID
					
					$ExistingAlertElement = $EventLogAdvisorXML.SelectSingleNode("/Alerts/Section[Alert[(EventLog = `'$EventLogName`') and (Source = `'$EventLogSource`') and (ID = `'$EventLogId`')]]")

					if ($ExistingAlertElement -eq $null)
					{
						$AlertElement = $EventLogAdvisorXML.CreateElement("Alert")
						$X = $AlertElement.Set_InnerXML($GlobalSectionAlertNode.Get_InnerXML())
						$X = $SectionElement.AppendChild($AlertElement)
					}
					else
					{
						"WARNING: An alert for event log [$EventLogName], Event ID [$EventLogId], Source [$EventLogSource] was already been queued by another script." | WriteTo-StdOut -ShortFormat
					}
				}
			}
			
			$EventLogAdvisorXML.Save($EventLogAdvisorXMLFilename)
				
		}
		else
		{
			$Global:EventLogAdvisorAlertXML.Save($EventLogAdvisorXMLFilename)
		}
	}
	
	$EventLogAdvisorXMLCMD = "/AlertXML:$EventLogAdvisorXMLFilename /GenerateScriptedDiagXMLAlerts "
}
	
if ($SectionDescription -eq "") 
{
	$SectionDescription = $GetEventsStrings.ID_EventLogFiles
}

if ($Prefix -ne $null)
{
	$Prefix = "/prefix:`"" + $ComputerName + "_evt_" + $Prefix + "`""
}

if ($Suffix -ne $null)
{
	$Suffix = "/suffix:`"" + $Suffix + "`""
}

ForEach ($EventLogName in $EventLogNames) 
{
    if ($ExclusionList -notcontains $EventLogName) 
	{
		$ExportingString = $GetEventsStrings.ID_ExportingLogs
    	Write-DiagProgress -Activity $GetEventsStrings.ID_EVENTLOG -Status ($ExportingString + ": " + $EventLogName)
    	$CommandToExecute = "cscript.exe //E:vbscript GetEvents.VBS `"$EventLogName`" /channel $Days $OutputFormatCMD $EventLogAdvisorXMLCMD `"$OutputPath`" /noextended $Query $Prefix $Suffix"
		$OutputFiles = $OutputPath + "\" + $Computername + "_evt_*.*"
		$FileDescription = $EventLogName.ToString() + $DisplayToAdd

		RunCmD -commandToRun $CommandToExecute -sectionDescription $SectionDescription -filesToCollect $OutputFiles -fileDescription $FileDescription

		$EventLogFiles = Get-ChildItem $OutputFiles
		if ($EventLogFiles -ne $null) 
		{
    		$EventLogFiles | Remove-Item
    	}
    }
}

$EventLogAlertXMLFileName = $Computername + "_EventLogAlerts.XML"

if (($DisableRootCauseDetection.IsPresent -ne $true) -and (test-path $EventLogAlertXMLFileName)) 
{	
	[xml] $XMLDoc = Get-Content -Path $EventLogAlertXMLFileName
	if($XMLDoc -ne $null)
	{
		$Processed = $XMLDoc.SelectSingleNode("//Processed").InnerXML
	}
	
	if($Processed -eq $null)
	{
		#Check if there is any node that does not contain SkipRootCauseDetection. In this case, set root cause detected to 'true'
		if ($XMLDoc.SelectSingleNode("//Object[not(Property[@Name=`"SkipRootCauseDetection`"])]") -eq $null)
		{
			Update-DiagRootCause -id RC_GetEvents -Detected $true
			
			if($XMLDoc -ne $null)
			{
				[System.Xml.XmlElement] $rootElement=$XMLDoc.SelectSingleNode("//Root")
				[System.Xml.XmlElement] $element = $XMLDoc.CreateElement("Processed")
				$element.innerXML = "True"
				$rootElement.AppendChild($element)
				$XMLDoc.Save($EventLogAlertXMLFileName)	
			}
		}
	}
}

# SIG # Begin signature block
# MIIa7AYJKoZIhvcNAQcCoIIa3TCCGtkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUzceRy3v6xNw0jHcrAyM00wnG
# YxGgghWCMIIEwzCCA6ugAwIBAgITMwAAAEyh6E3MtHR7OwAAAAAATDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTMxMTExMjIxMTMx
# WhcNMTUwMjExMjIxMTMxWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkMwRjQtMzA4Ni1ERUY4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsdj6GwYrd6jk
# lF18D+Z6ppLuilQdpPmEdYWXzMtcltDXdS3ZCPtb0u4tJcY3PvWrfhpT5Ve+a+i/
# ypYK3EbxWh4+AtKy4CaOAGR7vjyT+FgyeYfSGl0jvJxRxA8Q+gRYtRZ2buy8xuW+
# /K2swUHbqs559RyymUGneiUr/6t4DVg6sV5Q3mRM4MoVKt+m6f6kZi9bEAkJJiHU
# Pw0vbdL4d5ADbN4UEqWM5zYf9IelsEEXb+NNdGbC/aJxRjVRzGsXUWP6FZSSml9L
# KLrmFkVJ6Sy1/ouHr/ylbUPcpjD6KSjvmw0sXIPeEo1qtNtx71wUWiojKP+BcFfx
# jAeaE9gqUwIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFLkNrbNN9NqfGrInJlUNIETY
# mOL0MB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAAmKTgav6O2Czx0HftcqpyQLLa+aWyR/lHEMVYgkGlIVY+KQ
# TQVKmEqc++GnbWhVgrkp6mmpstXjDNrR1nolN3hnHAz72ylaGpc4KjlWRvs1gbnk
# PUZajuT8dTdYWUmLTts8FZ1zUkvreww6wi3Bs5tSLeA1xbnBV7PoPaE8RPIjFh4K
# qlk3J9CVUl6ofz9U8IHh3Jq9ZdV49vdMObvd4NY3DpGah4xz53FkUvc+A9jGzXK4
# NDSYW4zT9Qim63jGUaANDm/0azxAGmAWLKkGUp0cE5DObwIe6nucs/b4l2DyZdHR
# H4c6wXXwQo167Yxysnv7LIq0kUdU4i5pzBZUGlkwggTsMIID1KADAgECAhMzAAAA
# sBGvCovQO5/dAAEAAACwMA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBMB4XDTEzMDEyNDIyMzMzOVoXDTE0MDQyNDIyMzMzOVowgYMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# HjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAOivXKIgDfgofLwFe3+t7ut2rChTPzrbQH2zjjPmVz+l
# URU0VKXPtIupP6g34S1Q7TUWTu9NetsTdoiwLPBZXKnr4dcpdeQbhSeb8/gtnkE2
# KwtA+747urlcdZMWUkvKM8U3sPPrfqj1QRVcCGUdITfwLLoiCxCxEJ13IoWEfE+5
# G5Cw9aP+i/QMmk6g9ckKIeKq4wE2R/0vgmqBA/WpNdyUV537S9QOgts4jxL+49Z6
# dIhk4WLEJS4qrp0YHw4etsKvJLQOULzeHJNcSaZ5tbbbzvlweygBhLgqKc+/qQUF
# 4eAPcU39rVwjgynrx8VKyOgnhNN+xkMLlQAFsU9lccUCAwEAAaOCAWAwggFcMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRZcaZaM03amAeA/4Qevof5cjJB
# 8jBRBgNVHREESjBIpEYwRDENMAsGA1UECxMETU9QUjEzMDEGA1UEBRMqMzE1OTUr
# NGZhZjBiNzEtYWQzNy00YWEzLWE2NzEtNzZiYzA1MjM0NGFkMB8GA1UdIwQYMBaA
# FMsR6MrStBZYAck3LjMWFrlMmgofMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY0NvZFNpZ1BDQV8w
# OC0zMS0yMDEwLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljQ29kU2lnUENBXzA4LTMx
# LTIwMTAuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQAx124qElczgdWdxuv5OtRETQie
# 7l7falu3ec8CnLx2aJ6QoZwLw3+ijPFNupU5+w3g4Zv0XSQPG42IFTp8263Os8ls
# ujksRX0kEVQmMA0N/0fqAwfl5GZdLHudHakQ+hywdPJPaWueqSSE2u2WoN9zpO9q
# GqxLYp7xfMAUf0jNTbJE+fA8k21C2Oh85hegm2hoCSj5ApfvEQO6Z1Ktwemzc6bS
# Y81K4j7k8079/6HguwITO10g3lU/o66QQDE4dSheBKlGbeb1enlAvR/N6EXVruJd
# PvV1x+ZmY2DM1ZqEh40kMPfvNNBjHbFCZ0oOS786Du+2lTqnOOQlkgimiGaCMIIF
# vDCCA6SgAwIBAgIKYTMmGgAAAAAAMTANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZIm
# iZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQD
# EyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTAwODMx
# MjIxOTMyWhcNMjAwODMxMjIyOTMyWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJyWVwZMGS/HZpgICBC
# mXZTbD4b1m/My/Hqa/6XFhDg3zp0gxq3L6Ay7P/ewkJOI9VyANs1VwqJyq4gSfTw
# aKxNS42lvXlLcZtHB9r9Jd+ddYjPqnNEf9eB2/O98jakyVxF3K+tPeAoaJcap6Vy
# c1bxF5Tk/TWUcqDWdl8ed0WDhTgW0HNbBbpnUo2lsmkv2hkL/pJ0KeJ2L1TdFDBZ
# +NKNYv3LyV9GMVC5JxPkQDDPcikQKCLHN049oDI9kM2hOAaFXE5WgigqBTK3S9dP
# Y+fSLWLxRT3nrAgA9kahntFbjCZT6HqqSvJGzzc8OJ60d1ylF56NyxGPVjzBrAlf
# A9MCAwEAAaOCAV4wggFaMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMsR6MrS
# tBZYAck3LjMWFrlMmgofMAsGA1UdDwQEAwIBhjASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBT90TFO0yaKleGYYDuoMW+mPLzYLTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTAfBgNVHSMEGDAWgBQOrIJgQFYnl+UlE/wq4QpTlVnk
# pDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEE
# SDBGMEQGCCsGAQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY3Jvc29mdFJvb3RDZXJ0LmNydDANBgkqhkiG9w0BAQUFAAOCAgEAWTk+
# fyZGr+tvQLEytWrrDi9uqEn361917Uw7LddDrQv+y+ktMaMjzHxQmIAhXaw9L0y6
# oqhWnONwu7i0+Hm1SXL3PupBf8rhDBdpy6WcIC36C1DEVs0t40rSvHDnqA2iA6VW
# 4LiKS1fylUKc8fPv7uOGHzQ8uFaa8FMjhSqkghyT4pQHHfLiTviMocroE6WRTsgb
# 0o9ylSpxbZsa+BzwU9ZnzCL/XB3Nooy9J7J5Y1ZEolHN+emjWFbdmwJFRC9f9Nqu
# 1IIybvyklRPk62nnqaIsvsgrEA5ljpnb9aL6EiYJZTiU8XofSrvR4Vbo0HiWGFzJ
# NRZf3ZMdSY4tvq00RBzuEBUaAF3dNVshzpjHCe6FDoxPbQ4TTj18KUicctHzbMrB
# 7HCjV5JXfZSNoBtIA1r3z6NnCnSlNu0tLxfI5nI3EvRvsTxngvlSso0zFmUeDord
# EN5k9G/ORtTTF+l5xAS00/ss3x+KnqwK+xMnQK3k+eGpf0a7B2BHZWBATrBC7E7t
# s3Z52Ao0CW0cgDEf4g5U3eWh++VHEK1kmP9QFi58vwUheuKVQSdpw5OPlcmN2Jsh
# rg1cnPCiroZogwxqLbt2awAdlq3yFnv2FoMkuYjPaqhHMS+a3ONxPdcAfmJH0c6I
# ybgY+g5yjcGjPa8CQGr/aZuW4hCoELQ3UAjWwz0wggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBNQwggTQ
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAAAsBGvCovQO5/d
# AAEAAACwMAkGBSsOAwIaBQCgge0wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFEDV
# 9lFci1M/kL7C+DoM6hMncAzDMIGMBgorBgEEAYI3AgEMMX4wfKBigGAARABJAEEA
# RwBfAEMAVABTAF8ARwBlAG4AZQByAGEAbABfAFIAZQBwAG8AcgB0AHMAXwBnAGwA
# bwBiAGEAbABfAFQAUwBfAEcAZQB0AEUAdgBlAG4AdABzAC4AcABzADGhFoAUaHR0
# cDovL21pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAJ9vP1TCVmVoIzB+E
# 0/sfUZUobTPsLkrVdS2eNaB7YIJ1Na9Jiocz5qQW+T+6uCv+mDSdqlRPyoHIuk+w
# /uKmDGGBEGhcXDHg+2a/TgLbRVY/ulwxefv9ooOLQ5XWk4brjMbMQNCfBFGIy8WT
# HB+NdtpqOV7XafnZ6iFP2WFo1H+caOGUPTTdHqVJX38SesLzgtGeXMhLsu+23hXg
# 9aJgc2MZmOvlmgVWbU1p7bWhTc0dpRKqS0a/CHnUQEQVwG6NKXX7bJRyJMVmsykO
# yb137123h8Zibprxz0U0T62ZLzLBCQCEyPKnlHkgktsGW6wEMKxZA4Hu0zqxDpAT
# EvcpSqGCAigwggIkBgkqhkiG9w0BCQYxggIVMIICEQIBATCBjjB3MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0ECEzMAAABMoehNzLR0ezsAAAAAAEwwCQYFKw4DAhoFAKBd
# MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE0MDIy
# NDE3MzgwMlowIwYJKoZIhvcNAQkEMRYEFJ4mO780Npb6BMD5gHLlA8qi9R5GMA0G
# CSqGSIb3DQEBBQUABIIBAIcHqHslVko9aVIVQw3PmS7BFHlo2qArBdcBeq77eLhK
# fr8N/UbsCsUC4OEeQ/7+lLAoo+1bhkSO23TnEaG6vzhLdDLN31XpvsKfQPurF2gF
# d1s4jLbOCgdnAeibqCsFvkjgerCI1p1hYl5C5Qwb0t0kP615SA91f3abEiGp6eYW
# 5YOQMcOK9n/3R6Arqy4ALP9e8NkNdtHp/BA2npFI2I/rOmlEPtUg+Zey5ZXlhS48
# D5ggHXb2TISN+pEqEkzi0W2CbSK/QAJQc09hfrl1Ocow8lliL6qjRBbzbQpx9LO6
# CAlqz2FUFARDE1DCou5BZ0fYOHEh1BIZhFmafQuOczk=
# SIG # End signature block

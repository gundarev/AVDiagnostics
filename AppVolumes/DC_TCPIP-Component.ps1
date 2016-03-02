#************************************************
# DC_TCPIP-Component.ps1
# Version 1.2
# Date: 2009, 2013
# Author: Boyd Benson (bbenson@microsoft.com)
# v1.2: Updated IPv6 Transition Technologies section for SKU checks to clean up exceptions.
# Description: Collects information about TCPIP.
# Called from: Main Networking Diag, DirectAccess Diag and many others.
#*******************************************************


Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
		 # later use return to return the exception message to an object:   return $Script:ExceptionMessage
	}

Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status $ScriptVariable.ID_CTSTCPIPDescription

"[info]:TCPIP-Component:BEGIN" | WriteTo-StdOut


function RunNetSH ([string]$NetSHCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status "netsh $NetSHCommandToExecute"
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"`n`n`n" + "-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $outputFile -append
	"`n" | Out-File -FilePath $outputFile -append
	"`n" | Out-File -FilePath $outputFile -append
	"`n" | Out-File -FilePath $outputFile -append
	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $outputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false -BackgroundExecution
}


function runPS ([string]$runPScmd="")
{
	$runPScmdLength = $runPScmd.Length
	"-" * ($runPScmdLength) | Out-File -FilePath $outputFile -append
	"$runPScmd" | Out-File -FilePath $outputFile -append
	"-" * ($runPScmdLength) | Out-File -FilePath $outputFile -append
	Invoke-Expression $runPScmd | out-file -FilePath $outputFile -append
}


#-----MAIN TCPIP INFO  (W2003+)
$sectionDescription = "TCPIP"

#----------TCPIP Information from Various Tools
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info.TXT")

"`n" + "-" * (50) + "`r`n[Hostname]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
$CommandToExecute = "cmd.exe /c hostname >> $outputFile"
RunCmD -commandToRun $CommandToExecute -CollectFiles $false -BackgroundExecution
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n`n`n" + "-" * (50) + "`r`n[ipconfig /all]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
$CommandToExecute = "cmd.exe /c ipconfig /all >> $outputFile"
RunCmD -commandToRun $CommandToExecute -CollectFiles $false -BackgroundExecution
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n`n`n" + "-" * (50) + "`r`n[route print]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
$CommandToExecute = "cmd.exe /c route print >> $outputFile"
RunCmD -commandToRun $CommandToExecute -CollectFiles $false -BackgroundExecution
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n`n`n" + "-" * (50) + "`r`n[arp -a]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
$CommandToExecute = "cmd.exe /c arp -a >> $outputFile"
RunCmD -commandToRun $CommandToExecute -CollectFiles $false -BackgroundExecution
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n`n`n" + "-" * (50) + "`r`n[netstat -nato]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
$CommandToExecute = "cmd.exe /c netstat -nato >> $outputFile"
RunCmD -commandToRun $CommandToExecute -CollectFiles $false -BackgroundExecution
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n`n`n" + "-" * (50) + "`r`n[netstat -anob]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
$CommandToExecute = "cmd.exe /c netstat -anob >> $outputFile"
RunCmD -commandToRun $CommandToExecute -CollectFiles $false -BackgroundExecution
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n`n`n" + "-" * (50) + "`r`n[netstat -es]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
$CommandToExecute = "cmd.exe /c netstat -es >> $outputFile"
RunCmD -commandToRun $CommandToExecute -CollectFiles $false -BackgroundExecution
CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Info" -SectionDescription $sectionDescription



#----------Registry (General)
"`n" + "-" * (50) + "`r`n[TCPIP Registry Information]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_reg_output.TXT")

$CurrentVersionKeys =	"HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP",
						"HKLM\SYSTEM\CurrentControlSet\services\TCPIP",
						"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6",
						"HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg",
						"HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc"
RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -outputFile $outputFile -fileDescription "TCPIP registry output" -SectionDescription $sectionDescription



#----------TCP OFFLOAD (netsh)
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_OFFLOAD.TXT")

RunNetSH -NetSHCommandToExecute "int tcp show global"
RunNetSH -NetSHCommandToExecute "int ipv4 show offload"

#----------TCP OFFLOAD (netstat)
"-" * (50) + "`r`n[netstat -nato -p tcp]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
$CommandToExecute = "cmd.exe /c netstat -nato -p tcp >> $outputFile"
RunCmD -commandToRun $CommandToExecute -CollectFiles $false -BackgroundExecution

#----------TCP OFFLOAD (registry)
"`n" + "-" * (50) + "`r`n[TCP OFFLOAD (registry)]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
$StartupKeys =	"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
				"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
				"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
				"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$StartupKeysValues =	"EnableTCPChimney",
						"EnableRSS",
						"EnableTCPA",
						"DisableTaskOffload"
RegQueryValue -RegistryKeys $StartupKeys -RegistryValues $StartupKeysValues -outputFile $outputFile -fileDescription "TCP OFFLOAD" -AddFileToReport $false

CollectFiles -filesToCollect $outputFile -fileDescription "TCP OFFLOAD" -SectionDescription $sectionDescription


#----------Copy the Services File
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_ServicesFile.TXT")

$servicesfile = "$ENV:windir\system32\drivers\etc\services"
if (test-path $servicesfile)
{
  Copy-Item -Path $servicesfile -Destination $outputFile
  CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Services File" -SectionDescription $sectionDescription
}
else
{
  "$servicesfile Does not exist" | writeto-stdout
}


# W8/WS2012
if ($OSVersion.Build -gt 9000)
{
	"[info]: TCPIP-Component W8/WS2012+" | WriteTo-StdOut
	$sectionDescription = "TCPIP Network Interfaces"
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info_pscmdlets_net.TXT")

	# NetTCPIP
	runPS "Get-NetIPAddress"
	runPS "Get-NetIPInterface"
	runPS "Get-NetIPConfiguration"
	runPS "Get-NetIPv4Protocol"
	runPS "Get-NetIPv6Protocol"
	runPS "Get-NetOffloadGlobalSetting"
	runPS "Get-NetPrefixPolicy"
	runPS "Get-NetRoute"
	runPS "Get-NetTCPConnection"
	runPS "Get-NetTransportFilter"
	runPS "Get-NetTCPSetting"
	runPS "Get-NetUDPEndpoint"
	runPS "Get-NetUDPSetting"

	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Net Powershell Cmdlets" -SectionDescription $sectionDescription


	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info_pscmdlets_IPv6Transition.TXT")
	#Get role, OSVer, hotfix data.
	$cs =  gwmi -Namespace "root\cimv2" -class win32_computersystem -ComputerName $ComputerName
	$DomainRole = $cs.domainrole
	
	if ($cs.DomainRole -ge 2)	
	{
		runPS "Get-Net6to4Configuration"
		runPS "Get-NetDnsTransitionConfiguration"	# server only
		runPS "Get-NetDnsTransitionMonitoring"		# server only
	}
	runPS "Get-NetIPHttpsConfiguration"
	runPS "Get-NetIPHttpsState"
	runPS "Get-NetIsatapConfiguration"
	
	if ($cs.DomainRole -ge 2)	
	{
		runPS "Get-NetNatTransitionConfiguration"	#server only
		runPS "Get-NetNatTransitionMonitoring"		#server only
	}
	runPS "Get-NetTeredoConfiguration"
	runPS "Get-NetTeredoState"

	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP IPv6 Transition Technology Info" -SectionDescription $sectionDescription	
}



#V/WS2008+
if ($OSVersion.Build -gt 6000)
{
	"[info]: TCPIP-Component WV/WS2008+" | WriteTo-StdOut

	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_netsh_info.TXT")
	

	#----------Netsh for NetIO
	"`n`n`n`n`n" + "=" * (50) + "`r`n[NETSH NETIO]`r`n" + "=" * (50) | Out-File -FilePath $outputFile -Append
	"`n`n"
	"`n" + "-" * (50) + "`r`n[netsh netio show bindingfilters]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
	RunNetSH -NetSHCommandToExecute "netio show bindingfilters"

	#----------Netsh for TCP
	"`n`n`n`n`n" + "=" * (50) + "`r`n[NETSH INT TCP]`r`n" + "=" * (50) | Out-File -FilePath $outputFile -Append
	"`n`n"
	"`n" + "-" * (50) + "`r`n[netsh int tcp show output]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
	RunNetSH -NetSHCommandToExecute "int tcp show global"
	RunNetSH -NetSHCommandToExecute "int tcp show heu"
	RunNetSH -NetSHCommandToExecute "int tcp show chimneyapplications"
	RunNetSH -NetSHCommandToExecute "int tcp show chimneyports"


	#----------Netsh for IPv4
	"`n`n`n`n`n" + "=" * (50) + "`r`n[NETSH INT IPv4]`r`n" + "=" * (50) | Out-File -FilePath $outputFile -Append
	"`n`n"
	"`n" + "-" * (50) + "`r`n[netsh int ipv4 show output]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
	RunNetSH -NetSHCommandToExecute "int show int"
	RunNetSH -NetSHCommandToExecute "int ipv4 show int"
	RunNetSH -NetSHCommandToExecute "int ipv4 show addresses"
	RunNetSH -NetSHCommandToExecute "int ipv4 show ipaddresses"
	RunNetSH -NetSHCommandToExecute "int ipv4 show compartments"
	RunNetSH -NetSHCommandToExecute "int ipv4 show dnsservers"
	RunNetSH -NetSHCommandToExecute "int ipv4 show winsservers"
	RunNetSH -NetSHCommandToExecute "int ipv4 show dynamicportrange tcp"
	RunNetSH -NetSHCommandToExecute "int ipv4 show dynamicportrange udp"
	RunNetSH -NetSHCommandToExecute "int ipv4 show global"
	RunNetSH -NetSHCommandToExecute "int ipv4 show icmpstats"
	RunNetSH -NetSHCommandToExecute "int ipv4 show ipstats"
	RunNetSH -NetSHCommandToExecute "int ipv4 show joins"
	RunNetSH -NetSHCommandToExecute "int ipv4 show offload"
	RunNetSH -NetSHCommandToExecute "int ipv4 show route"
	RunNetSH -NetSHCommandToExecute "int ipv4 show subint"
	RunNetSH -NetSHCommandToExecute "int ipv4 show tcpconnections"
	RunNetSH -NetSHCommandToExecute "int ipv4 show tcpstats"
	RunNetSH -NetSHCommandToExecute "int ipv4 show udpconnections"
	RunNetSH -NetSHCommandToExecute "int ipv4 show udpstats"
	RunNetSH -NetSHCommandToExecute "int ipv4 show destinationcache"
	RunNetSH -NetSHCommandToExecute "int ipv4 show ipnettomedia"
	RunNetSH -NetSHCommandToExecute "int ipv4 show neighbors"


	#----------Netsh for IPv6
	"`n`n`n`n`n" + "=" * (50) + "`r`n[NETSH INT IPv6]`r`n" + "=" * (50) | Out-File -FilePath $outputFile -Append
	"`n`n"
	RunNetSH -NetSHCommandToExecute "int show int"
	RunNetSH -NetSHCommandToExecute "int ipv6 show int"
	RunNetSH -NetSHCommandToExecute "int ipv6 show addresses"
	RunNetSH -NetSHCommandToExecute "int ipv6 show compartments"
	RunNetSH -NetSHCommandToExecute "int ipv6 show destinationcache"
	RunNetSH -NetSHCommandToExecute "int ipv6 show dnsservers"
	RunNetSH -NetSHCommandToExecute "int ipv6 show dynamicportrange tcp"
	RunNetSH -NetSHCommandToExecute "int ipv6 show dynamicportrange udp"
	RunNetSH -NetSHCommandToExecute "int ipv6 show global"
	RunNetSH -NetSHCommandToExecute "int ipv6 show ipstats"
	RunNetSH -NetSHCommandToExecute "int ipv6 show joins"
	RunNetSH -NetSHCommandToExecute "int ipv6 show neighbors"
	RunNetSH -NetSHCommandToExecute "int ipv6 show offload"
	RunNetSH -NetSHCommandToExecute "int ipv6 show potentialrouters"
	RunNetSH -NetSHCommandToExecute "int ipv6 show prefixpolicies"
	if ($OSVersion.Build -gt 9000)
	{
		"-------------------" | Out-File -FilePath $outputFile -Append
		"Get-NetPrefixPolicy" | Out-File -FilePath $outputFile -Append
		"-------------------" | Out-File -FilePath $outputFile -Append
		Get-NetPrefixPolicy | Out-File -FilePath $outputFile -Append
	}
	RunNetSH -NetSHCommandToExecute "int ipv6 show privacy"
	RunNetSH -NetSHCommandToExecute "int ipv6 show route"
	RunNetSH -NetSHCommandToExecute "int ipv6 show siteprefixes"
	RunNetSH -NetSHCommandToExecute "int ipv6 show siteprefixes"
	RunNetSH -NetSHCommandToExecute "int ipv6 show subint"
	RunNetSH -NetSHCommandToExecute "int ipv6 show tcpstats"
	RunNetSH -NetSHCommandToExecute "int ipv6 show teredo"
	RunNetSH -NetSHCommandToExecute "int ipv6 show udpstats"
	RunNetSH -NetSHCommandToExecute "int portproxy show all"
	RunNetSH -NetSHCommandToExecute "int 6to4 show int"
	RunNetSH -NetSHCommandToExecute "int ipv6 show int level=verbose"
	RunNetSH -NetSHCommandToExecute "int 6to4 show relay"
	RunNetSH -NetSHCommandToExecute "int 6to4 show routing"
	RunNetSH -NetSHCommandToExecute "int 6to4 show state"
	RunNetSH -NetSHCommandToExecute "int httpstunnel show interfaces"
	RunNetSH -NetSHCommandToExecute "int httpstunnel show statistics"

	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP netsh output" -SectionDescription $sectionDescription

	
	#----------Iphlpsvc EventLog
	#Iphlpsvc
	$EventLogNames = "Microsoft-Windows-Iphlpsvc/Operational"
	$Prefix = ""
	$Suffix = "_evt_"
	.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

}
# XP/WS2003
else
{
	"[info]: TCPIP-Component XP/WS2003+" | WriteTo-StdOut
	#----------Netsh for IP (XP/W2003)
	"`n`n`n`n`n" + "=" * (50) + "`r`n[NETSH INT IP]`r`n" + "=" * (50) | Out-File -FilePath $outputFile -Append
	"`n`n"
	"`n" + "-" * (50) + "`r`n[netsh int ipv4 show output]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
	RunNetSH -NetSHCommandToExecute "int show int"
	RunNetSH -NetSHCommandToExecute "int ip show int"
	RunNetSH -NetSHCommandToExecute "int ip show address"
	RunNetSH -NetSHCommandToExecute "int ip show config"
	RunNetSH -NetSHCommandToExecute "int ip show dns"
	RunNetSH -NetSHCommandToExecute "int ip show joins"
	RunNetSH -NetSHCommandToExecute "int ip show offload"
	RunNetSH -NetSHCommandToExecute "int ip show wins"

	# If RRAS is running, run the following commands
	if ((Get-Service "remoteaccess").Status -eq 'Running')
	{
		RunNetSH -NetSHCommandToExecute "int ip show icmp"
		RunNetSH -NetSHCommandToExecute "int ip show interface"
		RunNetSH -NetSHCommandToExecute "int ip show ipaddress"
		RunNetSH -NetSHCommandToExecute "int ip show ipnet"
		RunNetSH -NetSHCommandToExecute "int ip show ipstats"
		RunNetSH -NetSHCommandToExecute "int ip show tcpconn"
		RunNetSH -NetSHCommandToExecute "int ip show tcpstats"
		RunNetSH -NetSHCommandToExecute "int ip show udpconn"
		RunNetSH -NetSHCommandToExecute "int ip show udpstats"
	}

}

"[info]:TCPIP-Component:END" | WriteTo-StdOut



# SIG # Begin signature block
# MIIa+gYJKoZIhvcNAQcCoIIa6zCCGucCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+jmf8qjzkRG8qbvYatcp2CtL
# ZPCgghWCMIIEwzCCA6ugAwIBAgITMwAAAEyh6E3MtHR7OwAAAAAATDANBgkqhkiG
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
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBOIwggTe
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAAAsBGvCovQO5/d
# AAEAAACwMAkGBSsOAwIaBQCggfswGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIqi
# XCJeJvZcsIjJlVyFoXV6mhNAMIGaBgorBgEEAYI3AgEMMYGLMIGIoG6AbABEAEkA
# QQBHAF8AQwBUAFMAXwBHAGUAbgBlAHIAYQBsAF8AUgBlAHAAbwByAHQAcwBfAGcA
# bABvAGIAYQBsAF8ARABDAF8AVABDAFAASQBQAC0AQwBvAG0AcABvAG4AZQBuAHQA
# LgBwAHMAMaEWgBRodHRwOi8vbWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASC
# AQCCJQYcJXDYXoos5Q1hs86zLWY8f81MxMJRSJL1z9Ox+L8L2pGZLJGpGwGO9Vid
# ZuFxcuh1t6VAo68J572/h1dVgbEtL5+XwEgzZgJcUEkFcDIFpiepTssRYc4dGR5Z
# d6shVPpi7+ws5UMB7XVFyGtq9B/viBfup4esMg5+UVl2akBwM8ZsoIJSznNn0Td5
# kDdSj5FIAGKLeTQAYpmLXMlbKRFH+kCgUiWvXJOpNxXokraNcu+hb2FrtOtxca+7
# DaAN/N1uEcX4umDaEVymHNWihceNLLaH6iUh34y1v8JcgEYfq6TnrFXswVFJzVwS
# ncGNmUdxt7adkMb7pnkfSJXsoYICKDCCAiQGCSqGSIb3DQEJBjGCAhUwggIRAgEB
# MIGOMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNV
# BAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQQITMwAAAEyh6E3MtHR7OwAAAAAA
# TDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMTQwMjI0MTczNzU4WjAjBgkqhkiG9w0BCQQxFgQUTmTgJAZCiRIs
# xLNY7mbatFZGTWUwDQYJKoZIhvcNAQEFBQAEggEAIBUL/bRfyqFanEJYC70D6kPx
# yv13zuldtF3FC9jEFR/LlaRbEbaTJPKJ59YUvmgYM8PE4WzUJuNNyIsxnRFBgjAZ
# CGkA+SYjcL4seVoWA3/qaLhVfOAMZQuEBbImHt2PZobxY+G5dY5jbjvr0WuTCKoS
# qdKMfv8v0a9rSWef8oTGLpGT2YyjcdVo206YSrdtfAOlmz7BYGAAlVAB+leJ+ePj
# nVVEnCFbPahjO0M3JhyPjnYz5d2wDbjsh5Ipciu5AyizhE/k1CDB7Qfm95L0dUNE
# fP1XcTR1wNlqYEvKSbuhEyInMjkHHZ03Ry3sP1V+Fa0WaTHD3h4LATPy+TQT0A==
# SIG # End signature block

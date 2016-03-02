#************************************************
# DC_Firewall-Component.ps1
# Version 1.0
# Date: 2009
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about the Windows Firewall.
# Called from: Main Networking Diag
#*******************************************************

param(
		[switch]$before,
		[switch]$after
	)

	
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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSFirewall -Status $ScriptVariable.ID_CTSFirewallDescription


function RunNetSH ([string]$NetSHCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSFirewall -Status "netsh $NetSHCommandToExecute"
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"`n`n`n" + "-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $outputFile -append
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


#Handle suffix of file name
	if ($before)
	{
		$suffix = "_BEFORE"
	}
	elseif ($after)
	{
		$suffix = "_AFTER"
	}
	else
	{
		$suffix = ""
	}


#W8/WS2012+
if ($OSVersion.Build -gt 9000)
{	
	"[info]: Firewall-Component W8/WS2012+"  | WriteTo-StdOut 
	$sectionDescription = "Firewall"
	$outputFile= $Computername + "_Firewall_info_pscmdlets" + $suffix + ".TXT"

	runPS "Show-NetIPsecRule -PolicyStore ActiveStore"
	runPS "Get-NetIPsecMainModeSA"
	runPS "Get-NetIPsecQuickModeSA"
	runPS "Get-NetFirewallProfile"
	runPS "Get-NetFirewallRule"
	runPS "Show-NetFirewallRule"

	CollectFiles -filesToCollect $outputFile -fileDescription "Firewall Information PS cmdlets" -SectionDescription $sectionDescription
}


#WV/WS2008+
if ($OSVersion.Build -gt 6000)
{
	"[info]: Firewall-Component WV/WS2008+"  | WriteTo-StdOut 
	#----------Registry
	$outputFile= $Computername + "_Firewall_reg_" + $suffix + ".TXT"
	$CurrentVersionKeys =	"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall",
							"HKLM\SYSTEM\CurrentControlSet\Services\BFE",
							"HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT",
							"HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc",
							"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess"
	$sectionDescription = "Firewall"
	RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -outputFile $outputFile -fileDescription "Firewall Registry Keys" -SectionDescription $sectionDescription

	#----------Netsh
	$outputFile = $ComputerName + "_Firewall_netsh_advfirewall" + $suffix + ".TXT"
	RunNetSH -NetSHCommandToExecute "advfirewall show allprofiles"
	RunNetSH -NetSHCommandToExecute "advfirewall show allprofiles state"
	RunNetSH -NetSHCommandToExecute "advfirewall show currentprofile"
	RunNetSH -NetSHCommandToExecute "advfirewall show domainprofile"
	RunNetSH -NetSHCommandToExecute "advfirewall show global"
	RunNetSH -NetSHCommandToExecute "advfirewall show privateprofile"
	RunNetSH -NetSHCommandToExecute "advfirewall show publicprofile"
	RunNetSH -NetSHCommandToExecute "advfirewall show store"
	CollectFiles -filesToCollect $outputFile -fileDescription "Firewall Advfirewall" -SectionDescription $sectionDescription


	#-----WFAS export
	$filesToCollect = $ComputerName + "_Firewall_netsh_advfirewall-export" + $suffix + ".wfw"
	$commandToRun = "netsh advfirewall export " +  $filesToCollect
	RunCMD -CommandToRun $commandToRun -filesToCollect $filesToCollect -fileDescription "Firewall Export" -sectionDescription $sectionDescription  -BackgroundExecution

	#-----WFAS ConSec rules (all)
	$outputFile = $ComputerName + "_Firewall_netsh_advfirewall-consec-rules" + $suffix + ".TXT"
	# 3/5/2013: Through feedback from Markus Sarcletti, this command has been removed because it is an invalid command:
	#   "advfirewall consec show rule name=all"
	RunNetSH -NetSHCommandToExecute "advfirewall consec show rule all any dynamic verbose"
	RunNetSH -NetSHCommandToExecute "advfirewall consec show rule all any static verbose"
	CollectFiles -filesToCollect $outputFile -fileDescription "Advfirewall ConSec Rules" -SectionDescription $sectionDescription

	#-----WFAS ConSec rules (active)
	# 3/5/2013: Through feedback from Markus Sarcletti, adding active ConSec rules
	$outputFile = $ComputerName + "_Firewall_netsh_advfirewall-consec-rules-active" + $suffix + ".TXT"
	RunNetSH -NetSHCommandToExecute "advfirewall monitor show consec verbose"
	CollectFiles -filesToCollect $outputFile -fileDescription "Advfirewall ConSec Rules" -SectionDescription $sectionDescription

	#-----WFAS Firewall rules (all)
	$outputFile = $ComputerName + "_Firewall_netsh_advfirewall-firewall-rules" + $suffix + ".TXT"
	RunNetSH -NetSHCommandToExecute "advfirewall firewall show rule name=all"
	CollectFiles -filesToCollect $outputFile -fileDescription "Advfirewall Firewall Rules" -SectionDescription $sectionDescription

	#-----WFAS Firewall rules all (active)
	# 3/5/2013: Through feedback from Markus Sarcletti, adding active Firewall Rules
	$outputFile = $ComputerName + "_Firewall_netsh_advfirewall-firewall-rules-active" + $suffix + ".TXT"
	RunNetSH -NetSHCommandToExecute "advfirewall monitor show firewall verbose"
	CollectFiles -filesToCollect $outputFile -fileDescription "Advfirewall Firewall Rules" -SectionDescription $sectionDescription	

	
	
	#-----Netsh WFP	

	#-----Netsh WFP show netevents file=
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-netevents" + $suffix + ".XML"
	$commandToRun = "netsh wfp show netevents file= " +  $outputFile
	RunCMD -CommandToRun $commandToRun -filesToCollect $outputFile -fileDescription "Netsh WFP Show Netevents" -sectionDescription $sectionDescription  -BackgroundExecution
	
	#-----Netsh WFP show BoottimePolicy file=
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-boottimepolicy" + $suffix + ".XML"
	$commandToRun = "netsh wfp show boottimepolicy file= " +  $outputFile
	RunCMD -CommandToRun $commandToRun -filesToCollect $outputFile -fileDescription "Netsh WFP Show BootTimePolicy" -sectionDescription $sectionDescription  -BackgroundExecution

	#-----Netsh wfp show Filters file=
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-filters" + $suffix + ".XML"
	$commandToRun = "netsh wfp show filters file= " +  $outputFile
	RunCMD -CommandToRun $commandToRun -filesToCollect $outputFile -fileDescription "Netsh WFP Show Filters" -sectionDescription $sectionDescription  -BackgroundExecution
	
	#-----Netsh wfp show Options optionsfor=keywords
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-options-optionsforkeywords" + $suffix + ".TXT"
	RunNetSH -NetSHCommandToExecute "wfp show options optionsfor=keywords"
	CollectFiles -filesToCollect $outputFile -fileDescription "Netsh WFP Show Options OptionsForKeywords" -SectionDescription $sectionDescription
	
	#-----Netsh wfp show Options optionsfor=netevents
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-options-optionsfornetevents" + $suffix + ".TXT"
	RunNetSH -NetSHCommandToExecute "wfp show options optionsfor=netevents"
	CollectFiles -filesToCollect $outputFile -fileDescription "Netsh WFP Show Options OptionsForNetEvents" -SectionDescription $sectionDescription
	
	#-----Netsh wfp show Security netevents
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-security-netevents" + $suffix + ".TXT"
	RunNetSH -NetSHCommandToExecute "wfp show security netevents"
	CollectFiles -filesToCollect $outputFile -fileDescription "Netsh WFP Show Security NetEvents" -SectionDescription $sectionDescription
	
	#-----Netsh wfp show State file=
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-state" + $suffix + ".XML"
	$commandToRun = "netsh wfp show state file= " +  $outputFile
	RunCMD -CommandToRun $commandToRun -filesToCollect $outputFile -fileDescription "Netsh WFP Show State" -sectionDescription $sectionDescription  -BackgroundExecution
	
	#-----Netsh wfp show Sysports file=
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-sysports" + $suffix + ".XML"
	$commandToRun = "netsh wfp show sysports file= " +  $outputFile
	RunCMD -CommandToRun $commandToRun -filesToCollect $outputFile -fileDescription "Netsh WFP Show Sysports" -sectionDescription $sectionDescription  -BackgroundExecution


	if ( ($suffix -eq "") -or ($suffix -eq "_AFTER") )
	{
		#----------WFAS Event Logs
		$sectionDescription = "Firewall EventLogs"
		#WFAS CSR
		$EventLogNames = "Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

		#WFAS CSR Verbose
		$EventLogNames = "Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurityVerbose"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

		#WFAS FW
		$EventLogNames = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

		#WFAS FW Verbose
		$EventLogNames = "Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix
	}
	
} 
#Windows Server 2003
else
{
	"[info]: Firewall-Component XP/WS2003"  | WriteTo-StdOut 
	#----------Registry
	$outputFile= $Computername + "_Firewall_reg_.TXT"
	$CurrentVersionKeys =	"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall",
							"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess"
	$sectionDescription = "Firewall"
	RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -outputFile $outputFile -fileDescription "Firewall Registry Keys" -SectionDescription $sectionDescription
	
	#----------Netsh
	$outputFile = $ComputerName + "_Firewall_netsh.TXT"
	RunNetSH -NetSHCommandToExecute "firewall show allowedprogram"
	RunNetSH -NetSHCommandToExecute "firewall show config"
	RunNetSH -NetSHCommandToExecute "firewall show currentprofile"
	RunNetSH -NetSHCommandToExecute "firewall show icmpsetting"
	RunNetSH -NetSHCommandToExecute "firewall show logging"
	RunNetSH -NetSHCommandToExecute "firewall show multicastbroadcastresponse"
	RunNetSH -NetSHCommandToExecute "firewall show notifications"
	RunNetSH -NetSHCommandToExecute "firewall show opmode"
	RunNetSH -NetSHCommandToExecute "firewall show portopening"
	RunNetSH -NetSHCommandToExecute "firewall show service"
	RunNetSH -NetSHCommandToExecute "firewall show state"
	CollectFiles -filesToCollect $outputFile -fileDescription "Firewall" -SectionDescription $sectionDescription
}

# SIG # Begin signature block
# MIIbAQYJKoZIhvcNAQcCoIIa8jCCGu4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6FIY0pXIsanlQ01mIJs79dYH
# LkugghWCMIIEwzCCA6ugAwIBAgITMwAAADPlJ4ajDkoqgAAAAAAAMzANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTMwMzI3MjAwODIz
# WhcNMTQwNjI3MjAwODIzWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkY1MjgtMzc3Ny04QTc2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyt7KGQ8fllaC
# X9hCMtQIbbadwMLtfDirWDOta4FQuIghCl2vly2QWsfDLrJM1GN0WP3fxYlU0AvM
# /ZyEEXmsoyEibTPgrt4lQEWSTg1jCCuLN91PB2rcKs8QWo9XXZ09+hdjAsZwPrsi
# 7Vux9zK65HG8ef/4y+lXP3R75vJ9fFdYL6zSDqjZiNlAHzoiQeIJJgKgzOUlzoxn
# g99G+IVNw9pmHsdzfju0dhempaCgdFWo5WAYQWI4x2VGqwQWZlbq+abLQs9dVGQv
# gfjPOAAPEGvhgy6NPkjsSVZK7Jpp9MsPEPsHNEpibAGNbscghMpc0WOZHo5d7A+l
# Fkiqa94hLwIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFABYGz7txfEGk74xPTa0rAtd
# MvCBMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAAL/44wD6u9+OLm5fJ87UoOk+iM41AO4alm16uBviAP0b1Fq
# lTp1hegc3AfFTp0bqM4kRxQkTzV3sZy8J3uPXU/8BouXl/kpm/dAHVKBjnZIA37y
# mxe3rtlbIpFjOzJfNfvGkTzM7w6ZgD4GkTgTegxMvjPbv+2tQcZ8GyR8E9wK/EuK
# IAUdCYmROQdOIU7ebHxwu6vxII74mHhg3IuUz2W+lpAPoJyE7Vy1fEGgYS29Q2dl
# GiqC1KeKWfcy46PnxY2yIruSKNiwjFOPaEdHodgBsPFhFcQXoS3jOmxPb6897t4p
# sETLw5JnugDOD44R79ECgjFJlJidUUh4rR3WQLYwggTsMIID1KADAgECAhMzAAAA
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
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBOkwggTl
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAAAsBGvCovQO5/d
# AAEAAACwMAkGBSsOAwIaBQCgggEBMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTX
# VOG4oy8L/XZwkp51hOSasW/ZejCBoAYKKwYBBAGCNwIBDDGBkTCBjqB0gHIARABJ
# AEEARwBfAEMAVABTAF8ARwBlAG4AZQByAGEAbABfAFIAZQBwAG8AcgB0AHMAXwBn
# AGwAbwBiAGEAbABfAEQAQwBfAEYAaQByAGUAdwBhAGwAbAAtAEMAbwBtAHAAbwBu
# AGUAbgB0AC4AcABzADGhFoAUaHR0cDovL21pY3Jvc29mdC5jb20wDQYJKoZIhvcN
# AQEBBQAEggEAPg9DmfSxVnCGDt8DfrxAsJZyfmhsLgyT3KMS9Tz6Bhd0OfRW6wF/
# ZZ5tf68khPqZRpZGO3lVcTnI+LUy80mxkpV0hWyQ0eKiTsrIyjbFqlELY087m4DG
# LFVeRE8BV6G1BKxYqWE5ePA/q8ZGKYgvDhDBkHkOfhZQorqHQEzhfKz8x0+7uN5R
# ZDC/fpUaP3+vd7K7PIiGhLCOHtt2JTMEII9chqJZ5TiE+om4171b9RJ8bUFqzbKA
# X8HtwuwPaNuKRY3/+SuYgp4oIdD/kkScp4jQ77fAkuNwPiTOj++DRWMBt3qg/OPV
# RAu4/1jJO1mdc9ICDLbKcdUleImeJbuXeaGCAigwggIkBgkqhkiG9w0BCQYxggIV
# MIICEQIBATCBjjB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0ECEzMAAAAz5SeGow5K
# KoAAAAAAADMwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEw
# HAYJKoZIhvcNAQkFMQ8XDTE0MDIyNDE3Mzc1NlowIwYJKoZIhvcNAQkEMRYEFK+J
# HAPgERv3MZ76EqSmyPZu9THKMA0GCSqGSIb3DQEBBQUABIIBAJ6fPHt8xt0TPDxa
# 4qDSFetC6JJMlKkeFF/dsEug6a2XoC6HBlYDhitpEn38g3dt1/vfXAfyXy1r3kJk
# /WALoJER4YW1TZaQrovHYOAsrzRIsdDLK7JTRB+l2XrfUhhgronleTdDRspo0DMx
# VoE7Oi4rYN/v2PzM3YPxdzYUeWablAoapgV6BwxMwui8FiE11mB0bNoQz3P3Zrm3
# 7J7s6CNJFYhtmCnVRz2hmWpepvK9SElX8WHqm3hNesayW1HdB1n1Io8hECnya0xn
# heT4mtq/P9At6sPfKHViJZunwMJycfTAey9rrhzjl1x8RSuLrtOrm0aW3J3BohQ+
# ySFc3c8=
# SIG # End signature block

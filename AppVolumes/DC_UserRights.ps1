#************************************************
# DC_UserRights.ps1
# Version 1.1
# Date: 11-29-2011
# Author: David Fisher
# Updated: Andret (removed dependency from batch file)
# Description: This script obtains User Rights (privileges) 
#              via the userrights.exe tool, saving output to a
#              file named $ComputerName_userrights.txt
#************************************************
#Last Updated Date: 05-23-2012
#Updated By: Alec Yao     v-alyao@microsoft.com
#Description: Add two arguments for the script, called $Prefix and $Suffix. It will allow to custermize the filename
#************************************************
Param($Prefix = '', $Suffix = '')

if ($OSArchitecture -eq 'ARM')
{
	'Skipping running {showpriv.exe} since it is not supported in ' + $OSArchitecture + ' architecture.' | WriteTo-StdOut
	return
}

Import-LocalizedData -BindingVariable InboxCommandStrings
	
Write-DiagProgress -Activity $InboxCommandStrings.ID_UserRightsActivity -Status $InboxCommandStrings.ID_UserRightsStatus

$fileDescription = "UserRights Output"
$sectionDescription = "User Rights Assignments"

$OutputFileName = Join-Path $Pwd.Path ($ComputerName + "_" + $Prefix + "UserRights" + $Suffix + ".txt")

"Defined User Rights" >$OutputFileName
"===================" >> $OutputFileName
"" >> $OutputFileName

"Access Credential Manager as a trusted caller" >> $OutputFileName
"=====================================" >> $OutputFileName
.\showpriv.exe SeTakeOwnershipPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Access this computer from the network" >> $OutputFileName
"=====================================" >> $OutputFileName
.\showpriv.exe SeNetworkLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Act as part of the operating system" >> $OutputFileName
"===================================" >> $OutputFileName
.\showpriv.exe SeTcbPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Add workstations to domain" >> $OutputFileName
"==========================" >> $OutputFileName
.\showpriv.exe SeMachineAccountPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Adjust memory quotas for a process" >> $OutputFileName
"==================================" >> $OutputFileName
.\showpriv.exe SeIncreaseQuotaPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Allow log on Locally" >> $OutputFileName
"=============" >> $OutputFileName
.\showpriv.exe SeInteractiveLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Allow logon through Remote Desktop Services" >> $OutputFileName
"=====================================" >> $OutputFileName
.\showpriv.exe SeRemoteInteractiveLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Back up files and directories" >> $OutputFileName
"=============================" >> $OutputFileName
.\showpriv.exe SeBackupPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Bypass Traverse Checking" >> $OutputFileName
"========================" >> $OutputFileName
.\showpriv.exe SeChangeNotifyPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Change the system time" >> $OutputFileName
"======================" >> $OutputFileName
.\showpriv.exe SeSystemTimePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Change the time zone" >> $OutputFileName
"====================" >> $OutputFileName
.\showpriv.exe SeTimeZonePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Create a pagefile" >> $OutputFileName
"=================" >> $OutputFileName
.\showpriv.exe SeCreatePagefilePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Create a token object" >> $OutputFileName
"=====================" >> $OutputFileName
.\showpriv.exe SeCreateTokenPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Create global objects" >> $OutputFileName
"=====================" >> $OutputFileName
.\showpriv.exe SeCreateGlobalPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Create permanent shared objects" >> $OutputFileName
"===============================" >> $OutputFileName
.\showpriv.exe SeCreatePermanentPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Create Symbolic links" >> $OutputFileName
"=====================" >> $OutputFileName
.\showpriv.exe SeCreateSymbolicLinkPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Debug programs" >> $OutputFileName
"==============" >> $OutputFileName
.\showpriv.exe SeDebugPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Deny access to this computer from the network" >> $OutputFileName
"=============================================" >> $OutputFileName
.\showpriv.exe SeDenyNetworkLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Deny log on as a batch job" >> $OutputFileName
"==========================" >> $OutputFileName
.\showpriv.exe SeDenyBatchLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Deny log on as a service" >> $OutputFileName
"========================" >> $OutputFileName
.\showpriv.exe SeDenyServiceLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Deny log on Locally" >> $OutputFileName
"==================" >> $OutputFileName
.\showpriv.exe SeDenyInteractiveLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Deny log on through Remote Desktop Services" >> $OutputFileName
"====================================" >> $OutputFileName
.\showpriv.exe SeDenyRemoteInteractiveLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Enable computer and user accounts to be trusted for delegation" >> $OutputFileName
"==============================================================" >> $OutputFileName
.\showpriv.exe SeEnableDelegationPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Force shutdown from a remote system" >> $OutputFileName
"===================================" >> $OutputFileName
.\showpriv.exe SeRemoteShutdownPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Generate security audits" >> $OutputFileName
"========================" >> $OutputFileName
.\showpriv.exe SeAuditPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Impersonate a client after authentication" >> $OutputFileName
"=========================================" >> $OutputFileName
.\showpriv.exe SeImpersonatePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Increase a process working set" >> $OutputFileName
"==============================" >> $OutputFileName
.\showpriv.exe SeIncreaseWorkingSetPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Increase scheduling priority" >> $OutputFileName
"============================" >> $OutputFileName
.\showpriv.exe SeIncreaseBasePriorityPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Load and unload device drivers" >> $OutputFileName
"==============================" >> $OutputFileName
.\showpriv.exe SeLoadDriverPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Lock pages in memory" >> $OutputFileName
"====================" >> $OutputFileName
.\showpriv.exe SeLockMemoryPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Log on as a batch job" >> $OutputFileName
"=====================" >> $OutputFileName
.\showpriv.exe SeBatchLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Log on as a service" >> $OutputFileName
"===================" >> $OutputFileName
.\showpriv.exe SeServiceLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Manage auditing and security log" >> $OutputFileName
"================================" >> $OutputFileName
.\showpriv.exe SeSecurityPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Modify an object label" >> $OutputFileName
"==================================" >> $OutputFileName
.\showpriv.exe SeRelabelPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Modify firmware environment values" >> $OutputFileName
"==================================" >> $OutputFileName
.\showpriv.exe SeSystemEnvironmentPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Perform volume maintenance tasks" >> $OutputFileName
"================================" >> $OutputFileName
.\showpriv.exe SeManageVolumePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Profile single process" >> $OutputFileName
"======================" >> $OutputFileName
.\showpriv.exe SeProfileSingleProcessPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Profile system performance" >> $OutputFileName
"==========================" >> $OutputFileName
.\showpriv.exe SeSystemProfilePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Remove computer from docking station" >> $OutputFileName
"====================================" >> $OutputFileName
.\showpriv.exe SeUndockPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Replace a process-level token" >> $OutputFileName
"=============================" >> $OutputFileName
.\showpriv.exe SeAssignPrimaryTokenPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Restore files and directories" >> $OutputFileName
"=============================" >> $OutputFileName
.\showpriv.exe SeRestorePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Shut down the system" >> $OutputFileName
"====================" >> $OutputFileName
.\showpriv.exe SeShutdownPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Synchronize directory service data" >> $OutputFileName
"==================================" >> $OutputFileName
.\showpriv.exe SeSynchAgentPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Take ownership of files or other objects" >> $OutputFileName
"========================================" >> $OutputFileName
.\showpriv.exe SeTakeOwnershipPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Read unsolicited input from a terminal device" >> $OutputFileName
"=============================================" >> $OutputFileName
.\showpriv.exe SeUnsolicitedInputPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

CollectFiles -sectionDescription $sectionDescription -filesToCollect $OutputFileName -fileDescription $fileDescription

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}

# SIG # Begin signature block
# MIIa7wYJKoZIhvcNAQcCoIIa4DCCGtwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOKzQlSeO+mQT30vn/yBbNQc/
# /MKgghWCMIIEwzCCA6ugAwIBAgITMwAAAEyh6E3MtHR7OwAAAAAATDANBgkqhkiG
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
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBNcwggTT
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAAAsBGvCovQO5/d
# AAEAAACwMAkGBSsOAwIaBQCggfAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFLZ
# zNDlvpxT7gPErvmUWDBmpePQMIGPBgorBgEEAYI3AgEMMYGAMH6gZIBiAEQASQBB
# AEcAXwBDAFQAUwBfAEcAZQBuAGUAcgBhAGwAXwBSAGUAcABvAHIAdABzAF8AZwBs
# AG8AYgBhAGwAXwBEAEMAXwBVAHMAZQByAFIAaQBnAGgAdABzAC4AcABzADGhFoAU
# aHR0cDovL21pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAPDWwXVUU8QKu
# t+vL5sZlSxagMV73WJRE7oDa5mo1i2xwhPWxy6mwhl8PSkjnyuqdujlHCn8BLOw+
# JbO8Hz2fLNFlZt9BQQjeoymFfrMIAI3MKYTwTPYtWLqgrj+VR2saL+Wg18+wm98s
# FORtNAtLsQ3raG2/y0SN1CIRdXOQEvCN58boL2PfqHvAGxNFbXTrhydVEYxREVtG
# ts1kO34hTaKRLR4bHcjtZ8Zms9QL1oQxsuX1LrwZ8lnqjr6yOdK8V5OqLAh6WfoS
# 7t4WCVCQ/z7JXZAKIHC1zQArK0X3QZqWZuDOTidyHiZHMmUzhNfZVz5LG/CecLBO
# Xk7lM60RuKGCAigwggIkBgkqhkiG9w0BCQYxggIVMIICEQIBATCBjjB3MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEwHwYDVQQDExhNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0ECEzMAAABMoehNzLR0ezsAAAAAAEwwCQYFKw4DAhoF
# AKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE0
# MDIyNDE3Mzc1OFowIwYJKoZIhvcNAQkEMRYEFNJC4W5pCgzTdrBv7Cm/xL/AbfKI
# MA0GCSqGSIb3DQEBBQUABIIBACCh7bRU01YCi8KuPOLgzVgLQcuFMSOfQ/9ePKB8
# MEF44iXrcfs84jvnOUB+0njFuZrtOmnNU8PB8GHFed3/woxD4Ro3AIK4DLZ33TxV
# AVs1ebXmatZgI5qKn8Mq9bkKhoYU2Jlgc4kLe5q8GXTPR7MTHk/LH2NuqxwfZtqm
# SQ0HU42vNxJZcPEgK8EXSihp6o2HFh4IdN1i1BOrdpPqSOM9SCejYs6BdsiY8bVg
# IiW03caRS6uSoz8ly9bZhFOikXggut4KRrNrZdnF+Mw9HSgtvymspJP+9fUKswG4
# cfztnaa+HDOQl6UwbJNvx4I5rssGqcbbO11IVfi/1nPdDY4=
# SIG # End signature block

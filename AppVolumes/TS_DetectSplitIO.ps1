#************************************************
# TS_SplitIO.ps1
# Version 1.0.1
# Date: 2/21/2013
# Author: Tspring
# Description:  [Idea ID 7345] [Windows] Perfmon - Split IO Counter
# Rule number:  7345
# Rule URL:  http://sharepoint/sites/rules/Rule Submissions/Forms/DispForm.aspx?ID=7345
#Split IO/sec
# Shows the rate, in incidents per second, at which input/output (I/O) requests to the disk were split into multiple requests. 
# A split I/O might result from requesting data in a size that is too large to fit into a single I/O, or from a fragmented disk subsystem.
#************************************************

Import-LocalizedData -BindingVariable ScriptStrings
Write-DiagProgress -Activity $ScriptStrings.ID_SplitIO_Activity -Status $ScriptStrings.ID_SplitIO_Status

$RootCauseDetected = $false
$RootCauseName = "RC_SplitIO"
$InformationCollected = new-object PSObject

# ***************************
# Data Gathering
# ***************************
function QueryTotalSplitIO
	{
	 $ReturnedObject = New-Object PSObject
	 $PhysDisk = New-Object System.Diagnostics.PerformanceCounter("PhysicalDisk", "Split IO/Sec", "_Total")
	 $LogDisk = New-Object System.Diagnostics.PerformanceCounter("LogicalDisk", "Split IO/Sec", "_Total")
	 $CookedPhysDisk = $PhysDisk.NextValue()
	 $CookedLogDisk = $LogDisk.NextValue()
	 add-member -inputobject $ReturnedObject  -membertype noteproperty -name "PhysicalDisk" -value $CookedPhysDisk
	 add-member -inputobject $ReturnedObject  -membertype noteproperty -name "LogicalDisk" -value $CookedLogDisk
	 return $ReturnedObject
	}
	

Function CollectedData
	{
	 $Sample1 = QueryTotalSplitIO
	 Start-Sleep 3
	 $Sample2 = QueryTotalSplitIO
	 Start-Sleep 3
	 $Sample3 = QueryTotalSplitIO
	 Start-Sleep 3
	 $Sample4 = QueryTotalSplitIO
	 Start-Sleep 3
	 $Sample5 = QueryTotalSplitIO
	 if ((($Sample1."PhysicalDisk" -ge 5) -or ($Sample1."LogicalDisk" -ge 5)) -or (($Sample2."PhysicalDisk" -ge 5) -or ($Sample2."LogicalDisk" -ge 5)) -or `
		(($Sample3."PhysicalDisk" -ge 5) -or ($Sample3."LogicalDisk" -ge 5)) -or (($Sample4."PhysicalDisk" -ge 5) -or ($Sample4."LogicalDisk" -ge 5)) -or `
		(($Sample5."PhysicalDisk" -ge 5) -or ($Sample5."LogicalDisk" -ge 5)))
		{
		 #Problem detected.
		 return $true
		}
	}



# **************
# Detection Logic
# **************

#Check to see if rule is applicable to this computer
if (CollectedData -eq $true)
	{
	 $RootCauseDetected = $true	
	 $SplitIOResults = New-Object PSObject
	 
	$SplitIODiskFlags = @{}

	 #Gather all logical and physical drives and then query each specific disk or logical
	 #disk to see which one(s) have the problem.
	 $Phys = New-Object System.Diagnostics.PerformanceCounterCategory("PhysicalDisk")
	 $PhysInstances = $Phys.GetInstanceNames()
	 $Log = New-Object System.Diagnostics.PerformanceCounterCategory("LogicalDisk")
	 $LogInstances = $Log.GetInstanceNames()
	 ForEach ($PhysInstance in $PhysInstances)
	 	{
		 WriteTo-StdOut "Within PhysInstance Foreach"
		 #Query for that drive letters statistic and place it into a PSObject.
		 $PhysSplitIOValue = New-Object System.Diagnostics.PerformanceCounter("PhysicalDisk", "Split IO/Sec", $PhysInstance)
		 $PhysSplitIOValue = $PhysSplitIOValue.NextValue()
		 #place Split IO into array for use in identifying correct key pair in hash table.
		 $SplitIOValuesArray = $SplitIOValuesArray + $PhysSplitIOValue
		 if (($PhysSplitIOValue -ge 5) -and ($PhysInstance -notmatch "_Total"))
			{
			 $PhysInstanceName = $PhysInstance
			 WriteTo-StdOut "PhysInstance is $PhysInstance"
			 $SplitIODiskFlags.Add($PhysInstance, "Physical Disk")
			 WriteTo-StdOut "SplitIODiskFlags is $SplitIODiskFlags"
			 add-member -inputobject $SplitIOResults  -membertype noteproperty -name $PhysInstanceName -value $PhysSplitIOValue
			}
		 $Drive = $null
		}
	 ForEach ($LogInstance in $LogInstances) 
	 	{
		 WriteTo-StdOut "Within LogInstance Foreach"
		 #Query for that drive letters statistic and place it into a PSObject.
		 $LogSplitIOValue = New-Object System.Diagnostics.PerformanceCounter("LogicalDisk", "Split IO/Sec", $LogInstance)
		 $LogSplitIOValue = $LogSplitIOValue.NextValue()
		 #place Split IO into array for use in identifying correct key pair in hash table.
		 $SplitIOValuesArray = $SplitIOValuesArray + $LogSplitIOValue
		 if (($LogSplitIOValue -ge 5) -and ($LogInstance -notmatch "_Total"))
			{
			 $LogInstanceName = $LogInstance
			 WriteTo-StdOut "LogInstance is $LogInstance"
			 $SplitIODiskFlags.Add($LogInstance, "Logical Disk")
			 WriteTo-StdOut "SplitIODiskFlags is $SplitIODiskFlags"
			 add-member -inputobject $SplitIOResults  -membertype noteproperty -name $LogInstanceName -value $LogSplitIOValue
			}
		 $Drive = $null
		}
		
	$SortedSplitIOArray =  $SplitIOValuesArray | Sort-Object -Descending

		$SplitIOResults | Get-Member -MemberType Properties |             
    		ForEach {$hash=@{}} {            
       		 $hash.($_.Name) = $SplitIOResults.($_.Name)
    			} 
		$SortedHash = $hash.GetEnumerator() | Sort-Object Value -Descending
		$SortedHash.GetEnumerator() | Foreach-Object {    
    		if($_.Value -eq $SortedSplitIOArray[0])
				{
					$WorstSplitIO = @{$_.Key = $_.Value}
					$Key = $_.Key
				}
			}
    WriteTo-StdOut "SplitIODiskFlags is $SplitIODiskFlags"


	$WorstSplitIO
	$WorstSplitIO.GetEnumerator() | Foreach-Object {    
			$BadKeyname = $_.Key
			$BadValue =  $_.Value
		}


    WriteTo-StdOut  "BadKeyname is $BadKeyname"
	WriteTo-StdOut  "BadValue is $BadValue"

	#Determine whether the disk was a logical one or physical one for reporting to engineer.
	$SplitIODiskFlags.GetEnumerator() | Foreach-Object {    
    		
			$Name = $_.Name
			$Value = $_.Value
			WriteTo-StdOut "Name is $Name"
			if ($Name -eq $Key)
				{ 
				 WriteTo-StdOut "Name is $_.Name and Key is $_.Key"
				 $PhysorLogFlag = $Value
				}
			}

	#Export results to a CSV for engineer review.
	$ExportCSV = Join-Path $Pwd.Path ($ComputerName + "_SplitIODiskInfo.csv")
	$SortedHash.GetEnumerator() | Export-Csv -Path $ExportCSV -Force
	
	$Date = Get-Date
	add-member -inputobject $InformationCollected  -membertype noteproperty -name "Date" -value $Date
	add-member -inputobject $InformationCollected  -membertype noteproperty -name "Problematic Volume" -value $BadKeyname
	add-member -inputobject $InformationCollected  -membertype noteproperty -name "Physical or Logical Disk" -value $Value
	add-member -inputobject $InformationCollected  -membertype noteproperty -name "Highest Split IO Value" -value $BadValue
	Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $InformationCollected -Verbosity "Error" -Visibility 3 -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_SplitIO_ST -SDPFileReference $ExportCSV

}


# *********************
# Root Cause processing
# *********************

if ($RootCauseDetected)
	{
	 # Red/ Yellow Light
	 Update-DiagRootCause -id $RootCauseName -Detected $true
	 CollectFiles -filesToCollect $ExportCSV -fileDescription "CSV output of logical and physical disk split IO performance counters." -sectionDescription "Split IO Disk Info" -renameOutput $false
	}
	else
	{
	 # Green Light
	 Update-DiagRootCause -id $RootCauseName -Detected $false
	}
	
# SIG # Begin signature block
# MIIa9gYJKoZIhvcNAQcCoIIa5zCCGuMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULTdjlLMiTRBeZajXiVFGsBY4
# daOgghWCMIIEwzCCA6ugAwIBAgITMwAAADQkMUDJoMF5jQAAAAAANDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTMwMzI3MjAwODI1
# WhcNMTQwNjI3MjAwODI1WjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkI4RUMtMzBBNC03MTQ0MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5RoHrQqWLNS2
# NGTLNCDyvARYgou1CdxS1HCf4lws5/VqpPW2LrGBhlkB7ElsKQQe9TiLVxj1wDIN
# 7TSQ7MZF5buKCiWq76F7h9jxcGdKzWrc5q8FkT3tBXDrQc+rsSVmu6uitxj5eBN4
# dc2LM1x97WfE7QP9KKxYYMF7vYCNM5NhYgixj1ESZY9BfsTVJektZkHTQzT6l4H4
# /Ieh7TlSH/jpPv9egMkGNgfb27lqxzfPhrUaS0rUJfLHyI2vYWeK2lMv80wegyxj
# yqAQUhG6gVhzQoTjNLLu6pO+TILQfZYLT38vzxBdGkVmqwLxXyQARsHBVdKDckIi
# hjqkvpNQAQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFF9LQt4MuTig1GY2jVb7dFlJ
# ZoErMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAA9CUKDVHq0XPx8Kpis3imdYLbEwTzvvwldp7GXTTMVQcvJz
# JfbkhALFdRxxWEOr8cmqjt/Kb1g8iecvzXo17GbX1V66jp9XhpQQoOtRN61X9id7
# I08Z2OBtdgQlMGESraWOoya2SOVT8kVOxbiJJxCdqePPI+l5bK6TaDoa8xPEFLZ6
# Op5B2plWntDT4BaWkHJMrwH3JAb7GSuYslXMep/okjprMXuA8w6eV4u35gW2OSWa
# l4IpNos4rq6LGqzu5+wuv0supQc1gfMTIOq0SpOev5yDVn+tFS9cKXELlGc4/DC/
# Zef1Od7qIu2HjKuyO7UBwq3g/I4lFQwivp8M7R0wggTsMIID1KADAgECAhMzAAAA
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
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBN4wggTa
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAAAsBGvCovQO5/d
# AAEAAACwMAkGBSsOAwIaBQCggfcwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFEh7
# iyiHNROCVZyPcX5Y2PQBV5xyMIGWBgorBgEEAYI3AgEMMYGHMIGEoGqAaABEAEkA
# QQBHAF8AQwBUAFMAXwBHAGUAbgBlAHIAYQBsAF8AUgBlAHAAbwByAHQAcwBfAGcA
# bABvAGIAYQBsAF8AVABTAF8ARABlAHQAZQBjAHQAUwBwAGwAaQB0AEkATwAuAHAA
# cwAxoRaAFGh0dHA6Ly9taWNyb3NvZnQuY29tMA0GCSqGSIb3DQEBAQUABIIBAN28
# hGkprz6pfZl21xTgzWxRkuUWJ5qPINSR+uJhC5cZXYRGSu4VShaVOTWY2kqBEgZz
# ZCtqgl07qtyJEfPwJV7DUz0sTu8miNwfSuROaHR20YBlIp3qLo6ICkzz7yFX3B/7
# +DUyHGYvuL+e8yaW385o1rGxWIcuwFGPb/nCzsQByi5NOnOI+Jx03D3K/9iB7nuk
# MjhieDek6lfP7j7WMDbaso0OaePe5eslwz5BxtWelQmPn38SuEusCBrOkdHqtsix
# HBLZCCJkA6UiGauVe+JbqfZgPMnTljsiN7v0JVfyIYGJNXNUJPYiEOSDGuDm3gFz
# QSNntFA54kRtLMR/xMqhggIoMIICJAYJKoZIhvcNAQkGMYICFTCCAhECAQEwgY4w
# dzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMY
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBAhMzAAAANCQxQMmgwXmNAAAAAAA0MAkG
# BSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0xNDAyMjQxNzM4MDFaMCMGCSqGSIb3DQEJBDEWBBQKM+j2RDNWlJ0ZBB4e
# m9EF3T8t1TANBgkqhkiG9w0BAQUFAASCAQAzvIl6ysaXBTFLYe4SjrJ0aleoUk2D
# dW07j5MqlJf42k7CmFQyLfUIbBQEgJ70RjMunmh0WCIxF6cDm4g4+XHMyiSC+X2g
# N+neW6qfWZeEFm/YM4xVpSEucfoohoTz/RyvWQIASLN6KsYA/4ueN+lXmDbvREWj
# B3B14XXZmRiWh5B3uENo+5wXXm0v+/aBxsRcyLVNAT4MuY7XubypvzRjzwsDXMx/
# tvITdoWHIqVWQZ7F982EnauS7h8zbil4JUpKxsz+c24xwczmecAhZU5ezROT7D4/
# r+BfbDphJayI69DsiVe4CFoB2umxrTjHeVejS1QdHuFDNa1Nr2rOGzRJ
# SIG # End signature block

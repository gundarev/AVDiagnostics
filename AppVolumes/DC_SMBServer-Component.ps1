#************************************************
# DC_SMBServer-Component.ps1
# Version 1.0
# Date: 2009
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about SMB Server.
# Called from: Main Networking Diag, WebClient Interactive Diag, and others.
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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSSMBServer -Status $ScriptVariable.ID_CTSSMBServerDescription

function RunNet ([string]$NetCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSSMBServer -Status "net $NetCommandToExecute"
	
	$NetCommandToExecuteLength = $NetCommandToExecute.Length + 6
	"`n`n`n" + "=" * ($NetCommandToExecuteLength) + "`r`n" + "net $NetCommandToExecute" + "`r`n" + "=" * ($NetCommandToExecuteLength) | Out-File -FilePath $OutputFile -append
	$CommandToExecute = "cmd.exe /c net.exe " + $NetCommandToExecute + " >> $OutputFile "
	
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false -BackgroundExecution
	"`n" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
}


#----------Check if SMB Server (File and Printer Sharing) is installed, and then run the script
$SvcKey = "HKLM:\SYSTEM\CurrentControlSet\services\LanManServer"
if (Test-Path $SvcKey) 
{
	#----------Registry
	$OutputFile= $Computername + "_SmbServer_reg_output.TXT"
	$sectionDescription = "SMB Server"
	$CurrentVersionKeys =	"HKLM\SYSTEM\CurrentControlSet\services\LanManServer",
							"HKLM\SYSTEM\CurrentControlSet\services\SRV",
							"HKLM\SYSTEM\CurrentControlSet\services\SRV2",
							"HKLM\SYSTEM\CurrentControlSet\services\SRVNET"

	RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "SMB Server registry output" -SectionDescription $sectionDescription
}

#----------Net Commands

$OutputFile= $Computername + "_SmbServer_info.txt"
"`n" | Out-File -FilePath $OutputFile -append
RunNet "accounts"

## 04/03/12: BBenson - added check to verify that the Server service is running.

if ((Get-Service "lanmanserver").Status -eq 'Running')
{
	RunNet "config server"
	RunNet "session"
	RunNet "files"
	RunNet "share"
	RunNet "statistics server"
	CollectFiles -filesToCollect $OutputFile -fileDescription "SMB Server Information from tools like net.exe" -SectionDescription $sectionDescription
}
else
{
	"[info] Server Service is not Started." | WriteTo-StdOut
	CollectFiles -filesToCollect $OutputFile -fileDescription "SMB Server Information from tools like net.exe" -SectionDescription $sectionDescription
}

#************************************************
# DC_RPC-Component.ps1
# Version 1.0
# Date: 2009
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about RPC.
# Called from: Main Networking Diag
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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSRPC -Status $ScriptVariable.ID_CTSRPCDescription


Function RunNetSH ([string]$NetSHCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSRPC -Status "netsh $NetSHCommandToExecute"

	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"`n`n`n" + "-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $OutputFile -append

	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false -BackgroundExecution
}


#----------Netsh
$OutputFile = $ComputerName + "_RPC_netsh_output.TXT"
$sectionDescription = "RPC"

RunNetSH -NetSHCommandToExecute "rpc show int"
RunNetSH -NetSHCommandToExecute "rpc show settings"
RunNetSH -NetSHCommandToExecute "rpc filter show filter"
CollectFiles -filesToCollect $OutputFile -fileDescription "RPC netsh output" -SectionDescription $sectionDescription


#----------Registry
$OutputFile= $Computername + "_RPC_reg_output.TXT"
$CurrentVersionKeys = "HKLM\Software\Microsoft\Rpc", 
					"HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper",
					"HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator",
					"HKLM\SYSTEM\CurrentControlSet\Services\RpcSs"
RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "RPC registry output" -SectionDescription $sectionDescription


#************************************************
# DC_IPsec-Component.ps1
# Version 1.0
# Date: 2009
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about the IPsec component.
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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSIPsec -Status $ScriptVariable.ID_CTSIPsecDescription

function RunNetSH ([string]$NetSHCommandToExecute="")
{
	
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSIPsec -Status "netsh $NetSHCommandToExecute"
	
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"`n`n`n" + "-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $OutputFile -append

	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFile "
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



if ($OSVersion.Build -gt 9000)
{
	$sectionDescription = "IPsec"
	$outputFile = join-path $pwd.path ($ComputerName + "_IPsec_info_pscmdlets.TXT")
	
	runPS "Get-NetIPsecMainModeCryptoSet"
	runPS "Get-NetIPsecMainModeRule"
	runPS "Get-NetIPsecMainModeSA"
	runPS "Get-NetIPsecPhase1AuthSet"
	runPS "Get-NetIPsecPhase2AuthSet"
	runPS "Get-NetIPsecQuickModeCryptoSet"
	runPS "Get-NetIPsecQuickModeSA"
	
	CollectFiles -sectionDescription $sectionDescription -fileDescription "IPsec Powershell Cmdlets" -filesToCollect $outputFile 
}



#----------Registry
$OutputFile= $Computername + "_IPsec_reg_.TXT"
$CurrentVersionKeys =	"HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec",
						"HKLM\SYSTEM\CurrentControlSet\Services\IPsec",
						"HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT",
						"HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent"

$sectionDescription = "IPsec"
RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "IPsec Registry keys" -SectionDescription $sectionDescription


#----------Netsh
$OutputFile = $ComputerName + "_IPsec_netsh_dynamic.TXT"
RunNetSH -NetSHCommandToExecute "ipsec dynamic show all"
CollectFiles -filesToCollect $OutputFile -fileDescription "IPsec netsh dynamic show all" -SectionDescription $sectionDescription

$OutputFile = $ComputerName + "_IPsec_netsh_static.TXT"
RunNetSH -NetSHCommandToExecute "ipsec static show all"
CollectFiles -filesToCollect $OutputFile -fileDescription "IPsec netsh static show all" -SectionDescription $sectionDescription

$filesToCollect = $ComputerName + "_IPsec_netsh_LocalPolicyExport.ipsec"
$commandToRun = "netsh ipsec static exportpolicy " +  $filesToCollect
RunCMD -CommandToRun $commandToRun -filesToCollect $filesToCollect -fileDescription "IPsec Local Policy Export" -sectionDescription $sectionDescription  -BackgroundExecution

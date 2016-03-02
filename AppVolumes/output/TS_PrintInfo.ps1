PARAM([switch]$DetectRootCauses, [switch] $DoNotCollectFile)



Import-LocalizedData -BindingVariable PrintInfoStrings -FileName TS_PrintInfo -UICulture en-us

Write-DiagProgress -Activity $PrintInfoStrings.ID_PrintInfo -Status $PrintInfoStrings.ID_PrintInfoCollecting

if ($DetectRootCauses.IsPresent) {$cmdLineToAdd = " /generatescripteddiagxmlalerts"} else {$cmdLineToAdd = ""}

$CommandToExecute = "cscript.exe PrintInfo.VBS" + $cmdLineToAdd


if ($DoNotCollectFile.IsPresent)
{
	RunCmD -commandToRun $CommandToExecute -CollectFiles $false 
}
else
{
	$OutputFile = $Computername + "_PrintInfo.*"
	RunCmD -commandToRun $CommandToExecute -sectionDescription "Print Drivers and Printers information" -filesToCollect $OutputFile -fileDescription $PrintInfoStrings.ID_PrintInfoOutput 
}

if ($DetectRootCauses.IsPresent) {
	$PrintInfoAlertXMLFileName = $Computername + "_PrintInfoAlerts.XML"
	if (test-path $PrintInfoAlertXMLFileName) {	
		Update-DiagRootCause -id RC_PrintInfo -Detected $true
	}
}

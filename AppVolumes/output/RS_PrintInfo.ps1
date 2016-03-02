
. ./utils_cts.ps1
SkipSecondExecution



$PrintInfoAlertXMLFileName = $Computername + "_PrintInfoAlerts.XML"

if (Test-Path $PrintInfoAlertXMLFileName) {
	
	if($debug -eq $true){[void]$shell.popup($PrintInfoAlertXMLFileName)}
	
	[xml] $XMLResults = Get-Content -Path $PrintInfoAlertXMLFileName
	$ID = 0
	$XMLResults.SelectNodes("//Alert") | Sort-Object -Property  @{expression={$_.Priority};Descending=$true} | ForEach-Object -Process { 
		$ID +=1
		$_.InnerXML | Update-DiagReport -id ($ID.ToString() + "_PrintInfo") -Name $_.Category -verbosity $_.Type
	}
}
if($debug -eq $true){[void]$shell.popup("RS_PrintInfo.ps1 finished")}

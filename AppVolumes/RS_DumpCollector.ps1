. ./utils_cts.ps1
SkipSecondExecution

$debug = $false



$DumpCollectorAlertXMLFileName = $Pwd.Path + "\" + $Computername + "_DumpReportAlerts.XML"

if (Test-Path $DumpCollectorAlertXMLFileName) {
	
	if($debug -eq $true){[void]$shell.popup($DumpCollectorAlertXMLFileName)}
	
	[xml] $XMLResults = Get-Content -Path $DumpCollectorAlertXMLFileName
	$ID = 0
	$XMLResults.SelectNodes("//Alert") | Sort-Object -Property  @{expression={$_.Priority};Descending=$true} | ForEach-Object -Process { 
		$_.Get_InnerXML() | Update-DiagReport -id ($ID.ToString() + "_DumpCollector") -Name $_.Category -verbosity $_.Type
	}
} else {
	"[RS_DumpCollector] Error: $DumpCollectorAlertXMLFileName does not exist"
}

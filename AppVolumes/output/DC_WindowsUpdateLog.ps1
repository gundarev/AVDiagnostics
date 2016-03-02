PARAM([string]$MachineName = $ComputerName,[string]$Path= $null)

Function CopyWindowsupdateLog($sourceFileName, $destinationFileName, $fileDescription) 
{

	$sectionDescription = "Windows Update"
	
	if (test-path $sourceFileName) {
		$sourceFile = Get-Item $sourceFileName
		#copy the file only if it is not a 0KB file.
		if ($sourceFile.Length -gt 0) 
		{
			$CommandLineToExecute = "cmd.exe /c copy `"$sourceFileName`" `"$destinationFileName`""
			RunCmD -commandToRun $CommandLineToExecute -sectionDescription $sectionDescription -filesToCollect $destinationFileName -fileDescription $fileDescription -BackgroundExecution
		}
	}
}

$FileToCollect = $null
if([string]::IsNullOrEmpty($Path))
{
	$FileToCollect = Join-Path $Env:windir "windowsupdate.log"
}
else
{
	$FileToCollect = Join-Path $Path "windowsupdate.log"

}

$FileDescription = "Windows update log"

Import-LocalizedData -BindingVariable ScriptStrings

Write-DiagProgress -activity $ScriptStrings.ID_WindowsUpdateLogCollect -status $ScriptStrings.ID_WindowsUpdateLogCollectDesc

$destinationFileName = $MachineName + "_windowsupdate.log"

CopyWindowsupdateLog -sourceFileName $FileToCollect -destinationFileName $destinationFileName -fileDescription $FileDescription

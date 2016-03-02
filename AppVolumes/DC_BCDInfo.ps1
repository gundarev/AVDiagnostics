Function RunBCDEdit ($BCDEditCommand, [switch]$CollectFile) {

	$OutputFile = $ComputerName + "_BCDEdit.TXT"
	$CommandLineToExecute = "cmd.exe /c $BCDEditCommand >> $OutputFile"
	
	#header
	$date=Get-Date
	"-" * ($CommandLineToExecute.Length + 35) + "`r`n[$date] $BCDEditCommand`r`n" + "-" * ($BCDEditCommand.Length + 35) | Out-File -FilePath $OutputFile -Append



	RunCmD -commandToRun $CommandLineToExecute -sectionDescription "Boot Information" -filesToCollect $OutputFile -fileDescription "BCDEdit Output" -collectFiles $CollectFile.IsPresent -BackgroundExecution
}

Import-LocalizedData -BindingVariable BootInfoStrings

Write-DiagProgress -Activity $BootInfoStrings.ID_BootInfo -Status $BootInfoStrings.ID_BootInformation

if ($OSVersion.Major -ge 6)
{
	$BcdEditCommand = "bcdedit.exe /enum"
	RunBCDEdit -BCDEditCommand $BcdEditCommand

	$BcdEditCommand = "bcdedit.exe /enum all"
	RunBCDEdit -BCDEditCommand $BcdEditCommand

	$BcdEditCommand = "bcdedit.exe /enum all /v"
	RunBCDEdit -BCDEditCommand $BcdEditCommand -CollectFile

	#$OutputFile = $ComputerName + "_BCD-Backup.BKP"
	#$CommandLineToExecute = "bcdedit.exe /export `"$OutputFile`""
	#RunCmD -commandToRun $CommandLineToExecute -sectionDescription "Boot Information" -filesToCollect $OutputFile -fileDescription "BCD Backup (System Store)"
}
else
{
	$BootIni = (Join-Path $Env:SystemDrive "boot.ini")
	if (Test-Path $BootIni )
	{
		Get-Content $BootIni | Out-File (Join-Path $PWD.Path "Boot.ini")
		Collectfiles -fileDescription "Boot.Ini" -filesToCollect (Join-Path $PWD.Path "Boot.ini") -renameOutput $true -sectionDescription "Boot Information" 
	}
	else
	{
		"$BootIni could not be found" | WriteTo-StdOut
	}
}

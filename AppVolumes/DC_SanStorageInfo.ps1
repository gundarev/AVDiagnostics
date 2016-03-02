if ($OSVersion.Major -eq 5)
{
	# Disabling running on Win2K3 x64 due some reports of crashes for specific controllers
	"[San.exe] - Skipping running san.exe on Windows prior to Server 2008" | WriteTo-StdOut
}
else
{
	Import-LocalizedData -BindingVariable SanStorageInfoStrings

	Write-DiagProgress -Activity $SanStorageInfoStrings.ID_SanDev -Status $DOSDevStrings.ID_SanDevRunning

	$fileDescription = $SanStorageInfoStrings.ID_SanStorageInfoOutput
	$sectionDescription = $SanStorageInfoStrings.ID_SanStorageInfoOutputDesc
	$OutputFile = $ComputerName + "_Storage_Information.txt"
	$CommandToExecute = "cmd.exe /c SAN.exe $CommandToAdd"

	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -BackgroundExecution
}

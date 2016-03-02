#************************************************
# DC_PStat.PS1
# Version 1.0.1
# Date: 07-10-2009
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script obtains network information 
#              via PStat.exe tool, saving output to a
#              file named $ComputerName_PStat.txt
#************************************************



Import-LocalizedData -BindingVariable PStatStrings -FileName DC_PStat -UICulture en-us
	
Write-DiagProgress -Activity $PStatStrings.ID_PStat -Status $PStatStrings.ID_PStatRunning

if ($Env:PROCESSOR_ARCHITECTURE -ne "IA64") {

	$sectionDescription = $PStatStrings.ID_PStat

	$PStatExe = "PStat" + $Env:PROCESSOR_ARCHITECTURE + ".exe"

	$OutputFile = join-path $pwd.path ($ComputerName + "_PStat.txt")
	$CommandToExecute = $Env:windir + "\system32\cmd.exe /c $PStatExe > `"$OutputFile`""

	$fileDescription = $PStatStrings.ID_PStatOutput
	if ($OSArchitecture -ne 'ARM')
	{
		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -BackgroundExecution
	}
	else
	{
		 'Skipping running {' + $PStatExe + '} since it is not supported in ' + $OSArchitecture + ' architecture.' | WriteTo-StdOut
	}
} else {
	$PSCustom = new-object PSObject
	add-member -inputobject $PSCustom -membertype noteproperty -name "PStat" -value "PStat is not supported on IA64" 
	$PSCustom  | convertto-xml | update-diagreport -id 00_PStat -name "PStat" -verbosity "Debug"
}

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}


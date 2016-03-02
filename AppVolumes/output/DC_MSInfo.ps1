#************************************************
#Last Updated Date: 05-24-2012
#Updated By: Alec Yao     v-alyao@microsoft.com
#Description: Add two arguments for the script, called $Prefix and $Suffix. It will allow to custermize the filename
#************************************************
PARAM ($NFO = $true, $TXT = $true, $Prefix = '', $Suffix = '')

Import-LocalizedData -BindingVariable MSInfoStrings

Write-DiagProgress -Activity $MSInfoStrings.ID_MSInfo32 -Status $MSInfoStrings.ID_MSInfo32Running

$Process = "msinfo32.exe"
$sectionDescription = "System Information"

if (test-path (join-path ([Environment]::GetFolderPath("System")) $Process))
{
	$ProcessPath = "`"" + (join-path ([Environment]::GetFolderPath("System")) $Process) + "`"" 
}
elseif (test-path (join-path ([Environment]::GetFolderPath("CommonProgramFiles")) "Microsoft Shared\MSInfo\$Process"))
{
	$ProcessPath = "`"" + (join-path ([Environment]::GetFolderPath("CommonProgramFiles")) "Microsoft Shared\MSInfo\$Process") + "`""
} 
else
{
	$ProcessPath = "cmd.exe /c start /wait `"MsInfo`" $Process"
}

if ($OSVersion.Major -lt 6) #PreVista
{
	
	$fileToCollect = Join-Path -Path $PWD.Path -ChildPath ($ComputerName + "_" + $Prefix + "msinfo32" + $Suffix)
	$Arg = "/report `"$fileToCollect.txt`" /nfo `"$fileToCollect.nfo`" /categories +all-SWEnvRunningTasks-SWEnvLoadedModules-SWEnvWindowsError"
	$fileDescription = "MSInfo32 Report"

	Runcmd -commandToRun ($ProcessPath + " " + $Arg) -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect ($fileToCollect +".*") -BackgroundExecution

} 
else 
{
	$fileToCollect = Join-Path -Path $PWD.Path -ChildPath ($ComputerName + "_" + $Prefix + "msinfo32" + $Suffix + ".txt")
	$Arg = "/report `"$fileToCollect`""
	$fileDescription = "Text Format"
	
	if ($TXT)
	{
		Runcmd -commandToRun ($ProcessPath + " " + $Arg) -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $fileToCollect -BackgroundExecution
	}
	else
	{
		"MSInfo TXT not generated" | WriteTo-StdOut
	}

	$fileToCollect = Join-Path -Path $PWD.Path -ChildPath ($ComputerName + "_" + $Prefix + "msinfo32" + $Suffix + ".nfo")
	$Arg = "/nfo  `"$fileToCollect`""
	$fileDescription = "NFO Format"
	
	if ($NFO)
	{
		Runcmd -commandToRun ($ProcessPath + " " + $Arg) -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $fileToCollect -BackgroundExecution 
	}
	else
	{
		"MSInfo NFO not generated" | WriteTo-StdOut
	}
}

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}

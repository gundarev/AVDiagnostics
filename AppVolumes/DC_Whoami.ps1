
#************************************************
# DC_Whoami.ps1
# Version 1.0
# Date: 10-17-2009
# Author: David Fisher
# Description: This script obtains the user's SID, Group Memberhips,
#              and privileges using the Whoami.exe utility.
#************************************************
#Last Updated Date: 05-24-2012
#Updated By: Alec Yao     v-alyao@microsoft.com
#Description: Add two arguments for the script, called $Prefix and $Suffix. It will allow to custermize the filename
#************************************************
Param($Prefix = '', $Suffix = '')
Import-LocalizedData -BindingVariable InboxCommandStrings -FileName DC_Whoami -UICulture en-us
	
Write-DiagProgress -Activity $InboxCommandStrings.ID_WhoamiOutput -Status $InboxCommandStrings.ID_WhoamiStatus

$OutputFile = join-path $pwd.path ($ComputerName + "_" + $Prefix + "Whoami" + $Suffix + ".txt")
$CommandLineToExecute = $Env:windir + "\system32\cmd.exe /c whoami.exe /all > `"$OutputFile`""

$FileDescription = "Whoami /all Output"
$SectionDescription = "User and Group Information"

RunCmD -commandToRun $CommandLineToExecute -sectionDescription $SectionDescription -filesToCollect $OutputFile -fileDescription $FileDescription -BackgroundExecution

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}

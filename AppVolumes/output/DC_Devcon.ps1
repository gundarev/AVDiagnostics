# Copyright ?2008, Microsoft Corporation. All rights reserved.

# You may use this code and information and create derivative works of it,
# provided that the following conditions are met:
# 1. This code and information and any derivative works may only be used for
# troubleshooting a) Windows and b) products for Windows, in either case using
# the Windows Troubleshooting Platform
# 2. Any copies of this code and information
# and any derivative works must retain the above copyright notice, this list of
# conditions and the following disclaimer.
# 3. THIS CODE AND INFORMATION IS PROVIDED ``AS IS'' WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. IF THIS CODE AND
# INFORMATION IS USED OR MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION
# WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

# Copyright ?2008, Microsoft Corporation. All rights reserved.

# You may use this code and information and create derivative works of it,
# provided that the following conditions are met:
# 1. This code and information and any derivative works may only be used for
# troubleshooting a) Windows and b) products for Windows, in either case using
# the Windows Troubleshooting Platform
# 2. Any copies of this code and information
# and any derivative works must retain the above copyright notice, this list of
# conditions and the following disclaimer.
# 3. THIS CODE AND INFORMATION IS PROVIDED ``AS IS'' WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. IF THIS CODE AND
# INFORMATION IS USED OR MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION
# WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.
if ($OSArchitecture -eq 'ARM')
{
	'Skipping running {devcon.exe} since it is not supported in ' + $OSArchitecture + ' architecture.' | WriteTo-StdOut
	return
}

Import-LocalizedData -BindingVariable DevConStrings -FileName DC_DevCon -UICulture en-us
	
Write-DiagProgress -Activity $DevConStrings.ID_DevCon -Status $DevConStrings.ID_DevConRunning

$fileDescription = $DevConStrings.ID_DevConOutput
$sectionDescription = $DevConStrings.ID_DevConOutputDesc
$OutputFile = $ComputerName + "_DevCon.txt"

"DRIVER NODE INFORMATION`r`n" + "-" * 23 + "`r`n" | Out-File -FilePath $OutputFile
$CommandToExecute = "cmd.exe /c devcon.exe drivernodes * >> $OutputFile"
RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false -BackgroundExecution

"`r`nHARDWARE ID INFORMATION `r`n" + "-" * 23 + "`r`n" | Out-File -FilePath $OutputFile -append
$CommandToExecute = "cmd.exe /c devcon.exe hwids * >> $OutputFile"
RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false -BackgroundExecution 

"`r`nHARDWARE RESOURCE USAGE INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
$CommandToExecute = "cmd.exe /c devcon.exe resources * >> $OutputFile"
RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false -BackgroundExecution

"`r`nHARDWARE STACK INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
$CommandToExecute = "cmd.exe /c devcon.exe stack * >> $OutputFile"
RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false -BackgroundExecution

"`r`nHARDWARE STATUS INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
$CommandToExecute = "cmd.exe /c devcon.exe status * >> $OutputFile"
RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false -BackgroundExecution

"`r`nDRIVER FILES INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
$CommandToExecute = "cmd.exe /c devcon.exe driverfiles * >> $OutputFile"
RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false -BackgroundExecution

"`r`nCLASSES INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
$CommandToExecute = "cmd.exe /c devcon.exe classes * >> $OutputFile"
RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false -BackgroundExecution

"`r`nFIND ALL INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
$CommandToExecute = "cmd.exe /c devcon.exe findall * >> $OutputFile"
RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $true -BackgroundExecution

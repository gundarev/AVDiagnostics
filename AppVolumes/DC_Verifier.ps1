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



Import-LocalizedData -BindingVariable VerifierStrings
	
Write-DiagProgress -Activity $VerifierStrings.ID_VerifierDC -Status $VerifierStrings.ID_VerifierDCObtaining

$OutputFile = $ComputerName + "_verifier.txt"
$CommandLineToExecute = "cmd.exe /c verifier.exe /query > $OutputFile"

RunCmD -commandToRun $CommandLineToExecute -sectionDescription $VerifierStrings.ID_VerifierDCOutputDesc -filesToCollect $OutputFile -fileDescription $VerifierStrings.ID_VerifierDCOutput -BackgroundExecution

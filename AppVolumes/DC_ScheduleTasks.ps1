
Import-LocalizedData -BindingVariable ScheduleTasksStrings
	
Write-DiagProgress -Activity $ScheduleTasksStrings.ID_ScheduleTasks -Status $ScheduleTasksStrings.ID_ScheduleTasksObtaining

$OutputFile = $ComputerName + '_schtasks.csv'
$CommandLineToExecute = "cmd.exe /c %windir%\system32\schtasks.exe /query /fo CSV /v > $OutputFile"

RunCMD -commandToRun $CommandLineToExecute -sectionDescription $ScheduleTasksStrings.ID_ScheduleTasksSection -filesToCollect $OutputFile -fileDescription $ScheduleTasksStrings.ID_ScheduleTasksOutput -BackgroundExecution

$OutputFile = $ComputerName + '_schtasks.txt'
$CommandLineToExecute = "cmd.exe /c %windir%\system32\schtasks.exe /query /v > $OutputFile"

RunCMD -commandToRun $CommandLineToExecute -sectionDescription $ScheduleTasksStrings.ID_ScheduleTasksSection -filesToCollect $OutputFile -fileDescription $ScheduleTasksStrings.ID_ScheduleTasksOutput -BackgroundExecution

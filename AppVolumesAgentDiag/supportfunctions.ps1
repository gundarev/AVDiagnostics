

$ComputerName = $Env:computername
$OSVersion = [Environment]::OSVersion.Version

#*================================================================================
#Get-ServiceStartup
#*================================================================================
function Get-ServiceStartup
{
    param
    (
        [Object]
        $objService
    )

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $objService.Name
    if(Test-Path -Path $path)
    {
        $StartupType = (Get-ItemProperty -Path $path -ea silentlycontinue).start
    }
    Switch($StartupType)
    {
        0 
        {
            $TypeName = 'Boot'
        }
        1 
        {
            $TypeName = 'System'
        }
        2 
        {
            $TypeName = 'Automatic'
        }
        3 
        {
            $TypeName = 'Manual'
        }
        4 
        {
            $TypeName = 'Disabled'
        }
        default 
        {
            $TypeName = 'Error'
        }
    }

    Switch($StartupType)
    {
        0 
        {
            $TypeDescription = 'Loaded by kernel loader. Components of the driver stack for the boot (startup) volume must be loaded by the kernel loader.'
        }
        1 
        {
            $TypeDescription = 'Loaded by I/O subsystem. Specifies that the driver is loaded at kernel initialization.'
        }
        2 
        {
            $TypeDescription = 'Loaded by Service Control Manager. Specifies that the service is loaded or started automatically.'
        }
        3 
        {
            $TypeDescription = 'The service does not start until the user starts it manually, such as by using Services or Devices in Control Panel. '
        }
        4 
        {
            $TypeDescription = 'Specifies that the service should not be started.'
        }
        default 
        {
            $TypeDescription = 'There was an error retrieving information about this service.'
        }
    }

    return $TypeName
}




Function Invoke-RunCMD
{
    param ([string]$commandToRun, 
        $filesToCollect = $null, 
        [string]$fileDescription = '', 
        [string]$sectionDescription = '', 
        
        [string]$Verbosity = 'Informational',
        [switch]$NoFileExtensionsOnDescription,
        [boolean]$RenameOutput = $false,
        [switch]$DirectCommand,
    [Scriptblock] $PostProcessingScriptBlock)
    trap [Exception] 
    {
        Write-Error -Exception $_ -Message "[RunCMD (commandToRun = $commandToRun) (filesToCollect = $filesToCollect) (fileDescription $fileDescription) (sectionDescription = $sectionDescription) (collectFiles $collectFiles)]" -ErrorId $_.
       
        $Error.Clear()
        continue
    }
    [boolean]$collectFiles = $true

	
    if ($filesToCollect -eq $null)
    {
        $collectFiles = $false
    }


    $StringToAdd += " (Collect Files: $collectFiles)"
	
    '[RunCMD] Running Command' + $StringToAdd + ":`r`n `r`n                      $commandToRun`r`n" | Write-Output

 	
    '--[Stdout-Output]---------------------' | Write-Output
		
		
      
    $process = Invoke-ProcessCreate -Process 'cmd.exe' -Arguments ("/s /c `"" + $commandToRun + "`"")
        
    $process.WaitForExit()
    $StdoutOutput = $process.StandardOutput.ReadToEnd() 
    if ($StdoutOutput -ne $null)
    {
        ($StdoutOutput | Out-String) | Write-Output
    }
    else
    {
        '(No stdout output generated)' | Write-Output
    }
    $ProcessExitCode = $process.ExitCode
    if ($ProcessExitCode -ne 0) 
    {
        '[RunCMD] Process exited with error code ' + ('0x{0:X}' -f $process.ExitCode)  + " when running command line:`r`n             " + $commandToRun |Write-Output
        $ProcessStdError = $process.StandardError.ReadToEnd()
        if ($ProcessStdError -ne $null)
        {
            '--[StandardError-Output]--------------' + "`r`n" + $ProcessStdError + '--[EndOutput]-------------------------' + "`r`n" | Write-Output
        }
    }
		 
	
    "--[Finished-Output]-------------------`r`n" |Write-Output
		
    if ($collectFiles -eq $true) 
    {	
        '[RunCMD] Collecting Output Files... ' | Write-Output
        if ($NoFileExtensionsOnDescription.isPresent)
        {
            Invoke-CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -noFileExtensionsOnDescription -renameOutput $RenameOutput -InvokeInfo $MyInvocation
        }
        else 
        {
            Invoke-CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -renameOutput $RenameOutput -InvokeInfo $MyInvocation
        }
    }
}
Function Invoke-ProcessCreate
{
    param
    (
        [Object]
        $process,

        [string]
        $Arguments = '',

        [Object]
        $WorkingDirectory = $null
    )

	
    "ProcessCreate($process, $Arguments) called." | Write-Output 
	
    $Error.Clear()
    $processStartInfo  = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $processStartInfo.fileName = $process
    if ($Arguments.Length -ne 0) 
    {
        $processStartInfo.Arguments = $Arguments
    }
    if ($WorkingDirectory -eq $null) 
    {
        $processStartInfo.WorkingDirectory = (Get-Location).Path
    }
    $processStartInfo.UseShellExecute = $false
    $processStartInfo.RedirectStandardOutput = $true
    $processStartInfo.REdirectStandardError = $true
	
    #$process = New-Object System.Diagnostics.Process
    #$process.startInfo=$processStartInfo
	
    $process = [System.Diagnostics.Process]::Start($processStartInfo)
	
    if ($Error.Count -gt 0)
    {
        $errorMessage = $Error[0].Exception.Message
        $errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
        $PositionMessage = $Error[0].InvocationInfo.PositionMessage
        '[ProcessCreate] Error ' + $errorCode + ' on: ' + $line + ": $errorMessage" | Write-Output

        $Error.Clear()
    }

    Return $process
}

Function Invoke-CollectFiles
{
    param ($filesToCollect, 
        [string]$fileDescription = 'File', 
        [string]$sectionDescription = 'Section',
        [boolean]$RenameOutput = $false,
        [string]$MachineNamePrefix = $ComputerName,
        [switch]$NoFileExtensionsOnDescription,
        [string]$Verbosity = 'Informational',
    [System.Management.Automation.InvocationInfo] $InvokeInfo = $MyInvocation)

    $AddToStdout = "[CollectFiles] Collecting File(s):`r`n"
    if ($sectionDescription -ne 'Section')
    {
        $AddToStdout += "`r`n          Section    : $sectionDescription"
    }
    if ($fileDescription -ne 'File')
    {
        $AddToStdout += "`r`n          Description: $fileDescription"
    }

    $AddToStdout += "`r`n          Files      : $filesToCollect`r`n"
	
    $AddToStdout += '                     ----------------------------------'
    $AddToStdout | Write-Output

    ForEach ($pathFilesToCollect in $filesToCollect) 
    {
        if (($pathFilesToCollect -ne $null) -and (Test-Path $pathFilesToCollect -ErrorAction SilentlyContinue)) 
        {
            $FilestobeCollected = Get-ChildItem  $pathFilesToCollect
            $FilestobeCollected | ForEach-Object -Process {
                $FileName = Split-Path -Path $_.Name -Leaf
                $FileNameFullPath = $_.FullName
                $FileExtension = $_.extension.ToLower()
                $FilesCollectedDisplay = ''
                if ($NoFileExtensionsOnDescription.IsPresent) 
                {
                    $ReportDisplayName = $fileDescription
                }
                else 
                {
                    $ReportDisplayName = "$fileDescription ($FileExtension)"
                }
               
                if (Test-Path $FileNameFullPath)
                {
                    $m = (Get-Date -DisplayHint time).DateTime.ToString()										
                    if (($RenameOutput -eq $true) -and (-not $FileName.StartsWith($MachineNamePrefix))) 
                    {
                        $FileToCollect = $MachineNamePrefix + '_' + $FileName
                        $FilesCollectedDisplay += "                     | [$m] $FileName to $FileToCollect" |Write-Output
                        Copy-Item -Path $FileNameFullPath -Destination $FileToCollect 
                    }
                    else 
                    {
                        $FileToCollect = $FileNameFullPath
                        $FilesCollectedDisplay += "                     | [$m] $FileName" | Write-Output
                    }
							
                    $FileToCollectInfo = Get-Item $FileToCollect
					
                    if (($FileToCollectInfo.Length) -ge 2147483648)
                    {
                        $InfoSummary = New-Object -TypeName PSObject
                        $InfoSummary | Add-Member -MemberType noteproperty -Name $fileDescription -Value ('Not Collected. File is too large - ' + (FormatBytes -bytes $FileToCollectInfo.Length) + '')
                        $InfoSummary |
                        ConvertTo-Xml2 |
                        Update-DiagReport -Id ('CompFile_' + (Get-Random).ToString())  -Name $ReportDisplayName -Verbosity 'Error'
                        "[CollectFiles] Error: $FileToCollect ($fileDescription) will not be collected once it is larger than 2GB. Current File size: " + (FormatBytes -bytes $FileToCollectInfo.Length) | Write-Output
                    }
                    else
                    {
                        Update-DiagReport -Id $sectionDescription -Name $ReportDisplayName -File $FileToCollect -Verbosity $Verbosity
                    }
                }
                else
                {
                    (' ' * 21) + '[CollectFiles] ' + $FileNameFullPath + ' could not be found' | Write-Output
                }
            }
        } else 
        {
            (' ' * 21) + '[CollectFiles] ' + $pathFilesToCollect + ': The system cannot find the file(s) specified' |Write-Output
        }
    }
    "                     ----------------------------------`r`n" | Write-Output
}

Filter FormatBytes 
{
    param ($bytes,$precision = '0')
    trap [Exception] 
    {
        Write-Output -InputObject "[FormatBytes Error] - Bytes: $bytes / Precision: $precision" 
        continue
    }
	
    if ($bytes -eq $null)
    {
        $bytes = $_
    }
	
    if ($bytes -ne $null)
    {
        $bytes = [double] $bytes
        foreach ($i in ('Bytes', 'KB', 'MB', 'GB', 'TB')) 
        {
            if (($bytes -lt 1000) -or ($i -eq 'TB'))
            {
                $bytes = ($bytes).tostring('F0' + "$precision")
                return $bytes + " $i"
            }
            else 
            {
                $bytes /= 1KB
            }
        }
    }
}
#ConvertTo-Xml2 function
#-------------------------
#  This function is a replacement from ConvertTo-Xml.
#  ConvertTo-Xml replaces HTML tags inside strings limiting the richness of the resulting data
#  For instance, when using ConvertTo-Xml against a string like <b>Text</b>, results on the following:
#  &lt;b&gt;Text&lt;/b&gt;
#  the ConvertTo-Xml2 is our light implementation for ConvertTo-Xml that do not make string conversion.
filter ConvertTo-Xml2
{
    Param ($object, [switch]$sortObject, [int] $Visibility = 4)

    trap [Exception] 
    {
        Write-Output -InputObject $_ 
        $Error.Clear()
        continue
    }

    if ($object -eq $null) 
    {
        $object = $_
    }
	
    $TypeName = $object.GetType().FullName
	
    if (($Visibility -ge 0) -and ($Visibility -le 3))
    {
        $VisibilityString = 'Visibility="' + $Visibility + '"'
    }
    else
    {
        $VisibilityString = ''
    }
    $XMLString = "<?xml version=`"1.0`"?><Objects $VisibilityString><Object Type=`"$TypeName`">" 

    if ((($object.GetType().Name -eq 'PSObject') -or ($object.GetType().Name -eq 'PSCustomObject')) -and (-not $sortObject.IsPresent) ) 
    {
        foreach($p in $object.PSObject.Members | Where-Object -FilterScript {
                $_.MemberType -eq 'NoteProperty'
        }) 
        {
            $Name  = $p.Name
            $Value = $p.Value    
            $XMLString += "`t<Property Name=`"$Name`">$Value</Property>`r`n"
        }
    } 
    elseif ($object -is [System.String])
    {
        $XMLString += $object
    }
    else
    {
        foreach ($p in $object |Get-Member -type *Property)
        {
            $Name  = $p.Name
            $Value = $object.$Name    
            $XMLString += "`t<Property Name=`"$Name`">$Value</Property>`r`n"
        }
    }
    $XMLString += '</Object></Objects>'

    [xml] $XMLString
}

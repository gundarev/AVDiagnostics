PARAM($range = 'All', $prefix = '_sym', $FolderName = $null, $FileMask = $null, $Suffix = $null, $FileDescription = $null, [switch] $Recursive)
# v1.1 10 May 2010

$ProcArc = $Env:PROCESSOR_ARCHITECTURE
$ChkSymExe = 'Checksym' + $ProcArc + '.exe'

$Error.Clear

Import-LocalizedData -BindingVariable LocalsCheckSym

trap [Exception] 
{
    $errorMessage = $Error[0].Exception.Message
    $errorCode = '0x{0:X}' -f $Error[0].Exception.ErrorCode
	
    $Error.Clear
}

function GetExchangeInstallFolder
{
    If ((Test-Path -Path 'HKLM:SOFTWARE\Microsoft\ExchangeServer\v14') -eq $true)
    {
        [System.IO.Path]::GetDirectoryName((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath)
    }
    ElseIf ((Test-Path -Path 'HKLM:SOFTWARE\Microsoft\Exchange\v8.0') -eq $true) 
    {
        [System.IO.Path]::GetDirectoryName((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Exchange\Setup).MsiInstallPath)
    }
    Else 
    {
        $null
    }
}

Function FileExistOnFolder 
{
    param
    (
        [Object]
        $PathToScan,

        [Object]
        $FileMask,

        [switch]
        $Recursive
    )

    trap [Exception] 
    {
        'The following error ocurred when checking if a file exists on a folder:' | WriteTo-StdOut
        $errorMessage = $Error[0].Exception.Message
        $errorCode = '0x{0:X}' -f $Error[0].Exception.ErrorCode
	
        $Error.Clear
    }
    $AFileExist = $false
    foreach ($mask in $FileMask) 
    {
        if ([System.IO.Directory]::Exists($PathToScan)) 
        {
            $Files = [System.IO.Directory]::GetFiles($PathToScan, $mask)
            $AFileExist = ($Files.Count -ne 0)
            if ($AFileExist -eq $true)
            {
                return $AFileExist
            }
            ElseIf ($Recursive.IsPresent) 
            {
                $SubFolders = [System.IO.Directory]::GetDirectories($PathToScan)
                if ($SubFolders.Count -gt 0) 
                {
                    foreach ($SubFolder in $SubFolders) 
                    {
                        FileExistOnFolder $SubFolder $mask -Recursive
                    } 
                }
            }
        }
    }
    $AFileExist
}

Function RunChkSym ([string]$PathToScan = '', [array]$FileMask = '*.*', [string]$Output = '', [boolean]$Recursive = $false, [string]$Arguments = '', [string]$Description = '')
{
    if (($Arguments -ne '') -or (Test-Path ($PathToScan))) 
    {
        if ($PathToScan -ne '')
        {
            $eOutput = $Output
            ForEach ($scFileMask in $FileMask)
            {
                #
                $eFileMask = ($scFileMask.replace('*.*','')).toupper()
                $eFileMask = ($eFileMask.replace('*.',''))
                $eFileMask = ($eFileMask.replace('.*',''))
                if ($eFileMask -ne '') 
                {
                    $eOutput += ('_' + $eFileMask)
                }
                $symScanPath += ((Join-Path -Path $PathToScan -ChildPath $scFileMask) + ';')
            }
        }
		
		
        if ($Description -ne '') 
        {
            $FileDescription = $Description
        }
        else 
        {
            $fdFileMask = [string]::join(';',$FileMask)
            if ($fdFileMask -contains ';') 
            {
                $FileDescription = $PathToScan + ' [' + $fdFileMask + ']'
            }
            else 
            {
                $FileDescription = (Join-Path -Path $PathToScan -ChildPath $fdFileMask)
            }
        }
	

        if ($Arguments -ne '') 
        {
            $eOutput = $Output
            Write-DiagProgress -Activity $LocalsCheckSym.ID_FileVersionInfo -Status $Description
            $CommandToExecute = "cmd.exe /c $ChkSymExe $Arguments"
        }
        else 
        {
            Write-DiagProgress -Activity $LocalsCheckSym.ID_FileVersionInfo -Status ($FileDescription)# + " Recursive: " + $Recursive)
            if ($Recursive -eq $true) 
            {
                $F = '-F2'
                $AFileExistOnFolder = (FileExistOnFolder -PathToScan $PathToScan -FileMask $scFileMask -Recursive) 
            }
            else 
            {
                $F = '-F'
                $AFileExistOnFolder = (FileExistOnFolder -PathToScan $PathToScan -FileMask $scFileMask)
            }
            if ($AFileExistOnFolder) 
            {
                $CommandToExecute = "cmd.exe /c $ChkSymExe $F `"$symScanPath`" -R -S -O2 `"$eOutput.CSV`""
            }
            else 
            {
                "Chksym did not run against path '$PathToScan' since there are no files with mask ($scFileMask) on system" | WriteTo-StdOut
                $CommandToExecute = ''
            }
        }
        if ($CommandToExecute -ne '') 
        {
            RunCMD -commandToRun $CommandToExecute -sectionDescription $LocalsCheckSym.ID_FileVersionInfo -filesToCollect ("$eOutput.*") -fileDescription $FileDescription
            
        }
    }
    else 
    {
        "Chksym did not run against path '$PathToScan' since path does not exist" | WriteTo-StdOut
    }
}


#Check if using $FolderName or $RangeString
if (($FolderName -ne $null) -and ($FileMask -ne $null) -and ($Suffix -ne $null)) 
{
    $OutputBase = $ComputerName + $prefix + $Suffix
    $IsRecursive = ($Recursive.IsPresent)
    RunChkSym -PathToScan $FolderName -FileMask $FileMask -Output $OutputBase -Recursive $IsRecursive RunChkSym -PathToScan $FolderName -FileMask $FileMask -Output $OutputBase  -Description $FileDescription -Recursive $IsRecursive
}
else 
{
    [array] $RunChkSym = $null
    Foreach ($RangeString in $range) 
    {
        if ($RangeString -eq 'All')	
        {
            $RunChkSym += 'ProgramFilesSys', 'Drivers', 'System32DLL', 'System32Exe', 'System32SYS', 'Spool', 'iSCSI', 'Process', 'RunningDrivers', 'Cluster'
        }
        else 
        {
            $RunChkSym += $RangeString
        }
    }

    switch ($RunChkSym)	{
        'ProgramFilesSys' 
        {
            $OutputBase = "$ComputerName$prefix" + '_ProgramFiles'
            RunChkSym -PathToScan "$Env:ProgramFiles" -FileMask '*.sys' -Output $OutputBase -Recursive $true
            if (($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') -or $Env:PROCESSOR_ARCHITECTURE -eq 'IA64')  
            {
                $OutputBase = "$ComputerName$prefix" + '_ProgramFilesx86'
                RunChkSym -PathToScan (${Env:ProgramFiles(x86)}) -FileMask '*.sys' -Output $OutputBase -Recursive $true
            }
        }
        'Drivers' 
        {
            $OutputBase = "$ComputerName$prefix" + '_Drivers'
            RunChkSym -PathToScan "$Env:SystemRoot\System32\drivers" -FileMask '*.*' -Output $OutputBase -Recursive $false
        }
        'System32DLL' 
        {
            $OutputBase = "$ComputerName$prefix" + '_System32'
            RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask '*.DLL' -Output $OutputBase -Recursive $false
            if (($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') -or $Env:PROCESSOR_ARCHITECTURE -eq 'IA64')  
            {
                $OutputBase = "$ComputerName$prefix" + '_SysWOW64'
                RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask '*.dll' -Output $OutputBase -Recursive $true
            }
        }
        'System32Exe' 
        {
            $OutputBase = "$ComputerName$prefix" + '_System32'
            RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask '*.EXE' -Output $OutputBase -Recursive $false
            if (($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') -or $Env:PROCESSOR_ARCHITECTURE -eq 'IA64')  
            {
                $OutputBase = "$ComputerName$prefix" + '_SysWOW64'
                RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask '*.exe' -Output $OutputBase -Recursive $true
            }
        }
        'System32SYS' 
        {
            $OutputBase = "$ComputerName$prefix" + '_System32'
            RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask '*.SYS' -Output $OutputBase -Recursive $false
            if (($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') -or $Env:PROCESSOR_ARCHITECTURE -eq 'IA64')  
            {
                $OutputBase = "$ComputerName$prefix" + '_SysWOW64'
                RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask '*.sys' -Output $OutputBase -Recursive $true
            }
        }
        'Spool' 
        {
            $OutputBase = "$ComputerName$prefix" + '_PrintSpool'
            RunChkSym -PathToScan "$Env:SystemRoot\System32\Spool" -FileMask '*.*' -Output $OutputBase -Recursive $true
        }
        'Cluster' 
        {
            $OutputBase = "$ComputerName$prefix" + '_Cluster'
            RunChkSym -PathToScan "$Env:SystemRoot\Cluster" -FileMask '*.*' -Output $OutputBase -Recursive $false
        }
        'iSCSI' 
        {
            $OutputBase = "$ComputerName$prefix" + '_MS_iSNS'
            RunChkSym -PathToScan "$Env:ProgramFiles\Microsoft iSNS Server" -FileMask '*.*' -Output $OutputBase -Recursive $true
            $OutputBase = "$ComputerName$prefix" + '_MS'
            RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask 'iscsi*.*' -Output $OutputBase -Recursive $true
        }
        'Process' 
        {
            $OutputBase = "$ComputerName$prefix" + '_Process'
            Get-Process | Out-File -FilePath "$OutputBase.txt"
            '--------------------------------' | Out-File -FilePath "$OutputBase.txt" -Append
            tasklist -svc | Out-File -FilePath "$OutputBase.txt" -Append
            '--------------------------------' | Out-File -FilePath "$OutputBase.txt" -Append
            RunChkSym -Output $OutputBase -Arguments "-P * -R -O2 `"$OutputBase.CSV`" >> `"$OutputBase.TXT`"" -Description 'Running Processes'
        }
        'RunningDrivers' 
        {
            $OutputBase = "$ComputerName$prefix" + '_RunningDrivers'
            RunChkSym -Output $OutputBase -Arguments "-D -R -S -O2 `"$OutputBase.CSV`"" -Description 'Running Drivers'
        }
        'InetSrv' 
        {
            $inetSrvPath = (Join-Path -Path $Env:SystemRoot -ChildPath system32\inetsrv)
            $OutputBase = "$ComputerName$prefix" + '_InetSrv'
            RunChkSym -PathToScan $inetSrvPath -FileMask ('*.exe', '*.dll') -Output $OutputBase -Recursive $true
        }
        'Exchange' 
        {
            $ExchangeFolder = GetExchangeInstallFolder
            if ($ExchangeFolder -ne $null)
            {
                $OutputBase = "$ComputerName$prefix" + '_Exchange'
                RunChkSym -PathToScan $ExchangeFolder -FileMask ('*.exe', '*.dll') -Output $OutputBase -Recursive $true
            } else 
            {
                'Chksym did not run against Exchange since it could not find Exchange server installation folder' | WriteTo-StdOut
            }
        }
		
    }
}

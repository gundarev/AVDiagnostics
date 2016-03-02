#************************************************
# TS_KnownKernelTags.ps1
# Version 1.0.1
# Date: 5/18/2012
# Author: v-maam
# Description:  This script detects and report memory problems
#************************************************

trap [Exception] 
{
	WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_KnownKernelTags.ps1 Error")
	continue
}

Import-LocalizedData -BindingVariable ScriptStrings
$SupportTopicsID = "8113"

$script:PagePool = @{}
$script:NonPagePool = @{}
$script:MemSnapFilePath = join-path $PWD.Path "memsnap.txt"

#region Check the script running condition
	
if(-not(Test-Path $script:MemSnapFilePath))
{
	Run-DiagExpression .\TS_ProcessInfo.ps1
}

if(-not(Test-Path $script:MemSnapFilePath))
{
	$script:MemSnapFilePath + " does not exist. Exiting..."  | WriteTo-StdOut -ShortFormat
	return
}

#endregion

#region shared functions

Function LoadPoolMemUsageTags($PagePool,$NonPagepool)
{
	if(Test-Path $script:MemSnapFilePath)
	{
		$fileArray = Get-Content $script:MemSnapFilePath
		for($i = 0; $i -lt $fileArray.Length; $i++)
		{
			if($i -ne 0)
			{
				$LineArray = $fileArray[$i].Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
				if($LineArray.Length -eq 7)
				{
					$TageType = $LineArray[1]
					$TagName = $LineArray[0]
					[int]$MemUsage = $LineArray[5]
	
					if($TageType -contains "Paged")
					{
						if($PagePool.ContainsKey($TagName))
						{
							$PagePool[$TagName] += $MemUsage
						}
						else
						{
							$PagePool.Add($TagName,$MemUsage)
						}
					}
	
					if($TageType -contains "Nonp")
					{
						if($NonPagePool.ContainsKey($TagName))
						{
							$NonPagePool[$TagName] += $MemUsage
						}
						else
						{
							$NonPagePool.Add($TagName,$MemUsage)
						}
					}	
				}
			}
		}
	}
	else
	{
		"Unable to find "+ $script:MemSnapFilePath +" file and will exit" | WriteTo-StdOut -ShortFormat
		return
	}
}

Function getFileVersionInfo($filePath)
{
	if(Test-Path $filePath)
	{
		$fileVersion = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($filePath))
		return $fileVersion
	}
	else
	{
		return $null
	}
}

Function checkTagProcessInfo($TagName,$InformationCollected,$Top=5,[switch] $NonPagedPoolCheck)
{
	if($NonPagedPoolCheck.IsPresent)
	{
		$PoolMemoryUsage = $script:NonPagePool.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top | Where-Object {$_.Name -eq $TagName}
	}
	else
	{
		$PoolMemoryUsage = $script:PagePool.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top | Where-Object {$_.Name -eq $TagName}
	}

	if($PoolMemoryUsage -ne $null)
	{
		add-member -inputobject $InformationCollected -membertype noteproperty -name "$TagName Kernel Tag Current Usage" -value (FormatBytes -bytes $PoolMemoryUsage.Value -precision 2)
		return $true
	}
	else
	{
		return $false
	}
}

#check the machine is server media or not
Function isServerMedia
{
	$Win32OS = Get-WmiObject -Class Win32_OperatingSystem
	
	if (($Win32OS.ProductType -eq 3) -or ($Win32OS.ProductType -eq 2)) #Server Media
	{
		return $true
	}
	else
	{
		return $false
	}
}

#endregion

# Load all PagePool and NonPagePool tags to hashtable
LoadPoolMemUsageTags -PagePool $script:PagePool -NonPagepool $script:NonPagePool
if(($script:PagePool.Count -eq 0) -and ($script:NonPagePool.Count -eq 0))
{
	"Load the memory page pool tags failed and will exit" | WriteTo-StdOut -ShortFormat
	return
}


#region rule 2334 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 2334

Function isAffectedOSVersionFor2334
{
	if(($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)) #WinXP64/Server 2003 
	{
		return $true
	}
	else
	{
		return $false
	}
}

#rule 2334 detect logic
if(isAffectedOSVersionFor2334)
{
	$SysEventfilePath = "$Env:windir\system32\drivers\SymEvent.sys"
	$2334InformationCollected = new-object PSObject
	$RootCauseName = "RC_PagedPoolD2dSymEvent"
	$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=B;EN-US;2658721"
	$Verbosity = "Error"
	$Visibility = "4"
	
	$currentVersion = Get-FileVersionString($SysEventfilePath)		
	
	#Detect root cause 
	if (($currentVersion -eq "12.8.3.22") -and (checkTagProcessInfo -TagName "D2d" -InformationCollected $2334InformationCollected))
	{		
		add-member -inputobject $2334InformationCollected -membertype noteproperty -name "Current symevent.sys version" -value $currentVersion
			
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -InternalContentURL $InternalContent -InformationCollected $2334InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_PagedPoolD2dSymEvent_SD
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 1870 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 1870

Function isAffectedOSVersionFor1870
{
	if(((($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)) -or #Server 2003
	   (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 0)) -or # Server 2008
	   (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1))) -and #Win 7/Server 2008 R2 
	    (isRDSEnabled)) #Terminal Services
	{
		return $true
	}
	else
	{
		return $false
	}
}

#Check if Disable WindowsUpdateAccess is enabled
Function isWindowsUpdateAccessEnabled
{
	$WindowsUpdateAccessPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"
	if(Test-Path $WindowsUpdateAccessPath)
	{
		if((Get-ItemProperty ($WindowsUpdateAccessPath)).WindowsUpdate -eq 1)
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	else 
	{
		return $false
	}
}

#Check if RDS Role/ Terminal Services app mode is installed
Function isRDSEnabled
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("[isRDSEnabled] Checking if RDS is Enabled")
		continue
	}
	
	$RDSEnabled = $false
	
	if ((Get-WmiObject -Class Win32_OperatingSystem -Property ProductType).ProductType -ne 1) #Server
	{
		if (($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2))
		{
			$NameSpace = 'root\CIMV2'
		}
		else
		{
			$NameSpace = 'root\CIMV2\TerminalServices'
		}
		
		$TSSetting = (Get-WmiObject -Class Win32_TerminalServiceSetting  -Namespace $NameSpace).TerminalServerMode
		
		if (($TSSetting -ne $null) -and ($TSSetting -eq 1))
		{
			$RDSEnabled = $true
		}
	}
	return $RDSEnabled
}

#rule 1870 detect logic
if (isAffectedOSVersionFor1870)
{
	$1870InformationCollected = new-object PSObject
	$RootCauseName = "RC_KernelTagTokeKB982010"
	$PublicContent = "http://support.microsoft.com/kb/982010"
	$Verbosity = "Error"
	$Visibility = "4"
	
	#Detect root cause 
	if(isWindowsUpdateAccessEnabled -and (checkTagProcessInfo -TagName "Toke" -InformationCollected $1870InformationCollected))
	{	
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $1870InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_KernelTagTokeKB982010_SD
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 3297 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 3297

Function isAffectedOSVersionFor3297
{
	if(($OSVersion.Build -eq 7600) -or ($OSVersion.Build -eq 7601)) #Win7/Server 2008 R2 SP0,SP1
	{
		return $true
	}
	else
	{
		return $false
	}
}

#rule 3297 detect logic
if (isAffectedOSVersionFor3297)
{
	$RdbssfilePath = "$Env:windir\system32\drivers\Rdbss.sys"	
	$3297InformationCollected = new-object PSObject
	$RootCauseName = "RC_KernelTagRxM4SeTIKB2647452"
	$PublicContent = "http://support.microsoft.com/kb/2647452"
	$Verbosity = "Error"
	$Visibility = "4"
	
	$currentVersion = Get-FileVersionString($RdbssfilePath)
	if(($OSVersion.Build) -eq 7600)
	{
		$requiredVersion = "6.1.7600.21095"
		$CheckHotFix2647452 = CheckMinimalFileVersion $RdbssfilePath 6 1 7600 21095
	}
	else
	{
		$requiredVersion = "6.1.7601.21864"
		$CheckHotFix2647452 = CheckMinimalFileVersion $RdbssfilePath 6 1 7601 21864
	}
	
	#Detect root cause 
	if (-not($CheckHotFix2647452))
	{	
		$CheckRxM4 = checkTagProcessInfo -TagName "RxM4" -InformationCollected $3297InformationCollected
		$CheckSeTI = checkTagProcessInfo -TagName "SeTI" -InformationCollected $3297InformationCollected
		
		if($CheckRxM4 -or $CheckSeTI)
		{
			add-member -inputobject $3297InformationCollected -membertype noteproperty -name "Current Rdbss.sys version" -value $currentVersion
			add-member -inputobject $3297InformationCollected -membertype noteproperty -name "Required Rdbss.sys version" -value $requiredVersion
	
			# Red/ Yellow Light
			Update-DiagRootCause -id $RootCauseName -Detected $true
			Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $3297InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_KernelTagRxM4SeTIKB2647452_SD
		}
		else
		{
			Update-DiagRootCause -id $RootCauseName -Detected $false
		}
	}	
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}	

#endregion

#region rule 2527 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 2527

Function isAffectedOSVersionFor2527
{
	if($OSVersion.Build -eq 6002) #Server 2008 SP2
	{
		return $true
	}
	else
	{
		return $false
	}
}

#rule 2527 detect logic
if (isAffectedOSVersionFor2527)
{
	$KsecddfilePath = "$Env:windir\system32\drivers\Ksecdd.sys"
	$2527InformationCollected = new-object PSObject
	$RootCauseName = "RC_KernelTagSslCKB2585542"
	$PublicContent = "http://support.microsoft.com/kb/2585542"
	$Verbosity = "Error"
	$Visibility = "4"
	
	$currentVersionInfo = getFileVersionInfo($KsecddfilePath)
	if($currentVersionInfo -ne $null)
	{
		$currentVersion = Get-FileVersionString($KsecddfilePath)
	}	
	
	switch($currentVersionInfo.FilePrivatePart.ToString().Remove(2))
	{
		"18" {
				$requiredVersion = "6.0.6002.18541"
				$CheckHotFix2585542 = CheckMinimalFileVersion $KsecddfilePath 6 0 6002 18541 -LDRGDR
			 }
		"22" {
		        $requiredVersion = "6.0.6002.22742"
				$CheckHotFix2585542 = CheckMinimalFileVersion $KsecddfilePath 6 0 6002 22742 -LDRGDR
			 }
	}
		
	#Detect root cause 
	if (-not($CheckHotFix2585542) -and (checkTagProcessInfo -TagName "SslC" -InformationCollected $2527InformationCollected))
	{		
		add-member -inputobject $2527InformationCollected -membertype noteproperty -name "Current Ksecdd.sys version" -value $currentVersion
		add-member -inputobject $2527InformationCollected -membertype noteproperty -name "Required Ksecdd.sys version" -value $requiredVersion
	
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $2527InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_KernelTagSslCKB2585542_SD
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 4631 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 4631

# Check if it is a Failovercluster
# - To detect a Failovercluster, just check if HKLM:\Cluster exists
Function IsCluster
{
	$ClusterKeyName = "HKLM:\Cluster"
	if (Test-Path -Path $ClusterKeyName) 
	{
		return $true
	}
	else
	{
		return $false
	}
}

#check the Mpio service is running
Function IsMpioRunning
{
	$MpioRegistryPath = "HKLM:\System\CurrentControlSet\Services\Mpio"
	if(Test-Path $MpioRegistryPath)
	{
		if((Get-ItemProperty ($MpioRegistryPath)).Start -eq 0)
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	else
	{
		return $false
	}
}

Function isAffectedOSVersionFor4631
{
	if(($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2) -and (IsCluster) -and (IsMpioRunning)) #Server 2003 with Failovercluster and Mpio service is running
	{		
		return $true
	}
	else
	{
		return $false
	}
}

#rule 4631 detect logic
if (isAffectedOSVersionFor4631)
{
	$4631InformationCollected = new-object PSObject
	$RootCauseName = "RC_MPIO2K3Check"
	$PublicContent = "http://support.microsoft.com/kb/961640"
	$Verbosity = "Warning"
	$Visibility = "4"
	
	$MpioRegistryImagePath = (Get-ItemProperty ("HKLM:\System\CurrentControlSet\Services\Mpio")).ImagePath
	if($MpioRegistryImagePath -ne $null)
	{
		$MpiofilePath = join-path $env:windir "$MpioRegistryImagePath"
	}
	else
	{
		$MpiofilePath = join-path $env:windir "system32\drivers\mpio.sys"
	}
	
	#Detect root cause 
	if (-not(CheckMinimalFileVersion $MpiofilePath 1 23 -ForceMinorCheck))
	{		
		$currentVersion = Get-FileVersionString($MpiofilePath)	
		$requiredVersion = "1.23"
		if(-not(checkTagProcessInfo -TagName "Mpio" -InformationCollected $4631InformationCollected -NonPagedPoolCheck))
		{
			add-member -inputobject $4631InformationCollected -membertype noteproperty -name "MPIO Pool Memory usage" -Value $null
		}
		add-member -inputobject $4631InformationCollected -membertype noteproperty -name "Current Mpio.sys version" -value $currentVersion
		add-member -inputobject $4631InformationCollected -membertype noteproperty -name "Required Mpio.sys version" -value $requiredVersion
	
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $4631InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_MPIO2K3Check_ST
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 4062 and 5769 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 4062

$script:BaspfilePath = join-path $env:windir "system32\drivers\Basp.sys"

Function isAffectedOSVersionFor4062
{
	if((($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1)) -and  #Windows Server 2008 R2
	   (isServerMedia)) #Server Media
	{	
		if(Test-Path $script:BaspfilePath) #check BASP.SYS present on the system
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	else
	{
		return $false
	}
}

#rule 4062,5769 detect logic
if (isAffectedOSVersionFor4062)
{
	$4062InformationCollected = new-object PSObject
	$RootCauseName = "RC_BASPNPPLeakCheck"
	$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=B;EN-US;2211813"
	$Verbosity = "Error"
	$Visibility = "4"
	
	#Detect root cause 
	if (-not(CheckMinimalFileVersion $script:BaspfilePath 1 3 23 0 ) -and (checkTagProcessInfo -TagName "Blfp" -InformationCollected $4062InformationCollected -NonPagedPoolCheck))
	{	
		$currentVersion = Get-FileVersionString($script:BaspfilePath)
		
		add-member -inputobject $4062InformationCollected -membertype noteproperty -name "Current Basp.sys version" -value $currentVersion
	
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -InternalContentURL $InternalContent -InformationCollected $4062InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_BASPNPPLeakCheck_ST
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 4061 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 4061

Function isAffectedOSVersionFor4061
{
	if((($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)) -or #Server 2003
	   (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 0)) -or #Server 2008
	   (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1))) #Windows Server 2008 R2 
	{	
		if(($OSArchitecture -like "*64*") -and (isServerMedia)) #check the OS is X64 version and is Server Media
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	else
	{
		return $false
	}
}

#rule 4061 detect logic
if (isAffectedOSVersionFor4061)
{
	$4061InformationCollected = new-object PSObject
	$RootCauseName = "RC_AladdinDeviceDriversCheck"
	$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=B;EN-US;2461230"
	$Verbosity = "Error"
	$Visibility = "4"
	$HardlockfilePath = join-path $env:windir "system32\drivers\Hardlock.sys"
	$AksdffilePath = join-path $env:windir "system32\drivers\Aksdf.sys"
	
	$HardlockFileVersionInfo = getFileVersionInfo($HardlockfilePath)
	if($HardlockFileVersionInfo -ne $null)
	{
		$HardlockcurrentVersion = Get-FileVersionString($HardlockfilePath)
	}
		
	$AksdfFileVersionInfo = getFileVersionInfo($AksdffilePath)
	if($AksdfFileVersionInfo -ne $null)
	{
		$AksdfcurrentVersion = Get-FileVersionString($AksdffilePath)
	}
	
	#Detect root cause 
	if ((($HardlockFileVersionInfo.FileMajorPart -eq 3 ) -and ($HardlockFileVersionInfo.FileMinorPart -eq 42 )) -and (($AksdfFileVersionInfo.FileMajorPart -eq 1 ) -and ($AksdfFileVersionInfo.FileMinorPart -eq 11 )))
	{				
		if($script:NonPagePool.ContainsKey("Proc"))
		{
			add-member -inputobject $4061InformationCollected -membertype noteproperty -name "Proc Kernel Tag Current Usage" -value (FormatBytes -bytes $script:NonPagePool["Proc"] -precision 2)
		}
		
		if($script:NonPagePool.ContainsKey("Toke"))
		{
			add-member -inputobject $4061InformationCollected -membertype noteproperty -name "Toke Kernel Tag Current Usage" -value (FormatBytes -bytes $script:NonPagePool["Toke"] -precision 2)
		}
		
		add-member -inputobject $4061InformationCollected -membertype noteproperty -name "Current Hardlock.sys version" -value $HardlockcurrentVersion
		add-member -inputobject $4061InformationCollected -membertype noteproperty -name "Current Aksdf.sys version" -value $AksdfcurrentVersion
	
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -InternalContentURL $InternalContent -InformationCollected $4061InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_AladdinDeviceDriversCheck_ST
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 6296 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 6296

Function isAffectedOSVersionFor6296
{
	return (($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)) #Win Server 2003 
}

#rule 6296 detect logic
if (isAffectedOSVersionFor6296)
{
	$6296InformationCollected = new-object PSObject
	$RootCauseName = "RC_MemoryLeakInMountmgrCheck"
	$MountmgrfilePath = "$Env:windir\system32\drivers\Mountmgr.sys"

	$MountmgrCurrentVersionInfo = getFileVersionInfo($MountmgrfilePath)
	if($MountmgrCurrentVersionInfo -ne $null)
	{
		$MountmgrCurrentVersion = Get-FileVersionString($MountmgrfilePath)
		switch($MountmgrCurrentVersionInfo.FilePrivatePart.ToString().Remove(1))
		{
			"2" {
					$MountmgrRequiredVersion = "5.2.3790.2979"
					$CheckHotFix940307 = CheckMinimalFileVersion $MountmgrfilePath 5 2 3790 2979
				}
			"4" {
			       $MountmgrRequiredVersion = "5.2.3790.4121"
					$CheckHotFix940307 = CheckMinimalFileVersion $MountmgrfilePath 5 2 3790 4121
				}
		}
	}	

	#Detect root cause 
	if (-not($CheckHotFix940307) -and (checkTagProcessInfo -TagName "MntA" -InformationCollected $6296InformationCollected -Top 10))
	{		
		add-member -inputobject $6296InformationCollected -membertype noteproperty -name "Current Mountmgr.sys version" -value $MountmgrCurrentVersion
		add-member -inputobject $6296InformationCollected -membertype noteproperty -name "Required Mountmgr.sys version" -value $MountmgrRequiredVersion

		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Add-GenericMessage -Id $RootCauseName -InformationCollected $6296InformationCollected
	}
	else
	{
		# Green Light
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 6911 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 6911

Function isAffectedOSVersionFor6911
{
	return (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1)) #Windows 7 or Windows Server 2008 R2
}

#rule 6911 detect logic
if (isAffectedOSVersionFor6911)
{
	$6911InformationCollected = new-object PSObject
	$RootCauseName = "RC_ALPCandPowerManagementPoolCheck"
	
	#Detect root cause 
	if ((checkTagProcessInfo -TagName "AlMs" -InformationCollected $6911InformationCollected -Top 10) -and (checkTagProcessInfo -TagName "Powe" -InformationCollected $6911InformationCollected -Top 10 -NonPagedPoolCheck))
	{		
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Add-GenericMessage -Id $RootCauseName -InformationCollected $6911InformationCollected
	}
	else
	{
		# Green Light
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 8267 related function and detect logic

Function isAffectedOSVersionFor8267 ($AdditionalFileToCheck)
{	
	$FileExists = Test-Path $AdditionalFileToCheck
	return (($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2) -and $FileExists) #Windows Server 2003 and WDICA file exists.
}

#rule 8267 detect logic
$WdicaFilePath = "$Env:windir\system32\drivers\WDICA.sys"
if (isAffectedOSVersionFor8267 -AdditionalFileToCheck $WdicaFilePath)
{
	Display-DefaultActivity -Rule -RuleNumber 8267
	
	$8267InformationCollected = new-object PSObject
	$RootCauseName = "RC_CitrixDriverCausedPagePoolMemoryLeak"	
	
	#Detect root cause 	
	$currentVersion = (Get-Item $WdicaFilePath).VersionInfo.ProductVersion
	if(($currentVersion -eq "4.5.4400.1") -and (checkTagProcessInfo -TagName "Ica" -InformationCollected $8267InformationCollected -NonPagedPoolCheck))
	{
		add-member -inputobject $8267InformationCollected -membertype noteproperty -name "Current WDICA.sys version" -value $currentVersion			
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Add-GenericMessage -Id $RootCauseName -InformationCollected $8267InformationCollected		
	}
	
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
	"$WdicaFilePath detected with version number $currentVersion" | WriteTo-StdOut
}

#endregion

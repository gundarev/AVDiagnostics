#************************************************
# TS_NTFSMetafilePerfCheck.ps1
# Version 1.0.1
# Date: 5/16/2012
# Author: v-maam
# Description:  [Idea ID 1911] [Windows] NTFS metafile cache consumes most of RAM in Win2k8R2 Server
# Rule number:  1911
# Rule URL:  //sharepoint/sites/rules/Rule%20Submissions/Forms/DispForm.aspx?ID=1911
#************************************************

Import-LocalizedData -BindingVariable ScriptStrings
Display-DefaultActivity -Rule -RuleNumber 1911

$RuleApplicable = $false
$RootCauseDetected = $false
$RootCauseName = "RC_NTFSMetafilePerfCheck"
$PublicCintent = "http://serverfault.com/questions/325277/windows-server-2008-r2-metafile-ram-usage"
$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=KB;EN-US;2635684"
$Verbosity = "Error"
$Visibility = "4"
$SupportTopicsID = "8116"
$InformationCollected = new-object PSObject

# ***************************
# Data Gathering
# ***************************

Function isAffectedOSVersion
{
	if(($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1))  #Win7/Server 2008 R2
	{
		return $true
	}
	else
	{
		return $false
	}
}

Function checkAvailableMemoryLessThan500MB($Available)
{

#		<#
#			.SYNOPSIS
#				Check performance counter Memory\Available Mbytes value is less than 500MB
#			.DESCRIPTION
#				Compare the Memory\Available Mbytes value with 500.
#			.NOTES
#			.LINK
#			.EXAMPLE
#			.OUTPUTS
#			.PARAMETER file
#		#>

	if($Available -lt 500*1024*1024)
	{
		return $true
	}
	else
	{
		return $false
	}	
}

Function checkSystemCacheResidentMemory($SystemCacheResident, $TotalVisibleMemory)
{

#		<#
#			.SYNOPSIS
#				Check if the Memory\System Cache Resident Bytes counter value is equal or greater than 50% of the TotalVisibleMemorySize 
#			.DESCRIPTION
#				Obtain the TotalVisibleMemorySize value, multiply the Memory\System Cache Resident Bytes counter by 2 and then compare with the TotalVisibleMemorySize value.
#			.NOTES
#			.LINK
#			.EXAMPLE
#			.OUTPUTS
#			.PARAMETER file
#		#>

	if(($SystemCacheResident*2) -ge $TotalVisibleMemory)
	{
		return $true
	}
	else
	{
		return $false
	}
}

# **************
# Detection Logic
# **************
#WriteTo-StdOut -Color Magenta -DebugOnly "Detection Logic"

#Check to see if rule is applicable to this computer
if (isAffectedOSVersion)
{
	$RuleApplicable = $true
	
	$TotalVisibleMemorySize = (Get-WmiObject Win32_OperatingSystem).TotalVisibleMemorySize*1024
	$AvailableMemory = Get-Counter "\\.\Memory\Available Bytes" | Foreach { $_.CounterSamples[0].CookedValue }
	$SystemCacheResidentMemory = Get-Counter "\\.\Memory\System Cache Resident Bytes" | Foreach { $_.CounterSamples[0].CookedValue }
	
	if(($TotalVisibleMemorySize -ne $null) -and ($Available -ne $null) -and ($SystemCacheResident -ne $null))
	{
		#Detect root cause 
		if (checkAvailableMemoryLessThan500MB($AvailableMemory) -and (checkSystemCacheResidentMemory -SystemCacheResident $SystemCacheResidentMemory -TotalVisibleMemory $TotalVisibleMemorySize))
		{
			$RootCauseDetected = $true	
			add-member -inputobject $InformationCollected -membertype noteproperty -name "Total Physical Memory" -value (FormatBytes -bytes $TotalVisibleMemorySize -precision 1)
			add-member -inputobject $InformationCollected -membertype noteproperty -name "Available Memory" -value (FormatBytes -bytes $AvailableMemory -precision 1)
			add-member -inputobject $InformationCollected -membertype noteproperty -name "System Cache Resident Memory" -value (FormatBytes -bytes $SystemCacheResidentMemory -precision 1)
		}
	}
}	
	

# *********************
# Root Cause processing
# *********************

if ($RuleApplicable)
{
	if ($RootCauseDetected)
	{
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicCintent -InternalContentURL $InternalContent -InformationCollected $InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_NTFSMetafilePerfCheck_SD
	}
	else
	{
		# Green Light
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}               

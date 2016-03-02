#************************************************
# TS_SBSL_MCAfee_EEPC_SlowBoot.ps1
# Version 1.0.1
# Date: 5/10/2012
# Author: v-maam
# Description:  [Idea ID 986] [Windows] SBSL McAfee Endpoint Encryption for PCs may cause slow boot or delay between CTRL+ALT+DEL and Cred
# Rule number:  986
# Rule URL:  //sharepoint/sites/rules/Rule%20Submissions/Forms/DispForm.aspx?ID=986
#************************************************

Import-LocalizedData -BindingVariable ScriptStrings
Display-DefaultActivity -Rule -RuleNumber 986

$RuleApplicable = $false
$RootCauseDetected = $false
$RootCauseName = "RC_SBSL_MCAfee_EEPC_SlowBoot"
$PublicContent = "https://kc.mcafee.com/corporate/index?page=content&id=KB72309&actp=LIST"
$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=B;EN-US;2584922"
$Verbosity = "Warning"
$Visibility = "4"
$SupportTopicsID = "7988"
$InformationCollected = new-object PSObject

# ***************************
# Data Gathering
# ***************************
$filePath = "$Env:ProgramFiles\McAfee\Endpoint Encryption for PC v6\EpePcCredentialProvider64.dll"

Function isAffectedOSVersion
{
	if($OSVersion.Major -ge 6) #Win8
	{
		return $true
	}
	else
	{
		return $false
	}
}


Function isIssueFileVersion
{
	if(Test-Path $filePath)
	{
		[string]$global:fileVersion = Get-FileVersionString($filePath)
		$fileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($filePath)
		if($fileVersionInfo.FileMajorPart -eq 6 )
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


# **************
# Detection Logic
# **************
#WriteTo-StdOut -Color Magenta -DebugOnly "Detection Logic"


#Check to see if rule is applicable to this computer
if (isAffectedOSVersion)
{
	$RuleApplicable = $true

	#Detect root cause 
	if (isIssueFileVersion)
	{
		$RootCauseDetected = $true	
		#add-member -inputobject $InformationCollected -membertype noteproperty -name "information collected name" -value $Value
		add-member -inputobject $InformationCollected -membertype noteproperty -name "McAfee Endpoint Encryption file path" -value $filePath
		add-member -inputobject $InformationCollected -membertype noteproperty -name "Current McAfee Endpoint Encryption file version" -value $fileVersion
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
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_SBSL_MCAfee_EEPC_SlowBoot_SD
	}
	else
	{
		# Green Light
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

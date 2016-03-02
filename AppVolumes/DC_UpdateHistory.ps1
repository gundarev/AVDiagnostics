#************************************************
# UpdateHistory.ps1
# Version 1.0.1
# Date: 7/2/2013
# Author: v-maam
# Description:  This file will list all updates installed on the local machine
#************************************************
Param($Prefix = '', $Suffix = '', $OutputFormats= @("TXT", "CSV", "HTM"), [int]$NumberOfDays=10, [Switch]$ExportOnly)

trap
{		
	WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[UpdateHistory.ps1] error"
	continue
}

Import-LocalizedData -BindingVariable ScriptStrings

# ***************************
# Store the updates history output information in CSV, TXT, XML format
# ***************************

$Script:SbCSVFormat = New-Object -TypeName System.Text.StringBuilder
$Script:SbTXTFormat = New-Object -TypeName System.Text.StringBuilder
$Script:SbXMLFormat = New-Object -TypeName System.Text.StringBuilder

# Store the WU errors
$Script:WUErrors

# Store the Updated installed in the past $NumberOfDays days when $ExportOnly is not used
if($ExportOnly.IsPresent -eq $false)
{
	$LatestUpdates_Summary= New-Object PSObject
	$LatestUpdates_Summary | Add-Member -MemberType NoteProperty -Name "  Date" -Value ("<table><tr><td width=`"40px`" style=`"border-bottom:1px solid #CCCCCC`">Results</td><td width=`"60px`" style=`"border-bottom:1px solid #CCCCCC`">ID</td><td width=`"300px`" style=`"border-bottom:1px solid #CCCCCC`">Category</td></tr></table>")
	[int]$Script:LatestUpdateCount = 0
}

# ***************************
# Functions
# ***************************

Function GetHotFixFromRegistry
{
	$RegistryHotFixList = @{}
	$UpdateRegistryKeys = @("HKLM:\SOFTWARE\Microsoft\Updates")

	#if $OSArchitecture -ne X86 , should be 64-bit machine. we also need to check HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates
	if($OSArchitecture -ne "X86")
	{
		$UpdateRegistryKeys += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates"
	}
						  						 	
	foreach($RegistryKey in $UpdateRegistryKeys)
	{
		If(Test-Path $RegistryKey)
		{
			$AllProducts = Get-ChildItem $RegistryKey -Recurse | Where-Object {$_.Name.Contains("KB") -or $_.Name.Contains("Q")}

			foreach($subKey in $AllProducts)
			{
				if($subKey.Name.Contains("KB") -or $subKey.Name.Contains("Q"))
				{
					$HotFixID = GetHotFixID $subKey.Name
					if($RegistryHotFixList.Keys -notcontains $HotFixID)
					{
						$Category = [regex]::Match($subKey.Name,"Updates\\(?<Category>.*?)[\\]").Groups["Category"].Value
						$HotFix = @{HotFixID=$HotFixID;Category=$Category}				
						foreach($property in $subKey.Property)
						{
							$HotFix.Add($property,$subKey.GetValue($property))
						}
						$RegistryHotFixList.Add($HotFixID,$HotFix)
					}
				}
			}
		}
	}
	return $RegistryHotFixList
}

Function GetHotFixID($strContainID)
{
	return [System.Text.RegularExpressions.Regex]::Match($strContainID,"(KB|Q)\d+(v\d)?").Value
}

Function ToNumber($strHotFixID)
{
	return [System.Text.RegularExpressions.Regex]::Match($strHotFixID,"([0-9])+").Value
}

Function FormatStr([string]$strValue,[int]$NumberofChars)
{
	if([String]::IsNullOrEmpty($strValue))
	{
		$strValue = " "
		return $strValue.PadRight($NumberofChars," ")
	}
	else
	{
		if($strValue.Length -lt $NumberofChars)
		{
			return $strValue.PadRight($NumberofChars," ")
		}
		else
		{
			return $strValue.Substring(0,$NumberofChars)
		}
	}
}

# Make sure all dates are with dd/mm/yy hh:mm:ss
Function FormatDateTime($dtLocalDateTime,[Switch]$SortFormat)
{	
	trap
	{		
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[FormatDateTime] Error Convert date time"
		continue
	}

	if([string]::IsNullOrEmpty($dtLocalDateTime))
	{
		return ""
	}
	
	if($SortFormat.IsPresent)
	{
		# Obtain dates on yyyymmdddhhmmss
		return Get-Date -Date $dtLocalDateTime -Format "yyyyMMddHHmmss"
	}
	else
	{
		return Get-Date -Date $dtLocalDateTime -Format G
	}
}

Function ValidatingDateTime($dateTimeToValidate)
{
	trap
	{		
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[ValidateDateTime] Error"
		continue
	}

	if([String]::IsNullOrEmpty($dateTimeToValidate))
	{
		return $false
	}

	$ConvertedDateTime = Get-Date -Date $dateTimeToValidate

	if($ConvertedDateTime -ne $null)
	{
		if(((Get-Date) - $ConvertedDateTime).Days -le $NumberOfDays)
		{
			return $true
		}
	}

	return $false
}

Function GetUpdateResultString($OperationResult)
{
	switch ($OperationResult)
	{
		"Completed successfully"  {return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group id=`"Inf1`" class=`"vmlimage`" style=`"width:15px;height:15px;vertical-align:middle`" coordsize=`"100,100`" title=`"Completed successfully`"><v:oval class=`"vmlimage`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#009933`" strokecolor=`"#C0C0C0`" /></v:group></span>"}
		"In progress"  {return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:14px;height:14px;vertical-align:middle`" coordsize=`"100,100`" title=`"In progress`"><v:roundrect class=`"vmlimage`" arcsize=`"10`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#00FF00`" strokecolor=`"#C0C0C0`" /><v:shape class=`"vmlimage`" style=`"width:100; height:100; z-index:0`" fillcolor=`"white`" strokecolor=`"white`"><v:path v=`"m 40,25 l 75,50 40,75 x e`" /></v:shape></v:group></span>"}
		"Operation was aborted"  {return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:15px;height:15px;vertical-align:middle`" coordsize=`"100,100`" title=`"Operation was aborted`"><v:roundrect class=`"vmlimage`" arcsize=`"20`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#290000`" strokecolor=`"#C0C0C0`" /><v:line class=`"vmlimage`" style=`"z-index:2`" from=`"52,30`" to=`"52,75`" strokecolor=`"white`" strokeweight=`"8px`" /></v:group></span>"}
		"Completed with errors"  {return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:15px;height:15px;vertical-align:middle`" coordsize=`"100,100`" title=`"Completed with errors`"><v:shape class=`"vmlimage`" style=`"width:100; height:100; z-index:0`" fillcolor=`"yellow`" strokecolor=`"#C0C0C0`"><v:path v=`"m 50,0 l 0,99 99,99 x e`" /></v:shape><v:rect class=`"vmlimage`" style=`"top:35; left:45; width:10; height:35; z-index:1`" fillcolor=`"black`" strokecolor=`"black`"></v:rect><v:rect class=`"vmlimage`" style=`"top:85; left:45; width:10; height:5; z-index:1`" fillcolor=`"black`" strokecolor=`"black`"></v:rect></v:group></span>"}
		"Failed to complete"  {return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:15px;height:15px;vertical-align:middle`" coordsize=`"100,100`" title=`"Failed to complete`"><v:oval class=`"vmlimage`" style=`"width:100;height:100;z-index:0`" fillcolor=`"red`" strokecolor=`"#C0C0C0`"></v:oval><v:line class=`"vmlimage`" style=`"z-index:1`" from=`"25,25`" to=`"75,75`" strokecolor=`"white`" strokeweight=`"3px`"></v:line><v:line class=`"vmlimage`" style=`"z-index:2`" from=`"75,25`" to=`"25,75`" strokecolor=`"white`" strokeweight=`"3px`"></v:line></v:group></span>"}
		Default { return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group id=`"Inf1`" class=`"vmlimage`" style=`"width:15px;height:15px;vertical-align:middle`" coordsize=`"100,100`" title=`"{$OperationResult}`"><v:oval class=`"vmlimage`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#FF9933`" strokecolor=`"#C0C0C0`" /></v:group></span>" }
	}
}

Function GetOSSKU($SKU)
{
	switch ($SKU)
	{
		0  {return ""}
		1  {return "Ultimate Edition"}
		2  {return "Home Basic Edition"}
		3  {return "Home Basic Premium Edition"}
		4  {return "Enterprise Edition"}
		5  {return "Home Basic N Edition"}
		6  {return "Business Edition"}
		7  {return "Standard Server Edition"}
		8  {return "Datacenter Server Edition"}
		9  {return "Small Business Server Edition"}
		10 {return "Enterprise Server Edition"}
		11 {return "Starter Edition"}
		12 {return "Datacenter Server Core Edition"}
		13 {return "Standard Server Core Edition"}
		14 {return "Enterprise Server Core Edition"}
		15 {return "Enterprise Server Edition for Itanium-Based Systems"}
		16 {return "Business N Edition"}
		17 {return "Web Server Edition"}
		18 {return "Cluster Server Edition"}
		19 {return "Home Server Edition"}
		20 {return "Storage Express Server Edition"}
		21 {return "Storage Standard Server Edition"}
		22 {return "Storage Workgroup Server Edition"}
		23 {return "Storage Enterprise Server Edition"}
		24 {return "Server For Small Business Edition"}
		25 {return "Small Business Server Premium Edition"}	
	}	
}

Function GetOS()
{
	$WMIOS = Get-WmiObject -Class Win32_OperatingSystem

	$StringOS = $WMIOS.Caption

	if($WMIOS.CSDVersion -ne $null)
	{
		$StringOS += " - " + $WMIOS.CSDVersion
	}
	else
	{
		$StringOS += " - Service Pack not installed"
	}

	if(($WMIOS.OperatingSystemSKU -ne $null) -and ($WMIOS.OperatingSystemSKU.ToString().Length -gt 0))
	{
		$StringOS += " ("+(GetOSSKU $WMIOS.OperatingSystemSKU)+")"
	}

	return $StringOS
}

# Query SID of an object using WMI and return the account name
Function ConvertSIDToUser([string]$strSID) 
{
	trap
	{		
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[ConvertSIDToUser] Error convert User SID to User Account"
		continue
	}
	
	if([string]::IsNullOrEmpty($strSID))
	{
		return
	}

	if($strSID.StartsWith("S-1-5"))
	{
		$UserSIDIdentifier = New-Object System.Security.Principal.SecurityIdentifier `
    	($strSID)
		$UserNTAccount = $UserSIDIdentifier.Translate( [System.Security.Principal.NTAccount])
		if($UserNTAccount.Value.Length -gt 0)
		{
			return $UserNTAccount.Value
		}
		else
		{
			return $strSID
		}
	}
	
	return $strSID	
}

Function ConvertToHex([int]$number)
{
	return ("0x{0:x8}" -f $number)
}

Function GetUpdateOperation($Operation)
{
	switch ($Operation)
	{
		1 { return "Install" }
		2 { return "Uninstall" }
		Default { return "Unknown("+$Operation+")" }
	}
}

Function GetUpdateResult($ResultCode)
{
	switch ($ResultCode)
	{
		0 { return "Not started" }
		1 { return "In progress" }
		2 { return "Completed successfully" }
		3 { return "Completed with errors" }
		4 { return "Failed to complete" }
		5 { return "Operation was aborted" }
		Default { return "Unknown("+$ResultCode+")" }
	}					
}

Function GetWUErrorCodes($HResult)
{
	if($Script:WUErrors -eq $null)
	{
		$WUErrorsFilePath = Join-Path $PWD.Path "WUErrors.xml"
		if(Test-Path $WUErrorsFilePath)
		{
			[xml] $Script:WUErrors = Get-Content $WUErrorsFilePath
		}
		else
		{
			"[Error]: Did not find the WUErrors.xml file, can not load all WU errors" | WriteTo-StdOut -ShortFormat
		}
	}

	$WUErrorNode = $Script:WUErrors.ErrV1.err | Where-Object {$_.n -eq $HResult}

	if($WUErrorNode -ne $null)
	{
		$WUErrorCode = @()
		$WUErrorCode += $WUErrorNode.name
		$WUErrorCode += $WUErrorNode."#text"
		return $WUErrorCode
	}

	return $null
}

Function PrintHeaderOrXMLFooter([switch]$IsHeader,[switch]$IsXMLFooter)
{
	if($IsHeader.IsPresent)
	{
		if($OutputFormats -contains "TXT")
		{
			# TXT formate Header
			LineOut -IsTXTFormat -Value ([String]::Format("{0} {1} {2} {3} {4} {5} {6} {7} {8}",
												(FormatStr "Category" 20),
												(FormatStr "Level" 6),
												(FormatStr "ID" 10),
												(FormatStr "Operation" 11),
												(FormatStr "Date" 23),
												(FormatStr "Client" 18),
												(FormatStr "By" 28),
												(FormatStr "Result" 23),
												"Title"))																								
			LineOut -IsTXTFormat -Value ("-").PadRight(200,"-")
		}

		if($OutputFormats -contains "CSV")
		{
			# CSV formate Header										
			LineOut -IsCSVFormat -Value ("Category,Level,ID,Operation,Date,Client,By,Result,Title")
		}

		if($OutputFormats -contains "HTM")
		{
			# XML format Header
			LineOut -IsXMLFormat -IsXMLLine -Value "<?xml version=`"1.0`" encoding=`"UTF-8`"?>"
			LineOut -IsXMLFormat -IsOpenTag -TagName "Root"
			LineOut -IsXMLFormat -IsOpenTag -TagName "Updates"
			LineOut -IsXMLFormat -IsXMLLine -Value ("<Title name=`"QFE Information from`">"+$Env:COMPUTERNAME+"</Title>")
			LineOut -IsXMLFormat -IsXMLLine -Value ("<OSVersion name=`"Operating System`">"+(GetOS)+"</OSVersion>")
			LineOut -IsXMLFormat -IsXMLLine -Value ("<TimeField name=`"Local time`">"+[DateTime]::Now.ToString()+"</TimeField>")
		}
	}
	
	if($IsXMLFooter)
	{
		if($OutputFormats -contains "HTM")
		{
			LineOut -IsXMLFormat -IsCloseTag -TagName "Updates"
			LineOut -IsXMLFormat -IsCloseTag -TagName "Root"
		}		
	}
}

Function LineOut([string]$TagName,[string]$Value,[switch]$IsTXTFormat,[switch]$IsCSVFormat,[switch]$IsXMLFormat,[switch]$IsXMLLine,[switch]$IsOpenTag,[switch]$IsCloseTag)
{
	if($IsTXTFormat.IsPresent)
	{		
		[void]$Script:SbTXTFormat.AppendLine($Value)
	}
	
	if($IsCSVFormat.IsPresent)
	{
		[void]$Script:SbCSVFormat.AppendLine($Value)
	}
	
	if($IsXMLFormat.IsPresent)
	{
		if($IsXMLLine.IsPresent)
		{
			[void]$Script:SbXMLFormat.AppendLine($Value)
			return
		}
		
		if(($TagName -eq $null) -or ($TagName -eq ""))
		{
			"[Warning]: Did not provide valid TagName: $TagName, will not add this Tag." | WriteTo-StdOut -ShortFormat
			return
		}
		
		if($IsOpenTag.IsPresent -or $IsCloseTag.IsPresent)
		{
			if($IsOpenTag.IsPresent)
			{
				[void]$Script:SbXMLFormat.AppendLine("<"+$TagName+">")
			}
	
			if($IsCloseTag.IsPresent)
			{
				[void]$Script:SbXMLFormat.AppendLine("</"+$TagName+">")
			}
		}
		else
		{
			[void]$Script:SbXMLFormat.AppendLine("<"+$TagName+">"+$Value+"</"+$TagName+">")
		}
	}
}

Function PrintUpdate([string]$Category,[string]$SPLevel,[string]$ID,[string]$Operation,[string]$Date,[string]$ClientID,[string]$InstalledBy,[string]$OperationResult,[string]$Title,[string]$Description,[string]$HResult,[string]$UnmappedResultCode)
{
	if($OutputFormats -contains "TXT")
	{
		LineOut -IsTXTFormat -Value ([String]::Format("{0} {1} {2} {3} {4} {5} {6} {7} {8}",
												(FormatStr $Category 20),
												(FormatStr $SPLevel 6),
												(FormatStr $ID 10),
												(FormatStr $Operation 11),
												(FormatStr $Date 23),
												(FormatStr $ClientID 18),
												(FormatStr $InstalledBy 28),
												(FormatStr $OperationResult 23),
												$Title))
	}

	if($OutputFormats -contains "CSV")
	{
		LineOut -IsCSVFormat -Value ([String]::Format("{0},{1},{2},{3},{4},{5},{6},{7},{8}",
												  $Category,
												  $SPLevel,
												  $ID,
												  $Operation,
												  $Date,
												  $ClientID,
												  $InstalledBy,
												  $OperationResult,
												  $Title))
	}

	if($OutputFormats -contains "HTM")
	{	
		if($Category -eq "QFE hotfix")
		{
			$Category = "Other updates not listed in history"
		}
		
		if(-not [String]::IsNullOrEmpty($ID))
		{
			$NumberHotFixID = ToNumber $ID
			if($NumberHotFixID.Length -gt 5)
			{
				$SupportLink = "http://support.microsoft.com/kb/$NumberHotFixID"				
			}
		}
		else
		{
			$ID = ""
			$SupportLink = ""
		}	

		if([String]::IsNullOrEmpty($Date))
		{
			$DateTime = ""
		}
		else
		{
			$DateTime = FormatDateTime $Date -SortFormat			
		}

		if([String]::IsNullOrEmpty($Title))
		{
			$Title = ""
		}
		else
		{
			$Title = $Title.Trim()
		}

		if([String]::IsNullOrEmpty($Description))
		{
			$Description = ""
		}
		else
		{
			$Description = $Description.Trim()			
		}

		# Write the Update to XML Formate
		LineOut -IsXMLFormat -TagName "Update" -IsOpenTag
		LineOut -IsXMLFormat -TagName "Category" -Value $Category
		if(-not [String]::IsNullOrEmpty($SPLevel))
		{
			LineOut -IsXMLFormat -TagName "SPLevel" -Value $SPLevel
		}
		LineOut -IsXMLFormat -TagName "ID" -Value $ID
		LineOut -IsXMLFormat -TagName "SupportLink" -Value $SupportLink
		LineOut -IsXMLFormat -TagName "Operation" -Value $Operation
		LineOut -IsXMLFormat -TagName "Date" -Value $Date
		LineOut -IsXMLFormat -TagName "SortableDate" -Value $DateTime
		LineOut -IsXMLFormat -TagName "ClientID" -Value $ClientID
		LineOut -IsXMLFormat -TagName "InstalledBy" -Value $InstalledBy
		LineOut -IsXMLFormat -TagName "OperationResult" -Value $OperationResult
		LineOut -IsXMLFormat -TagName "Title" -Value $Title
		LineOut -IsXMLFormat -TagName "Description" -Value $Description

		if((-not [String]::IsNullOrEmpty($HResult)) -and ($HResult -ne 0))
		{
			$HResultHex = ConvertToHex $HResult
			$HResultArray= GetWUErrorCodes $HResultHex
					
			LineOut -IsXMLFormat -IsOpenTag -TagName "HResult"
			LineOut -IsXMLFormat -TagName "HEX" -Value $HResultHex
			if($HResultArray -ne $null)
			{
				LineOut -IsXMLFormat -TagName "Constant" -Value $HResultArray[0]
				LineOut -IsXMLFormat -TagName "Description" -Value $HResultArray[1]
			}
			LineOut -IsXMLFormat -IsCloseTag -TagName "HResult"
			LineOut -IsXMLFormat -TagName "UnmappedResultCode" -Value (ConvertToHex $UnmappedResultCode)
		}

		LineOut -IsXMLFormat -TagName "Update" -IsCloseTag


		if (($ExportOnly.IsPresent -eq $false) -and (ValidatingDateTime $Date))
		{	
			if($LatestUpdates_Summary.$Date -ne $null)	
			{	
				$LatestUpdates_Summary.$Date = $LatestUpdates_Summary.$Date.Insert($LatestUpdates_Summary.$Date.LastIndexOf("</table>"),"<tr><td width=`"40px`" align=`"center`">" +(GetUpdateResultString $OperationResult) + "</td><td width=`"60px`"><a href=`"$SupportLink`" Target=`"_blank`">$ID</a></td><td>$Category</td></tr>")
			}
			else
			{
				$LatestUpdates_Summary | Add-Member -MemberType NoteProperty -Name $Date -Value ("<table><tr><td width=`"40px`" align=`"center`">" +(GetUpdateResultString $OperationResult) + "</td><td width=`"60px`"><a href=`"$SupportLink`" Target=`"_blank`">$ID</a></td><td>$($Category): $($Title)</td></tr></table>")	
			}
					
			$Script:LatestUpdateCount++
		}	
	}
}

Function GenerateHTMFile([string] $XMLFileNameWithoutExtension)
{
	trap
	{		
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[GenerateHTMFile] Error creating HTM file"
		continue
	}

	$UpdateXslFilePath = Join-Path $pwd.path "UpdateHistory.xsl"
	if(Test-Path $UpdateXslFilePath)
	{
		$XSLObject = New-Object System.Xml.Xsl.XslTransform
		$XSLObject.Load($UpdateXslFilePath)
		if(Test-Path ($XMLFileNameWithoutExtension + ".XML"))
		{
			$XSLObject.Transform(($XMLFileNameWithoutExtension + ".XML"), ($XMLFileNameWithoutExtension + ".HTM"))
		}
		else
		{
			"Error: HTML file was not generated" | WriteTo-StdOut -ShortFormat
		}
	}
	else
	{
		"Error: Did not find the UpdateHistory.xsl, won't generate HTM file" | WriteTo-StdOut -ShortFormat
	}
}

# ***************************
# Start here
# ***************************

Write-DiagProgress -Activity $ScriptStrings.ID_InstalledUpdates -Status $ScriptStrings.ID_InstalledUpdatesObtaining

# Get updates from the com object
"Querying IUpdateSession Interface to get the Update History" | WriteTo-StdOut -ShortFormat

$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$HistoryCount = $Searcher.GetTotalHistoryCount()
if ($HistoryCount -gt 0) 
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "Querying Update History"
		continue
	}

	$ComUpdateHistory = $Searcher.QueryHistory(1,$HistoryCount)
}
else
{
	$ComUpdateHistory = @()
	"No updates found on Microsoft.Update.Session" | WriteTo-StdOut -ShortFormat
}

# Get updates from the Wmi object Win32_QuickFixEngineering
"Querying Win32_QuickFixEngineering to obtain updates that are not on update history" | WriteTo-StdOut -ShortFormat

$QFEHotFixList = New-Object "System.Collections.ArrayList"
$QFEHotFixList.AddRange(@(Get-WmiObject -Class Win32_QuickFixEngineering))

# Get updates from the regsitry keys
"Querying Updates listed in the registry" | WriteTo-StdOut -ShortFormat
$RegistryHotFixList = GetHotFixFromRegistry

Write-DiagProgress -Activity $ScriptStrings.ID_InstalledUpdates -Status $ScriptStrings.ID_InstalledUpdatesFormateOutPut
PrintHeaderOrXMLFooter -IsHeader

# Format each update history to the stringbuilder
"Generating information for $HistoryCount updates found on update history" | WriteTo-StdOut -ShortFormat
foreach($updateEntry in $ComUpdateHistory)
{	
	#Do not list the updates on which the $updateEntry.ServiceID = '117CAB2D-82B1-4B5A-A08C-4D62DBEE7782'. These are Windows Store updates and are bringing inconsistent results
	if($updateEntry.ServiceID -ne '117CAB2D-82B1-4B5A-A08C-4D62DBEE7782')
	{		
		$HotFixID = GetHotFixID $updateEntry.Title
		$HotFixIDNumber = ToNumber $HotFixID
		$strInstalledBy = ""
		$strSPLevel = ""
	
		if(($HotFixID -ne "") -or ($HotFixIDNumber -ne ""))
		{
			foreach($QFEHotFix in $QFEHotFixList)
			{
				if(($QFEHotFix.HotFixID -eq $HotFixID) -or
		   			((ToNumber $QFEHotFix.HotFixID) -eq $HotFixIDNumber))
				{
					$strInstalledBy = ConvertSIDToUser $QFEHotFix.InstalledBy
					$strSPLevel = $QFEHotFix.ServicePackInEffect

					#Remove the duplicate HotFix in the QFEHotFixList
					$QFEHotFixList.Remove($QFEHotFix)
					break
				}
			}
		}
	
		#Remove the duplicate HotFix in the RegistryHotFixList
		if($RegistryHotFixList.Keys -contains $HotFixID)
		{
			$RegistryHotFixList.Remove($HotFixID)
		}

		$strCategory = ""		
		if($updateEntry.Categories.Count -gt 0)
		{
			$strCategory = $updateEntry.Categories.Item(0).Name
		}
	
		if([String]::IsNullOrEmpty($strCategory))
		{
			$strCategory = "(None)"
		}
	
		$strOperation = GetUpdateOperation $updateEntry.Operation
		$strDateTime = FormatDateTime $updateEntry.Date
		$strResult = GetUpdateResult $updateEntry.ResultCode

		PrintUpdate $strCategory $strSPLevel $HotFixID $strOperation $strDateTime $updateEntry.ClientApplicationID $strInstalledBy $strResult $updateEntry.Title $updateEntry.Description $updateEntry.HResult $updateEntry.UnmappedResultCode
	}
}

# Out Put the Non History QFEFixes
"Generating information for " + $QFEHotFixList.Count + " updates found on Win32_QuickFixEngineering WMI class" | WriteTo-StdOut -ShortFormat
foreach($QFEHotFix in $QFEHotFixList)
{
	$strInstalledBy = ConvertSIDToUser $QFEHotFix.InstalledBy
	$strDateTime = FormatDateTime $QFEHotFix.InstalledOn
	$strCategory = ""

	#Remove the duplicate HotFix in the RegistryHotFixList
	if($RegistryHotFixList.Keys -contains $QFEHotFix.HotFixID)
	{
		$strCategory = $RegistryHotFixList[$QFEHotFix.HotFixID].Category
		$strRegistryDateTime = FormatDateTime $RegistryHotFixList[$QFEHotFix.HotFixID].InstalledDate		
		if([String]::IsNullOrEmpty($strInstalledBy))
		{
			$strInstalledBy = $RegistryHotFixList[$QFEHotFix.HotFixID].InstalledBy
		}

		$RegistryHotFixList.Remove($QFEHotFix.HotFixID)
	}
	
	if([string]::IsNullOrEmpty($strCategory))
	{
		$strCategory = "QFE hotfix"
	}	
	if($strDateTime.Length -eq 0)
	{
		$strDateTime = $strRegistryDateTime
	}
	if([string]::IsNullOrEmpty($QFEHotFix.Status))
	{
		$strResult = "Completed successfully"
	}
	else
	{
		$strResult = $QFEHotFix.Status
	}	

	PrintUpdate $strCategory $QFEHotFix.ServicePackInEffect $QFEHotFix.HotFixID "Install" $strDateTime "" $strInstalledBy $strResult $QFEHotFix.Description $QFEHotFix.Caption
}

"Generating information for " + $RegistryHotFixList.Count + " updates found on registry" | WriteTo-StdOut -ShortFormat
foreach($key in $RegistryHotFixList.Keys)
{
	$strCategory = $RegistryHotFixList[$key].Category
	$HotFixID = $RegistryHotFixList[$key].HotFixID
	$strDateTime = $RegistryHotFixList[$key].InstalledDate
	$strInstalledBy = $RegistryHotFixList[$key].InstalledBy
	$ClientID = $RegistryHotFixList[$key].InstallerName

	if($HotFixID.StartsWith("Q"))
	{
		$Description = $RegistryHotFixList[$key].Description
	}
	else
	{
		$Description = $RegistryHotFixList[$key].PackageName		
	}

	if([string]::IsNullOrEmpty($Description))
	{
		$Description = $strCategory
	}

	PrintUpdate $strCategory "" $HotFixID "Install" $strDateTime $ClientID $strInstalledBy "Completed successfully" $strCategory $Description
}

PrintHeaderOrXMLFooter -IsXMLFooter

Write-DiagProgress -Activity $ScriptStrings.ID_InstalledUpdates -Status $ScriptStrings.ID_InstalledUpdatesOutPutAndCollectFile
$FileNameWithoutExtension = $ComputerName +"_"+ $Prefix + "Hotfixes" + $Suffix

"Creating output files" | WriteTo-StdOut -ShortFormat
if($OutputFormats -contains "CSV")
{
	$Script:SbCSVFormat.ToString() | Out-File ($FileNameWithoutExtension + ".CSV") -Encoding "UTF8"
}

if($OutputFormats -contains "TXT")
{
	$Script:SbTXTFormat.ToString() | Out-File ($FileNameWithoutExtension + ".TXT") -Encoding "UTF8"
}

if($OutputFormats -contains "HTM")
{
	$Script:SbXMLFormat.ToString().replace("&","") | Out-File ($FileNameWithoutExtension + ".XML") -Encoding "UTF8"

	"Generate the HTML Updates file according the UpdateHistory.xsl and XML file" | WriteTo-StdOut -ShortFormat
	GenerateHTMFile $FileNameWithoutExtension
}

$FileToCollects = @("$FileNameWithoutExtension.CSV","$FileNameWithoutExtension.TXT","$FileNameWithoutExtension.HTM")

if($ExportOnly.IsPresent)
{
	Copy-Item $FileToCollects -Destination (Join-Path $PWD.Path "result")
}
else
{
	if($Script:LatestUpdateCount -gt 0)
	{		
		$LatestUpdates_Summary | Add-Member -MemberType NoteProperty -Name "More Information" -Value ("<table><tr><td>For a complete list of installed updates, please open <a href= `"`#" + $FileNameWithoutExtension + ".HTM`">" + $FileNameWithoutExtension + ".HTM</a></td></tr></table>")
		$LatestUpdates_Summary | ConvertTo-Xml2 -sortObject | update-diagreport -id 11_Updates -name "Updates installed in past $NumberOfDays days ($($Script:LatestUpdateCount))" -verbosity informational
	}
	
	CollectFiles -filesToCollect $FileToCollects -fileDescription "Installed Updates and Hotfixes" -sectionDescription "General Information"
}

# SIG # Begin signature block
# MIIa9gYJKoZIhvcNAQcCoIIa5zCCGuMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJJAase+Ek348cGKezs1niXf+
# T4ygghWCMIIEwzCCA6ugAwIBAgITMwAAADPlJ4ajDkoqgAAAAAAAMzANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTMwMzI3MjAwODIz
# WhcNMTQwNjI3MjAwODIzWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkY1MjgtMzc3Ny04QTc2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyt7KGQ8fllaC
# X9hCMtQIbbadwMLtfDirWDOta4FQuIghCl2vly2QWsfDLrJM1GN0WP3fxYlU0AvM
# /ZyEEXmsoyEibTPgrt4lQEWSTg1jCCuLN91PB2rcKs8QWo9XXZ09+hdjAsZwPrsi
# 7Vux9zK65HG8ef/4y+lXP3R75vJ9fFdYL6zSDqjZiNlAHzoiQeIJJgKgzOUlzoxn
# g99G+IVNw9pmHsdzfju0dhempaCgdFWo5WAYQWI4x2VGqwQWZlbq+abLQs9dVGQv
# gfjPOAAPEGvhgy6NPkjsSVZK7Jpp9MsPEPsHNEpibAGNbscghMpc0WOZHo5d7A+l
# Fkiqa94hLwIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFABYGz7txfEGk74xPTa0rAtd
# MvCBMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAAL/44wD6u9+OLm5fJ87UoOk+iM41AO4alm16uBviAP0b1Fq
# lTp1hegc3AfFTp0bqM4kRxQkTzV3sZy8J3uPXU/8BouXl/kpm/dAHVKBjnZIA37y
# mxe3rtlbIpFjOzJfNfvGkTzM7w6ZgD4GkTgTegxMvjPbv+2tQcZ8GyR8E9wK/EuK
# IAUdCYmROQdOIU7ebHxwu6vxII74mHhg3IuUz2W+lpAPoJyE7Vy1fEGgYS29Q2dl
# GiqC1KeKWfcy46PnxY2yIruSKNiwjFOPaEdHodgBsPFhFcQXoS3jOmxPb6897t4p
# sETLw5JnugDOD44R79ECgjFJlJidUUh4rR3WQLYwggTsMIID1KADAgECAhMzAAAA
# sBGvCovQO5/dAAEAAACwMA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBMB4XDTEzMDEyNDIyMzMzOVoXDTE0MDQyNDIyMzMzOVowgYMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# HjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAOivXKIgDfgofLwFe3+t7ut2rChTPzrbQH2zjjPmVz+l
# URU0VKXPtIupP6g34S1Q7TUWTu9NetsTdoiwLPBZXKnr4dcpdeQbhSeb8/gtnkE2
# KwtA+747urlcdZMWUkvKM8U3sPPrfqj1QRVcCGUdITfwLLoiCxCxEJ13IoWEfE+5
# G5Cw9aP+i/QMmk6g9ckKIeKq4wE2R/0vgmqBA/WpNdyUV537S9QOgts4jxL+49Z6
# dIhk4WLEJS4qrp0YHw4etsKvJLQOULzeHJNcSaZ5tbbbzvlweygBhLgqKc+/qQUF
# 4eAPcU39rVwjgynrx8VKyOgnhNN+xkMLlQAFsU9lccUCAwEAAaOCAWAwggFcMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRZcaZaM03amAeA/4Qevof5cjJB
# 8jBRBgNVHREESjBIpEYwRDENMAsGA1UECxMETU9QUjEzMDEGA1UEBRMqMzE1OTUr
# NGZhZjBiNzEtYWQzNy00YWEzLWE2NzEtNzZiYzA1MjM0NGFkMB8GA1UdIwQYMBaA
# FMsR6MrStBZYAck3LjMWFrlMmgofMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY0NvZFNpZ1BDQV8w
# OC0zMS0yMDEwLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljQ29kU2lnUENBXzA4LTMx
# LTIwMTAuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQAx124qElczgdWdxuv5OtRETQie
# 7l7falu3ec8CnLx2aJ6QoZwLw3+ijPFNupU5+w3g4Zv0XSQPG42IFTp8263Os8ls
# ujksRX0kEVQmMA0N/0fqAwfl5GZdLHudHakQ+hywdPJPaWueqSSE2u2WoN9zpO9q
# GqxLYp7xfMAUf0jNTbJE+fA8k21C2Oh85hegm2hoCSj5ApfvEQO6Z1Ktwemzc6bS
# Y81K4j7k8079/6HguwITO10g3lU/o66QQDE4dSheBKlGbeb1enlAvR/N6EXVruJd
# PvV1x+ZmY2DM1ZqEh40kMPfvNNBjHbFCZ0oOS786Du+2lTqnOOQlkgimiGaCMIIF
# vDCCA6SgAwIBAgIKYTMmGgAAAAAAMTANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZIm
# iZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQD
# EyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTAwODMx
# MjIxOTMyWhcNMjAwODMxMjIyOTMyWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJyWVwZMGS/HZpgICBC
# mXZTbD4b1m/My/Hqa/6XFhDg3zp0gxq3L6Ay7P/ewkJOI9VyANs1VwqJyq4gSfTw
# aKxNS42lvXlLcZtHB9r9Jd+ddYjPqnNEf9eB2/O98jakyVxF3K+tPeAoaJcap6Vy
# c1bxF5Tk/TWUcqDWdl8ed0WDhTgW0HNbBbpnUo2lsmkv2hkL/pJ0KeJ2L1TdFDBZ
# +NKNYv3LyV9GMVC5JxPkQDDPcikQKCLHN049oDI9kM2hOAaFXE5WgigqBTK3S9dP
# Y+fSLWLxRT3nrAgA9kahntFbjCZT6HqqSvJGzzc8OJ60d1ylF56NyxGPVjzBrAlf
# A9MCAwEAAaOCAV4wggFaMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMsR6MrS
# tBZYAck3LjMWFrlMmgofMAsGA1UdDwQEAwIBhjASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBT90TFO0yaKleGYYDuoMW+mPLzYLTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTAfBgNVHSMEGDAWgBQOrIJgQFYnl+UlE/wq4QpTlVnk
# pDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEE
# SDBGMEQGCCsGAQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY3Jvc29mdFJvb3RDZXJ0LmNydDANBgkqhkiG9w0BAQUFAAOCAgEAWTk+
# fyZGr+tvQLEytWrrDi9uqEn361917Uw7LddDrQv+y+ktMaMjzHxQmIAhXaw9L0y6
# oqhWnONwu7i0+Hm1SXL3PupBf8rhDBdpy6WcIC36C1DEVs0t40rSvHDnqA2iA6VW
# 4LiKS1fylUKc8fPv7uOGHzQ8uFaa8FMjhSqkghyT4pQHHfLiTviMocroE6WRTsgb
# 0o9ylSpxbZsa+BzwU9ZnzCL/XB3Nooy9J7J5Y1ZEolHN+emjWFbdmwJFRC9f9Nqu
# 1IIybvyklRPk62nnqaIsvsgrEA5ljpnb9aL6EiYJZTiU8XofSrvR4Vbo0HiWGFzJ
# NRZf3ZMdSY4tvq00RBzuEBUaAF3dNVshzpjHCe6FDoxPbQ4TTj18KUicctHzbMrB
# 7HCjV5JXfZSNoBtIA1r3z6NnCnSlNu0tLxfI5nI3EvRvsTxngvlSso0zFmUeDord
# EN5k9G/ORtTTF+l5xAS00/ss3x+KnqwK+xMnQK3k+eGpf0a7B2BHZWBATrBC7E7t
# s3Z52Ao0CW0cgDEf4g5U3eWh++VHEK1kmP9QFi58vwUheuKVQSdpw5OPlcmN2Jsh
# rg1cnPCiroZogwxqLbt2awAdlq3yFnv2FoMkuYjPaqhHMS+a3ONxPdcAfmJH0c6I
# ybgY+g5yjcGjPa8CQGr/aZuW4hCoELQ3UAjWwz0wggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBN4wggTa
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAAAsBGvCovQO5/d
# AAEAAACwMAkGBSsOAwIaBQCggfcwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFPu6
# j5HkWceJo8j0G5tVzcFw8MwhMIGWBgorBgEEAYI3AgEMMYGHMIGEoGqAaABEAEkA
# QQBHAF8AQwBUAFMAXwBHAGUAbgBlAHIAYQBsAF8AUgBlAHAAbwByAHQAcwBfAGcA
# bABvAGIAYQBsAF8ARABDAF8AVQBwAGQAYQB0AGUASABpAHMAdABvAHIAeQAuAHAA
# cwAxoRaAFGh0dHA6Ly9taWNyb3NvZnQuY29tMA0GCSqGSIb3DQEBAQUABIIBADZp
# BQ31lxt/ytVEBdBGNBANQvu8+0C151dYY4qKn8akF/WsnTwcYyjIDVOH+0CZWDfI
# 6C1LMzWZUPGC3LbeVT7Bgh7Rcqw0tvjt296tImQPItk5otpGO6U1smgaWaw2vZp2
# ur7aZedPqAZGzxknWruxy2stz+3uPvPlyDh61rHarCAmLUr76B+66IHUI4YOAzwu
# dyNj34u462STz/jVNkg6MORV+5qm7rcLx50THPPE3/u3a3z126qEIvhyqq8JA6er
# TTNONNIKfP3QZ+xmNHy/0wGtFUzWsRZnmrdvt63/xP78sa/c08IudwUkKucg3h9m
# KvMZVpQ7Ser0I670lfqhggIoMIICJAYJKoZIhvcNAQkGMYICFTCCAhECAQEwgY4w
# dzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMY
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBAhMzAAAAM+UnhqMOSiqAAAAAAAAzMAkG
# BSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0xNDAyMjQxNzM3NTdaMCMGCSqGSIb3DQEJBDEWBBQmwP/YAoEB8LLaQpqD
# nnbRZza0pzANBgkqhkiG9w0BAQUFAASCAQAbIiRgRSZrluoI48eyPhrBkvqcLV32
# A1pIr2WWNd/NOT+AQmmx8HOG2+RtLm18NKjuapTUtj4h0yRoI8V47S5x9UomSHSZ
# /G4Eu7oiA79Th5H/+i00wihSphtEa6MlJZ/cjnxG780Hu7EIODRSmhNSxS9quHbX
# p06FQs9/93lqBQfzqj2S6/FSXPonBg/LiN7Rs6qyjpqgVplQWqw+fuzd0XRlNnej
# OvlYtCuhDWevP5ah06wZXDrHxJcDo6dSStT2UVTKWgCpM4V5IKI4X7t6taK34mFG
# gnfQ7f1WiN3qTdOxmxIHAU6bXlqnOXm8mhBLLptwARbZLXmn4/o1DSwL
# SIG # End signature block

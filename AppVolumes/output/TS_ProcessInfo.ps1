#************************************************
# TS_ProcOverview.ps1
# Version 1.0.1
# Date: 2-2-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script executes a series of WMI queries to obtain process statistics - such as top process by handle count/ memory usage and so.
#              Also, it shows statistics for Kernel Pool memory usage using MemSnap tool
#************************************************


trap 
{
	$errorMessage = "Error [{4}]:`r`n Category {0}, Error Type {1}, ID: {2}, Message: {3}" -f  $_.CategoryInfo.Category, $_.Exception.GetType().FullName,  $_.FullyQualifiedErrorID, $_.Exception.Message, $_.InvocationInfo.PositionMessage
	$errorMessage | WriteTo-StdOut
	continue
}

Import-LocalizedData -BindingVariable ProcInfoStrings

Write-DiagProgress -Activity $ProcInfoStrings.ID_ProcInfo -Status $ProcInfoStrings.ID_ProcInfoObtaining

$KernelGraph = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group id=`"GraphValue`" class=`"vmlimage`" style=`"width:300px;height:15px;vertical-align:middle`" coordsize=`"{MaxValue},100`" title=`"{ValueDisplay}`"><v:rect class=`"vmlimage`" style=`"top:1;left:1;width:{MaxValue};height:100`" strokecolor=`"#336699`"><v:fill type=`"gradient`" angle=`"0`" color=`"#C4CCC7`" color2=`"white`" /></v:rect><v:rect class=`"vmlimage`" style=`"top:2;left:2;width:{Value};height:99`" strokecolor=`"{GraphColorEnd}`"><v:fill type=`"gradient`" angle=`"270`" color=`"{GraphColorStart}`" color2=`"{GraphColorEnd}`" /></v:rect></v:group></span>"
$ProcGraph   = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group id=`"GraphValue`" class=`"vmlimage`" style=`"width:200px;height:15px;vertical-align:middle`" coordsize=`"{MaxValue},100`" title=`"{ValueDisplay}`"><v:rect class=`"vmlimage`" style=`"top:1;left:1;width:{MaxValue};height:100`" strokecolor=`"#336699`"><v:fill type=`"gradient`" angle=`"0`" color=`"#C4CCC7`" color2=`"white`" /></v:rect><v:rect class=`"vmlimage`" style=`"top:2;left:1;width:{Value};height:99`" strokecolor=`"{GraphColorEnd}`"><v:fill type=`"gradient`" angle=`"270`" color=`"{GraphColorStart}`" color2=`"{GraphColorEnd}`" /></v:rect><v:rect style=`"top:-70;left:1;width:{MaxValue};height:50`" filled=`"false`" stroked=`"false`" textboxrect=`"top:19;left:1;width:{MaxValue};height:30`"><v:textbox style=`"color:white;`" inset=`"10px, 10px, 28px, 177px`">{ValueDisplay}</v:textbox></v:rect></v:group></span>"

$sectionDescription = "Processes and Kernel Memory information"
$fileDescription = "Processess/Performance Information"
$OutputFile = $ComputerName + "_ProcessesPerfInfo.htm"
$CommandToExecute = "cscript.exe ProcessesPerfInfo.vbs /generatescripteddiagxmlalerts"

$OutputXMLFileName = ($Computername + "_ProcessesPerfInfo.xml")

if (-not (Test-Path $OutputXMLFileName))
{

	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription

	[xml] $ProcOverviewXML = Get-Content $OutputXMLFileName

	$MAXITEMS_TO_DISPLAY = 5

	$PoolMemoryXML = $ProcOverviewXML.SelectSingleNode("//Section[SectionTitle = 'Kernel Memory Information']")

	foreach ($PoolMemorySection in $PoolMemoryXML.SubSection) 
	{
		$Item_Summary = new-object PSObject
		$PoolMemorySectionTitle = $PoolMemorySection.SectionTitle.get_InnerText()
		$MaxValue = $PoolMemorySection.KernelMemory.MaxValue.get_InnerText()
		$Displayed = 0
		foreach ($Tag in $PoolMemorySection.SelectNodes("KernelMemory/PoolMemory"))
		{
			$Displayed++
			if ($Displayed -le $MAXITEMS_TO_DISPLAY) {
				$TagName = $Tag.Tag.get_InnerText()
				$MemoryAllocationDisplay = $Tag.ValueDisplay.get_InnerText()
				$MemoryAllocationValue = $Tag.Value.get_InnerText()
				$GraphColorStart = $Tag.GraphColorStart.get_InnerText()
				$GraphColorEnd = $Tag.GraphColorEnd.get_InnerText()
				
				$Graph = $KernelGraph -replace "{MaxValue}", "$MaxValue" -replace "{ValueDisplay}", "$MemoryAllocationDisplay" -replace "{Value}", "$MemoryAllocationValue" -replace "{GraphColorStart}", "$GraphColorStart" -replace "{GraphColorEnd}", "$GraphColorEnd"
				
				add-member -inputobject $Item_Summary  -membertype noteproperty -name $TagName -value ("<table><tr><td width=`"100px`">$MemoryAllocationDisplay</td><td> $Graph</td></tr></table>")
			}
		}
		$Item_Summary | ConvertTo-Xml2 | update-diagreport -id ("52_$PoolMemorySectionTitle") -name $PoolMemorySectionTitle -verbosity informational
	}

	$ProcXML = $ProcOverviewXML.SelectSingleNode("//Section[SectionTitle = 'Process Statistics']")

	$Item_Summary = new-object PSObject
	foreach ($ProcSection in $ProcXML.SubSection) 
	{
		$ProcSectionTitle = $ProcSection.SectionTitle.get_InnerText()
		$MaxValue = $ProcSection.ProcessCollection.MaxValue.get_InnerText()
		$Displayed = 0
		#$MaxValue = $null
		$Line = ""
		foreach ($Process in $ProcSection.SelectNodes("ProcessCollection/Process"))
		{
			$Displayed++
			if ($Displayed -lt $MAXITEMS_TO_DISPLAY) {
				$ProcessName = $Process.Name.get_InnerText()
				$Display = $Process.ValueDisplay.get_InnerText()
				$Value = $Process.Value.get_InnerText()
				$GraphColorStart = $Process.GraphColorStart.get_InnerText()
				$GraphColorEnd = $Process.GraphColorEnd.get_InnerText()
				
				#if ($MaxValue -eq $null) 
				#{
				#	$MaxValue = ([int] $Value * 1.2)
				#}
				
				$Graph = $ProcGraph -replace "{MaxValue}", "$MaxValue" -replace "{ValueDisplay}", "$Display" -replace "{Value}", "$Value" -replace "{GraphColorStart}", "$GraphColorStart" -replace "{GraphColorEnd}", "$GraphColorEnd"
				$Line += "<table><tr><td width=`"120px`">$ProcessName</td><td> $Graph</td></tr></table>"
			}
		}
		add-member -inputobject $Item_Summary  -membertype noteproperty -name $ProcSectionTitle -value $Line
	}

	add-member -inputobject $Item_Summary -membertype noteproperty -name "More Information" -value ("For more information, please open the file <a href= `"`#" + $OutputFile + "`">" + $OutputFile + "</a>.")

	$Item_Summary | ConvertTo-Xml2 | update-diagreport -id ("50_ProcSummary") -name "Processes Summary" -verbosity informational

	$RootCauseXMLFilename = ($ComputerName + "_ProcessesPerfInfoRootCauses.XML")
	if (Test-Path ($RootCauseXMLFilename))
	{ 
		$RootCauseDetectedHash = @{}
		[xml] $XMLRootCauses = Get-Content -Path $RootCauseXMLFilename
		Foreach ($RootCauseDetected in $XMLRootCauses.SelectNodes("/Root/RootCause"))
		{
			$InformationCollected = @{}
			$ProcessName = $null
			switch ($RootCauseDetected.name)
			{
				"RC_HighHandleCount"
				{
					$InformationCollected = @{"Process Name" = $RootCauseDetected.param1; 
											  "Process ID" = $RootCauseDetected.param2;
											  "Current Handle Count" = $RootCauseDetected.CurrentValue}
					$ProcessName = $RootCauseDetected.param1
					$PublicURL = "http://blogs.technet.com/b/markrussinovich/archive/2009/09/29/3283844.aspx"
				}
				
				"RC_KernelMemoryPerformanceIssue"
				{
					$InformationCollected = @{"Kernel Tag Name" = $RootCauseDetected.param1; 
											  "Pool Memory Type" = $RootCauseDetected.param2;
											  "Current Allocated (MB)" = $RootCauseDetected.CurrentValue;
											  "Current Allocated (%)" = ($RootCauseDetected.ExpectedValue + "%")}
					$PublicURL = "http://blogs.technet.com/b/askperf/archive/2008/04/11/an-introduction-to-pool-tags.aspx"
				}
				"RC_LowSysPTEs"
				{
					$InformationCollected = @{"Current SysPTEs count" = $RootCauseDetected.CurrentValue}; 			
					$PublicURL = "http://blogs.technet.com/b/askperf/archive/2008/05/16/troubleshooting-server-hangs-part-four.aspx"
				}
				
				"RC_LowVirtualMemory"
				{
					$InformationCollected = @{"Committed Bytes In Use (%)" = $RootCauseDetected.CurrentValue};
					$TopProcesses = Get-Process | Sort-Object -Property VM -Descending | Select-Object -First 3
					$X = 1
					foreach ($Process in $TopProcesses)
					{
						$InformationCollected += @{"Top Process [$X] Memory Usage" = ($Process.Name + " (ID " + $Process.Id.ToString() + "): " + (FormatBytes $Process.VirtualMemorySize64))};
						$X++
					}
					$PublicURL = "http://blogs.technet.com/b/askperf/archive/2008/01/25/an-overview-of-troubleshooting-memory-issues.aspx"
				}			
			}
		
			if ($RootCauseDetectedHash.ContainsKey($RootCauseDetected.name) -eq $false) 
			{
				$RootCauseDetectedHash += @{$RootCauseDetected.name = $true}
			}
			
			Write-GenericMessage -RootCauseID $RootCauseDetected.name -Verbosity $RootCauseDetected.Type -InformationCollected $InformationCollected -ProcessName $ProcessName -PublicContentURL $PublicURL -Visibility 4 -MessageVersion 2
		}
		foreach ($RootCause in $RootCauseDetectedHash.get_Keys())
		{
			Update-DiagRootCause -Id $RootCause -Detected $true
		}
	}
}
else
{
	"[ProcessInfo] - Skipped execution as $OutputXMLFileName already exists"  | WriteTo-StdOut
}

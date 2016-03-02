#************************************************
# DC_ServerManagerInfo.ps1
# Version 1.0.1
# Date: 09-11-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script can be used to 
#************************************************

trap [Exception] 
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

Function Out-MultiLevelObject
{ Param ($items, $startObjects, $path=("Path"), $parent=("Parent"), $label=("Label"), $indent=0, $Attributes="")
					
	Foreach ($startAt in $StartObjects) 
	{
		$children = $items | where-object {$_.$parent -eq $startAt.$path} 
	
		$AttributesText = ""
	
		if ($children -ne $null) {
			if ($startAt.$label -ne $null) {
			("<div style=`"margin-left:" + ($indent * 15) + "`">") + "$($startAt.$label)"  + "</div>" 
			}
			$children | ForEach-Object {Out-MultiLevelObject $items $_ $path $parent $label ($indent + 1)} 
		} else {
			("<div style=`"margin-left:" + ($indent * 15) + "`">" + "$($startAt.$label)" + "</div>")
		}
	}
}

if ($OSVersion.Build -gt 6000)
{
	Import-LocalizedData -BindingVariable ServerManagerStrings
	Write-DiagProgress -Activity $ServerManagerStrings.ID_ServerManagerInfo -Status $ServerManagerStrings.ID_ServerManagerObtaining

	if ((Get-WmiObject -Class Win32_ComputerSystem).DomainRole -gt 1) 
	{ #Server

		if (test-path "$Env:windir\system32\oclist.exe") 
		{
			$OutputFile = $ComputerName + "_OptionalComponents.txt"
			$CommandToExecute = "$Env:windir\system32\cmd.exe /c $Env:windir\system32\oclist.exe > $OutputFile"
			$fileDescription = $ServerManagerStrings.ID_ServerManagerOclist
			RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect "$OutputFile.*" -fileDescription $fileDescription  -BackgroundExecution
		} 
		else 
		{ # dont execute code below in ServerCore or pre-Windows Server 2008
			
			if ($OSVersion.Build -gt 7000)
			{
				Import-Module "ServerManager"
								
				$Features_Summary = new-object PSObject
				
				$AllFeatures = Get-WindowsFeature | Where-Object {($_.installed -eq $true)}
				$Roles = $AllFeatures | Where-Object {($_.FeatureType -eq "Role")}
				$RoleServices = $AllFeatures | Where-Object {($_.FeatureType -ne "Role")}
				$Features = $AllFeatures | Where-Object {($_.FeatureType -eq "Feature") -and ($_.Depth -eq 1)}
				
				Foreach ($Feature in $Roles) 
				{
					$RoleServicesForFeature = ($AllFeatures | Where {($_.Parent -eq $Feature.Name) -and ($_.Installed -eq $true)})
					if ($RoleServicesForFeature)
					{
						$RoleServiceDisplay = Out-MultiLevelObject -items $RoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
					}
					else
					{
						$RoleServiceDisplay = "<div style=`"margin-left:0`">(There are no role services for " + $Feature.Name + ")</div>"
					}
					add-member -inputobject $Features_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
				}
				
				$Features_Summary | ConvertTo-Xml2 | update-diagreport -ID "06_Roles" -name "Server Roles/ Role Services" -verbosity "Informational"
				
				$Features_Summary = new-object PSObject
				
				Foreach ($Feature in $Features) 
				{
					$RoleServicesForFeature = ($AllFeatures | Where {($_.Parent -eq $Feature.Name)})
					if ($RoleServicesForFeature)
					{
						$RoleServiceDisplay = Out-MultiLevelObject -items $RoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
					}
					else
					{
						$RoleServiceDisplay =  "<div style=`"margin-left:0`">&#160;</div>"
					}
					add-member -inputobject $Features_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
				}
				
				$Features_Summary | ConvertTo-Xml2 | update-diagreport -ID "06_RolesFeatures" -name "Feature/ Services" -verbosity "Informational"				
			}
			if(($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 2))
            {
                $AllRemovedFeatures = Get-WindowsFeature | Where-Object {$_.InstallState -eq "Removed"}    #This need to be confirmed.
                $RemovedRoles = $AllRemovedFeatures | Where-Object {($_.FeatureType -eq "Role")}
                $RemovedRoleServices = $AllRemovedFeatures | Where-Object {($_.FeatureType -ne "Role")}
                $RemovedFeatures = $AllRemovedFeatures | Where-Object {($_.FeatureType -eq "Feature") -and ($_.Depth -eq 1)}
	
                $Roles_Summary = new-object PSObject
				
                Foreach ($Feature in $RemovedRoles) 
                {
                   $RoleServicesForFeature = ($AllRemovedFeatures | Where { $_.Parent -eq $Feature.Name })
                   if ($RoleServicesForFeature -ne $null)
                   {
				      $RoleServiceDisplay = Out-MultiLevelObject -items $RemovedRoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
		           }
		           else
		           {
			          $RoleServiceDisplay = "<div style=`"margin-left:0`">(There are no role services for " + $Feature.Name + ")</div>"
		           }
		           add-member -inputobject $Roles_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
                }
				
                $Roles_Summary | ConvertTo-Xml2 | update-diagreport -ID "07_RemovedRoles" -name "Removed Server Roles/ Role Services" -verbosity "Informational"
				
                $Features_Summary = new-object PSObject
				
                Foreach ($Feature in $RemovedFeatures) 
                {
		           $RoleServicesForFeature = ($AllRemovedFeatures | Where { $_.Parent -eq $Feature.Name })
		           if ($RoleServicesForFeature)
		           {
		    	       $RoleServiceDisplay = Out-MultiLevelObject -items $RemovedRoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
	    	       }
    		       else
		           {
			           $RoleServiceDisplay =  "<div style=`"margin-left:0`">&#160;</div>"
    		       }
		           add-member -inputobject $Features_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
                }
				
                $Features_Summary | ConvertTo-Xml2 | update-diagreport -ID "07_RemovedRolesFeatures" -name "Removed Feature/ Services" -verbosity "Informational"
	
            }
		}
	}
}

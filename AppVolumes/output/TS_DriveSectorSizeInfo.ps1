#************************************************
# TS_4KDriveInfo.ps1
# Version 1.0.2
# Date: 03-21-2011
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script detects 4KB/ 512e drive informaiton
#************************************************

[string]$typeDefinition = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;

namespace Microsoft.DeviceIoControl
{
    internal static class NativeMethods
    {

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode,
             ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr CreateFile(string fileName,
                                                  int desiredAccess,
                                                  int sharedMode,
                                                  IntPtr securityAttributes,
                                                  int creationDisposition,
                                                  int flagsandAttributes,
                                                  IntPtr templatFile);

        [DllImport("kernel32.dll", ExactSpelling = true, EntryPoint = "DeviceIoControl", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern bool DeviceIoControl(IntPtr device,
                                                    int ioControlCode,
                                                    IntPtr inBuffer,
                                                    int inBufferSize,
                                                    IntPtr outBuffer,
                                                    int outputBufferSize,
                                                    out int bytesReturned,
                                                    IntPtr ignore);


        internal static readonly IntPtr INVALID_HANDLE_VALUE = (IntPtr)(-1);

        [DllImport("kernel32.dll")]
        internal static extern void ZeroMemory(IntPtr destination, int size);

    }

    public class SectorSize
    {

        [StructLayout(LayoutKind.Sequential)]   
        public struct STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR  
        {
            public int Version;
            public int Size;
            public int BytesPerCacheLine;
            public int BytesOffsetForCacheAlignment;
            public int BytesPerLogicalSector;
            public int BytesPerPhysicalSector;
            public int BytesOffsetForSectorAlignment;
        }

        public enum STORAGE_PROPERTY_ID 
        {
            StorageDeviceProperty = 0,
            StorageAdapterProperty,
            StorageDeviceIdProperty,
            StorageDeviceUniqueIdProperty,              // See storduid.h for details
            StorageDeviceWriteCacheProperty,
            StorageMiniportProperty,
            StorageAccessAlignmentProperty = 6,
            StorageDeviceSeekPenaltyProperty,
            StorageDeviceTrimProperty,
            StorageDeviceWriteAggregationProperty
        }

        public enum STORAGE_QUERY_TYPE {
              PropertyStandardQuery     = 0,
              PropertyExistsQuery,
              PropertyMaskQuery,
              PropertyQueryMaxDefined 
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STORAGE_PROPERTY_QUERY
        {
            public STORAGE_PROPERTY_ID PropertyId;
            public STORAGE_QUERY_TYPE QueryType;
            public IntPtr AdditionalParameters;
        }

        private const int GENERIC_READ = -2147483648;
        private const int FILE_SHARE_READ = 0x00000001;
        private const int FILE_SHARE_WRITE = 0x00000002;
        private const int OPEN_EXISTING = 3;
        private const int FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const int FSCTL_IS_VOLUME_DIRTY = 589944;
        private const int VOLUME_IS_DIRTY = 1;

        private const int PropertyStandardQuery = 0;
        private const int StorageAccessAlignmentProperty = 6;

        public static STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR DetectSectorSize(string devName)
        {
            string FileName = @"\\.\" + devName;
            int bytesReturned;
            IntPtr outputBuffer = IntPtr.Zero;

            STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR pAlignmentDescriptor = new STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR();

            SectorSize.STORAGE_PROPERTY_QUERY StoragePropertQuery = new SectorSize.STORAGE_PROPERTY_QUERY();

            StoragePropertQuery.QueryType = SectorSize.STORAGE_QUERY_TYPE.PropertyStandardQuery;
            StoragePropertQuery.PropertyId = SectorSize.STORAGE_PROPERTY_ID.StorageAccessAlignmentProperty;

            IntPtr hVolume = NativeMethods.CreateFile(FileName, 0, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

            if (hVolume != NativeMethods.INVALID_HANDLE_VALUE)
            {
                outputBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(pAlignmentDescriptor));
                NativeMethods.ZeroMemory(outputBuffer, Marshal.SizeOf(pAlignmentDescriptor));

                IntPtr outputBufferStoragePropertQuery = Marshal.AllocHGlobal(Marshal.SizeOf(StoragePropertQuery));
                Marshal.StructureToPtr(StoragePropertQuery, outputBufferStoragePropertQuery,false);

                int IOCTL_STORAGE_QUERY_PROPERTY = 2954240;
                
                bool status = NativeMethods.DeviceIoControl(hVolume,
                         IOCTL_STORAGE_QUERY_PROPERTY,
                         outputBufferStoragePropertQuery,
                         Marshal.SizeOf(StoragePropertQuery),
                         outputBuffer,
                         Marshal.SizeOf(pAlignmentDescriptor),
                         out bytesReturned,
                         IntPtr.Zero);

                if (!status)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                pAlignmentDescriptor = (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR) Marshal.PtrToStructure(outputBuffer, typeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR));
            }
            return pAlignmentDescriptor;
        }
	}
}
"@

function FormatBytes 
{
	param ($bytes,$precision='0')
	foreach ($i in ("Bytes","KB","MB","GB","TB")) {
		if (($bytes -lt 1000) -or ($i -eq "TB")){
			$bytes = ($bytes).tostring("F0" + "$precision")
			return $bytes + " $i"
		} else {
			$bytes /= 1KB
		}
	}
}


Function CheckMinimalFileVersionWithCTS([string] $Binary, $RequiredMajor, $RequiredMinor, $RequiredBuild, $RequiredFileBuild)
{
	$newProductVersion = Get-FileVersionString($Binary)
	if((CheckMinimalFileVersion -Binar $Binary -RequiredMajor $RequiredMajor -RequiredMinor $RequiredMinor -RequiredBuild $RequiredBuild -RequiredFileBuild $RequiredFileBuild -LDRGDR) -eq $true)
	{
		"[CheckMinimalFileVersion] $Binary version is " + $newProductVersion + " - OK" | WriteTo-StdOut -ShortFormat
		return $true
	}
	else
	{
		"[CheckMinimalFileVersion] $Binary version is " + $newProductVersion | WriteTo-StdOut -ShortFormat
		add-member -inputobject $KB982018Binaries_Summary  -membertype noteproperty -name $Binary -value $newProductVersion
		return $false
	}
}

Function KB982018IsInstalled()
{
	if ($OSVersion.Build -le 7601) #Win7 Service Pack 1 or RTM
	{
		#Pre-Win7 SP1 - Need to check if KB 982018 is actually installed
		$System32Folder = $Env:windir + "\system32"		
		if (((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Amdsata.sys" 1 1 2 5) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Amdxata.sys" 1 1 2 5) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Nvraid.sys" 10 6 0 18) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Nvstor.sys" 10 6 0 18) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7600 16778) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7600 20921) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7601 17577) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7601 21680) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7600 16778) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7600 20921) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7601 17577) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7601 21680) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7601 17577) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7601 21680) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7600 16778) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7600 20921) -eq $true)
			)
		{ 
			#Everything is fine
			return $true
		} else {
			return $false
		}		
	} else {
		#SP1 is already installed
		return $true
	}
}

$512eDrivesXML = Join-Path -Path $PWD.Path -ChildPath "512eDrives.xml"

# Windows 8 fully support 4KB drives: http://blogs.msdn.com/b/b8/archive/2011/11/29/enabling-large-disks-and-large-sectors-in-windows-8.aspx
if (($OSVersion.Build -gt 7000) -and ($OSVersion.Build -lt 9000))
{
	Import-LocalizedData -BindingVariable AdvDrivesString

	$4KBDriveE = @()
	$4KBDriveN = @()
	
	if (Test-Path $512eDrivesXML)
	{
		$512eDrivesXML | Remove-Item -Force -ErrorAction Continue
	}

	Write-DiagProgress -Activity $AdvDrivesString.ID_CheckingDriveSize

	$StorageType = Add-Type -TypeDefinition $typeDefinition -PassThru
		
	$AlignmentDescriptor = $StorageType::STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR
	#$AlignmentDescriptor = $StorageType[1]::DetectSectorSize("C:")

	#$devices = (Get-WmiObject -query "Select DeviceID from Win32_LogicalDisk WHERE ((MediaType=12) or (MediaType=11)) and ((DriveType=3) or (DriveType=2))")
	$devices = (Get-WmiObject -query "Select DeviceID, Model, InterfaceType, Size, BytesPerSector, MediaType from Win32_DiskDrive where ConfigManagerErrorCode=0 and MediaLoaded = true and SectorsPerTrack > 0")
	
	if($devices -ne $null) 
	{
	
		$4KDriveDetected = $false
		$SectorSize_Summary = new-object PSObject
		$4KDrive_Summary = new-object PSObject
		$KB982018Binaries_Summary = new-object PSObject
		$4KNativeDetected = $false
		
	    foreach($device in $devices) 
		{
			trap [Exception] 
			{
			    $errorMessage = $_.Exception.Message
				"           Error: " + $errorMessage | WriteTo-StdOut
				$_.InvocationInfo | fl | out-string | WriteTo-StdOut
				
				WriteTo-ErrorDebugReport -ErrorRecord $_ -InvokeInfo $MyInvocation
				$Error.Clear()
				continue
			}

			Write-DiagProgress -Activity $AdvDrivesString.ID_CheckingDriveSize -Status ($AdvDrivesString.ID_4KDriveDetectedDesc -replace ("%Drive%", $device.DeviceID))
			
			
			$Interface = Get-WmiObject -Query ("ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + $device.DeviceID + "'} Where ResultClass=Win32_PnPEntity") | % {Get-WmiObject -Query ("ASSOCIATORS OF {Win32_PnPEntity.DeviceID='" + $_.DeviceID + "'} Where ResultClass=CIM_Controller")}
			$Partitions = Get-WmiObject -Query ("ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + $device.DeviceID + "'} Where ResultClass=Win32_DiskPartition")
			
			$DriveLetters = @()
			foreach ($Partition in $Partitions)
			{
				$Win32Logical = Get-WmiObject -Query ("ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + $Partition.DeviceID + "'} Where ResultClass=Win32_LogicalDisk")
				if ($Win32Logical -ne $null)
				{
					$DriveLetters += $Win32Logical.DeviceID
				}
			}
			
			if ($DriveLetters.Length -gt 0)
			{
				$DriveLetterString = "[" + [string]::Join(", ", $DriveLetters) + "]"
				$DriveLetters | Export-Clixml -Path $512eDrivesXML
			}
			else
			{
				$DriveLetterString = ""
			}
			
			$BytesDisplay = ""
			$4KDriveType = ""
			"Checking drive: " + $device.DeviceID | WriteTo-StdOut -ShortFormat
			"Storage Type: " + $StorageType[1].ToString() | WriteTo-StdOut -ShortFormat
			$AlignmentDescriptor = $StorageType[1]::DetectSectorSize($device.DeviceID)
			if ($AlignmentDescriptor -ne $null)
			{
				$BytesDisplay = ($AlignmentDescriptor.BytesPerPhysicalSector.ToString()) + " Bytes"
			}
			else
			{
				$BytesDisplay = "(Unknown)"
			}
			
			$DebugString = "    Results for drive " + $device.DeviceID
			$DebugString += "`r`n      Drive Letter(s)       : " + $DriveLetterString
			$DebugString += "`r`n      Model                 : " + $device.Model
			$DebugString += "`r`n      Interface Name        : " + $Interface.Name
			$DebugString += "`r`n      Interface Type        : " + $device.InterfaceType
			$DebugString += "`r`n      Bytes per sector (WMI): " + $device.BytesPerSector
			$DebugString += "`r`n      BytesPerPhysicalSector: " + $AlignmentDescriptor.BytesPerPhysicalSector
			$DebugString += "`r`n      BytesPerLogicalSector : " + $AlignmentDescriptor.BytesPerLogicalSector
			$DebugString += "`r`n      Version               : " + $AlignmentDescriptor.Version
			
			$DebugString | WriteTo-StdOut
			
			if (($AlignmentDescriptor.BytesPerPhysicalSector -gt 512) -or ($device.BytesPerSector -ne 512))
			{
				trap [Exception] 
				{
				    $errorMessage = $_.Exception.Message
					"           Error: " + $errorMessage | WriteTo-StdOut
					$_.InvocationInfo | fl | out-string | WriteTo-StdOut
					
					WriteTo-ErrorDebugReport -ErrorRecord $_ -InvokeInfo $MyInvocation
					$Error.Clear()
					continue
				}

				#4K Drive
				$4KDriveDetected = $true

				$InformationCollected = @{"Drive Model"=$device.Model}
				$InformationCollected += @{"Device ID"=$device.DeviceID}
				$InformationCollected += @{"Drive Letter(s)"=$DriveLetterString}
				$InformationCollected += @{"Drive Size"=($device.Size | FormatBytes -precision 2)}
				$InformationCollected += @{"Media Type"=$device.MediaType}
				$InformationCollected += @{"Drive Type"=$device.InterfaceType}
				$InformationCollected += @{"Interface Name"=$Interface.Name}
				$InformationCollected += @{"Bytes per sector (Physical)"=$AlignmentDescriptor.BytesPerPhysicalSector}
				$InformationCollected += @{"Bytes per sector (Logical)"=$AlignmentDescriptor.BytesPerLogicalSector}
				$InformationCollected += @{"Bytes per sector (WMI)"=$device.BytesPerSector}

				if (($AlignmentDescriptor.BytesPerPhysicalSector -eq 3072) -or ($device.BytesPerSector -eq 4096))
				{
					# known issue
					$BytesDisplay = "Physical: 4KB"
				} 
				else
				{
					$BytesDisplay = "Physical: " + ($AlignmentDescriptor.BytesPerPhysicalSector.ToString())
				}
				
				
				if (($AlignmentDescriptor.BytesPerLogicalSector -eq 512) -and ($device.BytesPerSector -eq 512))
				{
					$512EDriveDetected = $true
					$4KDriveType = " - Logical: " + $AlignmentDescriptor.BytesPerLogicalSector + " bytes<br/><b>[512e Drive]</b>"
					$4KBDriveE += $device.DeviceID
				}
				elseif ($device.BytesPerSector -eq 4096)
				{
					$4KNativeDetected = $true
					if ($AlignmentDescriptor.BytesPerPhysicalSector -eq 4096)
					{
						$4KDriveType = "Physical: " + ($AlignmentDescriptor.BytesPerPhysicalSector.ToString()) + "<b><font color=`"red`">[4KB Native]</font></b>"
					}
					else
					{
						$4KDriveType = "<b><font color=`"red`">[4KB Native]</font></b>"
					}					
				}
				else 
				{
					$4KNativeDetected = $true
					$4KDriveType = " - Logical: " + $AlignmentDescriptor.BytesPerLogicalSector + " bytes<br/><b><font color=`"red`">[4KB Native]</font></b>"
					$4KBDriveN += $device.DeviceID
				}
				
			}
			
			add-member -inputobject $SectorSize_Summary  -membertype noteproperty -name ($device.DeviceID + " " + $DriveLetterString) -value ($BytesDisplay + $4KDriveType)
			
			if ($512EDriveDetected)
			{
				Write-GenericMessage -RootCauseID "RC_4KDriveDetected" -PublicContentURL "http://support.microsoft.com/kb/2510009" -Verbosity "Informational" -InformationCollected $InformationCollected -Visibility 4 -MessageVersion 4 -SupportTopicsID 8122
				$512EDriveDetected = $false
				$RC_4KDriveDetected = $true
			}
						
			if ($4KNativeDetected)
			{
				Write-GenericMessage -RootCauseID "RC_4KNativeDriveDetected" -PublicContentURL "http://support.microsoft.com/kb/2510009" -Verbosity "Error" -InformationCollected $InformationCollected -MessageVersion 3 -Visibility 4 -MessageVersion 4 -SupportTopicsID 8122
				$RC_4KNativeDriveDetected = $true
				$4KNativeDetected = $false
			}
			
	    }
		
		$SectorSize_Summary | ConvertTo-Xml2 | update-diagreport -id 99_SectorSizeSummary -name "Drive Sector Size Information" -verbosity informational
		
		if ($RC_4KDriveDetected)
		{	

			Update-DiagRootCause -id "RC_4KDriveDetected" -Detected $true
			
			if (-not (KB982018IsInstalled))
			{
				$XMLFileName = "..\KB982018.XML"
				($KB982018Binaries_Summary | ConvertTo-Xml2).Save($XMLFileName)
				
				Update-DiagRootCause -id "RC_KB982018IsNotInstalled" -Detected $true 
				Write-GenericMessage -RootCauseID "RC_KB982018IsNotInstalled" -PublicContentURL "http://support.microsoft.com/kb/982018" -Verbosity "Error" -MessageVersion 3 -Visibility 4 -MessageVersion 3 -SupportTopicsID 8122
			}
			else
			{
				Update-DiagRootCause -Id "RC_KB982018IsNotInstalled" -Detected $false
			}
		}
		else
		{
			Update-DiagRootCause -Id "RC_4KDriveDetected" -Detected $false
		}
		
		if ($RC_4KNativeDriveDetected)
		{
			Update-DiagRootCause -id "RC_4KNativeDriveDetected" -Detected $true
			Write-GenericMessage -RootCauseID "RC_4KNativeDriveDetected" -Verbosity "Error" -PublicContentURL "http://support.microsoft.com/kb/2510009" -Visibility 4 -MessageVersion 3 -SupportTopicsID 8122
		}
		else
		{
			Update-DiagRootCause -Id "RC_4KNativeDriveDetected" -Detected $false
		}
	}
}
# SIG # Begin signature block
# MIIbAwYJKoZIhvcNAQcCoIIa9DCCGvACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7Ce/H0VhUIFdnQPtHAAluZ8s
# j7CgghWCMIIEwzCCA6ugAwIBAgITMwAAAEyh6E3MtHR7OwAAAAAATDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTMxMTExMjIxMTMx
# WhcNMTUwMjExMjIxMTMxWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkMwRjQtMzA4Ni1ERUY4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsdj6GwYrd6jk
# lF18D+Z6ppLuilQdpPmEdYWXzMtcltDXdS3ZCPtb0u4tJcY3PvWrfhpT5Ve+a+i/
# ypYK3EbxWh4+AtKy4CaOAGR7vjyT+FgyeYfSGl0jvJxRxA8Q+gRYtRZ2buy8xuW+
# /K2swUHbqs559RyymUGneiUr/6t4DVg6sV5Q3mRM4MoVKt+m6f6kZi9bEAkJJiHU
# Pw0vbdL4d5ADbN4UEqWM5zYf9IelsEEXb+NNdGbC/aJxRjVRzGsXUWP6FZSSml9L
# KLrmFkVJ6Sy1/ouHr/ylbUPcpjD6KSjvmw0sXIPeEo1qtNtx71wUWiojKP+BcFfx
# jAeaE9gqUwIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFLkNrbNN9NqfGrInJlUNIETY
# mOL0MB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAAmKTgav6O2Czx0HftcqpyQLLa+aWyR/lHEMVYgkGlIVY+KQ
# TQVKmEqc++GnbWhVgrkp6mmpstXjDNrR1nolN3hnHAz72ylaGpc4KjlWRvs1gbnk
# PUZajuT8dTdYWUmLTts8FZ1zUkvreww6wi3Bs5tSLeA1xbnBV7PoPaE8RPIjFh4K
# qlk3J9CVUl6ofz9U8IHh3Jq9ZdV49vdMObvd4NY3DpGah4xz53FkUvc+A9jGzXK4
# NDSYW4zT9Qim63jGUaANDm/0azxAGmAWLKkGUp0cE5DObwIe6nucs/b4l2DyZdHR
# H4c6wXXwQo167Yxysnv7LIq0kUdU4i5pzBZUGlkwggTsMIID1KADAgECAhMzAAAA
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
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBOswggTn
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAAAsBGvCovQO5/d
# AAEAAACwMAkGBSsOAwIaBQCgggEDMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRY
# fduN/1K2uIQhrSbySbqnU1IuNzCBogYKKwYBBAGCNwIBDDGBkzCBkKB2gHQARABJ
# AEEARwBfAEMAVABTAF8ARwBlAG4AZQByAGEAbABfAFIAZQBwAG8AcgB0AHMAXwBn
# AGwAbwBiAGEAbABfAFQAUwBfAEQAcgBpAHYAZQBTAGUAYwB0AG8AcgBTAGkAegBl
# AEkAbgBmAG8ALgBwAHMAMaEWgBRodHRwOi8vbWljcm9zb2Z0LmNvbTANBgkqhkiG
# 9w0BAQEFAASCAQAEp1Ztdt8h3pZLA3Sy7PiMTZa4K9e/h9Tg6+JbSnvnVegP6yoN
# nwcUITkmu5Hi0OEFA8s3jR9lkWrvcOt5wS93WmAaj/8x1PhegtxENdfG5PCcdN5H
# y1sCigoQtscYjbOM9/UjhcjL8EhIELjJPPMS7Pz0x+TXFTKkzIZMsFu0wx6GGKh2
# z7+OxoG5/0iKcWpsPwkPXVOIQOUYB40KG1goPBmoZgBuVE/UiGbeheR6l5dWU8J5
# E3VpsTopzh82+OI6SpWZKxsgk99gXZ2rTdRKxO4B7j5b1FRmEbJsn4U+vTPNTDrd
# CfTuAak6YhNIgum1EniQvzwA2eZEtPf/Pqk4oYICKDCCAiQGCSqGSIb3DQEJBjGC
# AhUwggIRAgEBMIGOMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xITAfBgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQQITMwAAAEyh6E3M
# tHR7OwAAAAAATDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEH
# ATAcBgkqhkiG9w0BCQUxDxcNMTQwMjI0MTczODAyWjAjBgkqhkiG9w0BCQQxFgQU
# 348QFSKzXp9UCmDMlKNTttatJqAwDQYJKoZIhvcNAQEFBQAEggEAabXPMIN18Wpo
# SNDaLBT0oNe/pp/h7VZxAcrgUmvHZyE+sWZdIzNvb/BOOHkxmNm0DKEgC2VB4XYH
# UYZbTBsnnlbZX47fi7kGAaPWCWTDm0fug7n/om0EfXfXOxq5uQeMJjVymx2cX2em
# 3BvgRGXvw4gLCAl+2UqkGximUtpkJrcSioeAoMLS+/Ba7tN7dnbSZj5e0cXrrUXc
# lolNF4jcBcK7TDtjgpLkCpJFopdK5jKhS6YsrA1JMgDfRcYocAaofw7eR/NVYSq9
# dcwT7aZqfp+OpYc6w0tv/D6ornLUCyceuBGQ1p9UYh7dJv6xsTz0/gMA3Wh+oGKF
# 4EkTtbTGXg==
# SIG # End signature block

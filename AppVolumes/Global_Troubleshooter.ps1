$debug = $true
# Load Common Library:
$ComputerName = $Env:computername
$OSVersion = [Environment]::OSVersion.Version
. ./utils_cts.ps1


$FirstTimeExecution = FirstTimeExecution

if ($FirstTimeExecution) {
    Run-DiagExpression .\DC_BasicSystemInformation.ps1
    
    $SaveReport = get-diaginput -id "I_SaveReport" 
    
    if ([bool]::Parse($SaveReport))
    {
        Update-DiagRootCause -Id 'SaveReport' -Detected $true 
        $filename = "\$($env:COMPUTERNAME)_AppVolumesDiag_$(Get-Date -Format yyyy-MM-dd_hh-mm-ss-tt)" 
       
        
        $Global:reportpath=$(get-diaginput -id "I_SelectFile")[0]+$filename 
        
        $Global:SaveReport=$true
        
        Run-DiagExpression .\DC_MSInfo.ps1
        Run-DiagExpression .\DC_PStat.ps1
        Run-DiagExpression .\DC_RegistrySetupPerf.ps1
        Run-DiagExpression .\DC_ChkSym.ps1
        Run-DiagExpression .\DC_ScheduleTasks.ps1
        Run-DiagExpression .\DC_Verifier.ps1
        Run-DiagExpression .\DC_ServerManagerInfo.ps1
        Run-DiagExpression .\DC_UpdateHistory.ps1
        Run-DiagExpression .\DC_BCDInfo.ps1
        Run-DiagExpression .\DC_WindowsUpdateLog.ps1
        Run-DiagExpression .\TS_Virtualization.ps1
        Run-DiagExpression .\DC_Autoruns.ps1
        Run-DiagExpression .\DC_VMGuestSetupLogCollector.ps1
        Run-DiagExpression .\DC_RSoP.ps1
        Run-DiagExpression .\DC_UserRights.ps1
        Run-DiagExpression .\DC_Whoami.ps1
        Run-DiagExpression .\DC_TCPIP-Component.ps1
        Run-DiagExpression .\DC_DhcpClient-Component.ps1
        Run-DiagExpression .\DC_DNSClient-Component.ps1
        Run-DiagExpression .\DC_WINSClient-Component.ps1
        Run-DiagExpression .\DC_SMBClient-Component.ps1
        Run-DiagExpression .\DC_SMBServer-Component.ps1
        Run-DiagExpression .\DC_RPC-Component.ps1
        Run-DiagExpression .\DC_Firewall-Component.ps1
        Run-DiagExpression .\DC_IPsec-Component.ps1
        Run-DiagExpression .\DC_PFirewall.ps1
        Run-DiagExpression .\DC_PerfPrintEventLogs.ps1
        Run-DiagExpression .\DC_RegPrintKeys.ps1
        Run-DiagExpression .\DC_Devcon.ps1
        Run-DiagExpression .\DC_SanStorageInfo.ps1
    
        Run-DiagExpression .\DC_SystemAppEventLogs.ps1
            
        
        
    } 
    else
    {
        $Global:SaveReport=$false
    }
    

    #Run your .ps1 files from here
    #-----------------------------
    

    Run-DiagExpression .\TS_AppVolumesService.ps1
    Run-DiagExpression .\TS_ProcessInfo.ps1
    Run-DiagExpression .\TS_PrintInfo.ps1
    Run-DiagExpression .\TS_DriveSectorSizeInfo.ps1
    Run-DiagExpression .\TS_DetectSplitIO.ps1
    Run-DiagExpression .\TS_SBSL_MCAfee_EEPC_SlowBoot.ps1
    Run-DiagExpression .\TS_SEPProcessHandleLeak.ps1
    Run-DiagExpression .\TS_RPCUnauthenticatedSessions.ps1
    Run-DiagExpression .\TS_NTFSMetafilePerfCheck.ps1
    Run-DiagExpression .\TS_KnownKernelTags.ps1
    
    
        
    EndDataCollection

} else {
    #2nd execution. Delete the temporary flag file then exit
    WriteTo-StdOut "SecondExecutution defined"
    EndDataCollection -DeleteFlagFile $True
    
    if ($Global:SaveReport){
        
        Save-AppVolReport $Global:reportpath
        
    }

    
}

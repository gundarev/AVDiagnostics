'************************************************
'ProcessPerfInfo Script
'Version 2.1.5
'Date: 05-07-2013
'Author: Andre Teixeira - andret@microsoft.com
'************************************************

Option Explicit
Dim objShell
Dim objFSO
Dim objWMIService, objWMIReg

Dim srtBaseFileName, intCurrentTzBias
Dim objTXTFile, objXMLFile
Dim bGenerateSDP2Alerts
Dim bGenerateScriptedDiagXMLAlerts
Dim arrAlertsXML, arrScriptedDiagXML, strHTMLOutputfilename
Dim arrAlertsTXTType, arrAlertsTXTCategory, arrAlertsTXTMessage, arrAlertsTXTRecommendation
Dim strSystemDecimalSymbol
Dim arrAlwaysShowProcess
Dim xmlRootCauses

Const Fixed = 2, Removable = 1, ForReading = 1, ForWriting = 2

Const adDBTimeStamp = 135
Const adVarChar = 200
Const adBigInt = 20

Const ALERT_INFORMATION = 1
Const ALERT_WARNING = 2
Const ALERT_ERROR = 3

Const ALERT_CATEGORY_KERNEL_MEMORY_INFO = "Kernel Memory Information"

Const ALERT_CATEGORY_MEMORY_PERF = "Memory Performance Issue"
Const ALERT_CATEGORY_PROCESS_PERF = "Processes/Performance"
Const ALERT_CATEGORY_KERNEL_MEMORY_PERF = "Kernel Memory Performance"

Const OpenFileMode = -2

Dim MAX_ITEMS

Const HANDLE_LIMIT_MEDIUM = 40000
Const HANDLE_LIMIT_HIGH = 50000

Const SYSPTES_LIMIT_MEDIUM = 5500
Const SYSPTES_LIMIT_HIGH = 4000

Const COMMITED_LIMIT_MEDIUM = 80
Const COMMITED_LIMIT_HIGH = 90

Const POOL_LIMIT_PERCENTAGE_OF_TOTAL_MEDIUM = 0.65
Const POOL_LIMIT_PERCENTAGE_OF_TOTAL_HIGH = 0.72

Dim PAGEDPOOL_LIMIT_MEDIUM
Dim PAGEDPOOL_LIMIT_HIGH

Dim NONPAGEDPOOL_LIMIT_MEDIUM
Dim NONPAGEDPOOL_LIMIT_HIGH

Const OUTPUT_BASENAME = "ProcessesPerfInfo"


Main

Sub Main()
    Dim strCommandLineArgument, x
    MAX_ITEMS = 5
    
    'On Error Resume Next
    
    wscript.Echo ""
    wscript.Echo "ProcessPerfInfo Script"
    wscript.Echo "Revision 2.1.5"
    wscript.Echo "2010-2013 Microsoft Corporation"
    wscript.Echo ""
   
    Set objShell = CreateObject("WScript.Shell")
    Set objFSO = CreateObject("Scripting.FileSystemObject")

    bGenerateScriptedDiagXMLAlerts = False
    If wscript.Arguments.Count > 0 Then
        For x = 0 To (wscript.Arguments.Count - 1)
            strCommandLineArgument = wscript.Arguments(x)
            If LCase(strCommandLineArgument) = "/generatescripteddiagxmlalerts" Then
                bGenerateScriptedDiagXMLAlerts = True
            ElseIf LCase(strCommandLineArgument) = "/generatesdp2alerts" Then
                bGenerateSDP2Alerts = True
            ElseIf LCase(Left(strCommandLineArgument, 11)) = "/alwaysshow" Then
                arrAlwaysShowProcess = Split(Right(strCommandLineArgument, Len(strCommandLineArgument) - 12), ";")
            End If
        Next
    End If


    If Len(ReplaceEnvVars("%PROCESSOR_ARCHITEW6432%")) > 0 Then 'Running in WOW, we need to make sure we start the 64 bit version
        wscript.Echo "Script engine is under WOW. Trying to start it in 64 bit mode..."
        If RunScriptin64BitMode Then
            Exit Sub
        Else
            'Script failed to run in 64-bit mode, let's fallback to 32 bit mode.
            doWork
        End If
    Else
        doWork
    End If
    wscript.Echo ""
    wscript.Echo "****** Script Finished ******"
End Sub

Sub doWork()
    Dim strTXTFile, strXMLFile
    intCurrentTzBias = ObtainTimeZoneBias
    
    wscript.Echo ""
    Err.Clear
    
    strSystemDecimalSymbol = Mid(CStr(1.2), 2, 1) 'Obtain the numeric decimal separator
        
    srtBaseFileName = objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                                            "_" + OUTPUT_BASENAME
    
    strTXTFile = srtBaseFileName & ".TXT"
    
    wscript.Echo "Creating " & strTXTFile & "..."
    
    Set objTXTFile = objFSO.OpenTextFile(strTXTFile, ForWriting, True, -2)
    
    strXMLFile = srtBaseFileName & ".XML"
    
    Set objXMLFile = objFSO.OpenTextFile(strXMLFile, ForWriting, True, -2)
    
    If Err.Number <> 0 Then
        DisplayError "Creating " & strXMLFile, Err.Number, Err.Source, Err.Description
    Else
        objXMLFile.WriteLine "<?xml version='1.0' encoding='iso-8859-1'?>"
        'objXMLFile.WriteLine "<?xml version='1.0' encoding='UTF-8'?>"
        objXMLFile.WriteLine "<?xml-stylesheet type=""text/xsl"" href=""ProcessInfo.xsl""?>"
        objXMLFile.WriteLine "<Root>"
        
        WriteGeneralInformation
        DumpProcessInformation
        DumpKernelMemoryInformation
        
        WriteAlertsToXML
        
        objXMLFile.WriteLine "</Root>"
        objXMLFile.Close
        Set objXMLFile = Nothing
        
        CreateHTMFile
        wscript.Echo ""
        wscript.Echo "Closing file : '" & strTXTFile & "'"
        objTXTFile.Close
        Set objTXTFile = Nothing
        
        WriteAlertsToTXT (strTXTFile)
        
        If bGenerateScriptedDiagXMLAlerts Then WriteAlertsToScriptedDiagXML srtBaseFileName
        
    End If
    
End Sub

Function RunScriptin64BitMode()
    On Error Resume Next
    Dim strCmdArguments
    Dim strStdOutFilename
    Dim objStdoutFile
    Dim strArguments, x
    If LCase(objFSO.GetExtensionName(wscript.ScriptFullName)) = "vbs" Then
        strStdOutFilename = objFSO.GetSpecialFolder(2) & objFSO.GetFileName(wscript.ScriptFullName) & ".log"
        strArguments = ""
        If wscript.Arguments.Count > 0 Then
            For x = 0 To wscript.Arguments.Count - 1
                strArguments = strArguments & " " & Chr(34) & wscript.Arguments(x) & Chr(34) & " "
            Next
        End If
        strCmdArguments = "/c " & objFSO.GetDriveName(wscript.ScriptFullName) & " & cd " & Chr(34) & objFSO.GetParentFolderName(wscript.ScriptFullName) & Chr(34) & " & cscript.exe " & Chr(34) & wscript.ScriptFullName & Chr(34) & strArguments & " > " & Chr(34) & strStdOutFilename & Chr(34)
        ProcessCreate ReplaceEnvVars("%windir%\System32\CMD.EXE"), strCmdArguments
        If objFSO.FileExists(strStdOutFilename) Then
            Set objStdoutFile = objFSO.OpenTextFile(strStdOutFilename, ForReading, False, -2)
            While Not objStdoutFile.AtEndOfStream
                wscript.Echo objStdoutFile.ReadLine
            Wend
            objStdoutFile.Close
            Set objStdoutFile = Nothing
            objFSO.DeleteFile strStdOutFilename, True
            If Err.Number = 0 Then
                RunScriptin64BitMode = True
            End If
        Else
            wscript.Echo "An error ocurred running the command and resulting file was not created:"
            wscript.Echo ReplaceEnvVars("%windir%\System32\CMD.EXE") & strCmdArguments
            wscript.Echo ""
            wscript.Echo ""
            RunScriptin64BitMode = False
        End If
    Else
        RunScriptin64BitMode = False
    End If
End Function

Sub WriteAlertsToScriptedDiagXML(strBaseFileName)
    Dim strScriptedDiagXMLFileName, objScriptedDiagXMLFile, strLine
    If Not IsEmpty(arrScriptedDiagXML) Then
        strScriptedDiagXMLFileName = strBaseFileName + "Alerts.XML"
        wscript.Echo "Writing file : '" & strScriptedDiagXMLFileName & "'"
        Set objScriptedDiagXMLFile = objFSO.OpenTextFile(strScriptedDiagXMLFileName, ForWriting, True, OpenFileMode)
        objScriptedDiagXMLFile.WriteLine "<?xml version=""1.0""?><Root>"
        For Each strLine In arrScriptedDiagXML
            objScriptedDiagXMLFile.WriteLine strLine
        Next
        objScriptedDiagXMLFile.WriteLine "</Root>"
        objScriptedDiagXMLFile.Close
        
        xmlRootCauses = "<?xml version=""1.0""?><Root>" + xmlRootCauses + "</Root>"
        Set objScriptedDiagXMLFile = objFSO.OpenTextFile(strBaseFileName + "RootCauses.XML", ForWriting, True, OpenFileMode)
        objScriptedDiagXMLFile.WriteLine xmlRootCauses
    End If
End Sub

Sub AddExternalAlert(intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation, intPriority)
    Dim strAlertType, strAlertXML
    If bGenerateScriptedDiagXMLAlerts Then
        Select Case intAlertType
            Case ALERT_INFORMATION
                strAlertType = "Informational"
            Case ALERT_WARNING
                strAlertType = "Warning"
            Case ALERT_ERROR
                strAlertType = "Error"
            Case Else
                strAlertType = "Informational"
        End Select
        
        strAlertXML = "<Alert Priority=" & Chr(34) & CStr(intPriority) & Chr(34) & " Type=" & Chr(34) & strAlertType & Chr(34) & " Category=" & Chr(34) & strAlertCategory & Chr(34) & ">" & _
                      "<Objects><Object Type=" & Chr(34) & "System.Management.Automation.PSCustomObject" & Chr(34) & " >" & _
                      "<Property Name=" & Chr(34) & "Message" & Chr(34) & ">" & strAlertMessage & "</Property>" & _
                      iif(Len(strAlertRecommendation) > 0, "<Property Name=" & Chr(34) & "Recommendation" & Chr(34) & ">" & strAlertRecommendation & "</Property>", "") & _
                      "</Object></Objects>" & _
                      "</Alert>"
                      
        AddtoArray arrScriptedDiagXML, strAlertXML
        
    ElseIf bGenerateSDP2Alerts Then
        AddMSDTPLAAlert intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation, intPriority
    End If
End Sub


Sub DisplayError(strErrorLocation, errNumber, errSource, errDescription)
    On Error Resume Next
    wscript.Echo ""
    If errNumber <> 0 Then
        wscript.Echo "Error 0x" & HexFormat(errNumber) & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
        wscript.Echo errSource & " - " & errDescription
    Else
        wscript.Echo "An error ocurred!. " & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
    End If
    wscript.Echo ""
End Sub

Sub ProcessCreate(strProcess, strParameters)

    Const SW_HIDE = 0
    Dim strComputer, i, objStartup, objProcess, errResult, objConfig, intProcessID, colProcess, bExit
    strComputer = "."
    i = 0
    
    On Error Resume Next
    
    OpenWMIService
                    
    Set objStartup = objWMIService.Get("Win32_ProcessStartup")
    Set objConfig = objStartup.SpawnInstance_
                    objConfig.ShowWindow = SW_HIDE
    
    Set objProcess = objWMIService.Get("Win32_Process")

    If Err.Number <> 0 Then
        DisplayError "Accessing Win32_Process/ Win32_ProcessStartup WMI classes", Err.Number, Err.Source, Err.Description
        Exit Sub
    End If

    errResult = objProcess.Create(strProcess & " " & strParameters, Null, objConfig, intProcessID)
    
    If errResult = 0 Then
        Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
        
        i = 0
        While (Not bExit) And (i < 1000) 'Wait for exit for up 1000 times
            Set colProcess = objWMIService.ExecQuery _
                            ("Select ProcessID From Win32_Process where ProcessID = " & CStr(intProcessID))
            If colProcess.Count = 0 Then
                bExit = True
            Else
                wscript.Sleep 500
                i = i + 1
            End If
        Wend
    Else
        DisplayError "Creating a process using the command line: " & strProcess & " " & strParameters, 5000, "WMI", "Error 0x" & HexFormat(errResult)
    End If

End Sub

Sub OpenTag(strTag)
    objXMLFile.WriteLine "<" & strTag & ">"
End Sub

Sub CloseTag(strTag)
    objXMLFile.WriteLine "</" & strTag & ">"
End Sub

Function ObtainTimeZoneBias()
    ' Obtain local Time Zone bias from machine registry.
    On Error Resume Next
    Err.Clear
    
    Dim lngBiasKey, lngBias, k
    
    lngBiasKey = objShell.RegRead("HKLM\System\CurrentControlSet\Control\TimeZoneInformation\ActiveTimeBias")
      
    If UCase(TypeName(lngBiasKey)) = "LONG" Then
      lngBias = lngBiasKey
    ElseIf UCase(TypeName(lngBiasKey)) = "VARIANT()" Then
      lngBias = 0
      For k = 0 To UBound(lngBiasKey)
        lngBias = lngBias + (lngBiasKey(k) * 256 ^ k)
      Next
    End If
    
    If Err.Number = 0 Then
        ObtainTimeZoneBias = lngBias
    Else
        DisplayError "Calculating timezone bias. ActiveBias:" & CStr(lngBiasKey), Err.Number, Err.Source, Err.Description
        ObtainTimeZoneBias = 0
    End If

    
End Function

Sub WriteGeneralInformation()
    Dim colItems, objItem, x, objDrive, objFile, strDepPolicy, strRegValue, intOSSKU, strWindowsVersion, intWindowsVersion
    
    On Error Resume Next
    OpenWMIService
    
    LineOut "Processes Information from : ", objShell.Environment("PROCESS").Item("COMPUTERNAME"), False, False, "Title"
    LineOut "Local time : ", CStr(Now), False, False, "TimeField"
    
    OpenTag "Section"
    LineOut " -- General Information", "", False, False, "SectionTitle"
    LineOut "", "", True, False, ""

    Set colItems = objWMIService.ExecQuery("Select * from Win32_OperatingSystem", , 48)
    
    strRegValue = ""
    intOSSKU = ""
    strWindowsVersion = ""
    
    For Each objItem In colItems

        intOSSKU = objItem.OperatingSystemSKU
        strWindowsVersion = objItem.Version
        intWindowsVersion = GetWindowsVersion(strWindowsVersion)

        LineOut "    Operating System     : ", objItem.Caption, False, False, "Item"
        LineOut "    Type                 : ", CStr(ObtainOSProcessorAddressWidth) + " bit", False, False, "Item"
        If Not IsNull(objItem.CSDVersion) Then
            LineOut "    Service Pack         : ", objItem.CSDVersion, False, False, "Item"
        Else
            LineOut "    Service Pack         : ", "Not Installed", False, False, "Item"
        End If
        
        If Len(intOSSKU) > 0 Then
            LineOut "    Operating System SKU : ", GetOSSKU(intOSSKU), False, False, "Item"
        End If
        
        strRegValue = objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BuildLab")
        If strRegValue <> "" Then
            LineOut "    Build                : ", strRegValue, False, False, "Item"
            strRegValue = ""
        Else
            LineOut "    Build                : ", objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Build"), False, False, "Item"
            strRegValue = ""
        End If
    
    Next
    
    LineOut "", "", True, False, ""
    
    WriteMemoryInfo
    WriteMainMemoryCounters
    
    CloseTag "Section"
    LineOut "", "", True, False, ""

End Sub

Function ObtainOSProcessorAddressWidth()
    Dim ProcArch
    If Len(ReplaceEnvVars("%PROCESSOR_ARCHITEW6432%")) > 0 Then
        ObtainOSProcessorAddressWidth = 64
    Else
        ProcArch = UCase(ReplaceEnvVars("%PROCESSOR_ARCHITECTURE%"))
        Select Case ProcArch
            Case "X86"
                ObtainOSProcessorAddressWidth = 32
            Case "AMD64", "IA64"
                ObtainOSProcessorAddressWidth = 64
        End Select
    End If
End Function

Function GetWindowsVersion(strWindowsVersion)
    'wmi Windows version is always separated with ., such as 5.2.x, however this may represent a problem if the decimal separator is not a '.'
    'First test the decimal separator
    Dim strSeparator
    strSeparator = Mid(CStr(1.2), 2, 1)
    GetWindowsVersion = CDbl(Replace(Left(strWindowsVersion, 3), ".", strSeparator))
End Function


Sub WriteMemoryInfo()
    
    Dim colItems, objItem, x, objDrive, objFile, strDepPolicy, strBootOptions
    
    On Error Resume Next
    
    OpenWMIService
    OpenTag "SubSection"

    LineOut " -- Memory Information", "", False, False, "SectionTitle"
    LineOut "", "", True, False, ""

    Set colItems = objWMIService.ExecQuery("Select * from Win32_OperatingSystem", , 48)
    
    For Each objItem In colItems
        Select Case objItem.DataExecutionPrevention_SupportPolicy
            Case 0
                strDepPolicy = "Always Off"
            Case 1
                strDepPolicy = "Always On"
            Case 2
                strDepPolicy = "Opt In"
            Case 3
                strDepPolicy = "Opt Out"
            Case Else
                strDepPolicy = "(Unknown - " & CStr(objItem.DataExecutionPrevention_SupportPolicy) & ")"
        End Select
        
        strBootOptions = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemStartOptions")
        
        LineOut "    Total Visible Memory : ", FormatNumber(objItem.TotalVisibleMemorySize / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    Free Physical Memory : ", FormatNumber(objItem.FreePhysicalMemory / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    Total Virtual Memory : ", FormatNumber(objItem.TotalVirtualMemorySize / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    Free Virtual Memory  : ", FormatNumber(objItem.FreeVirtualMemory / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    Page File Commit Size: ", FormatNumber(objItem.SizeStoredInPagingFiles / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    Free Pagefile Space  : ", FormatNumber(objItem.FreeSpaceInPagingFiles / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    PAE Enabled          : ", iif(objItem.PAEEnabled, "True", "False"), False, False, "Item"
        LineOut "    DEP Available        : ", iif(objItem.DataExecutionPrevention_Available, "True", "False"), False, False, "Item"
        If Len(strDepPolicy > 0) Then LineOut "    DEP Support Policy   : ", strDepPolicy, False, False, "Item"
        LineOut "    Boot Options         : ", iif(Len(strBootOptions), strBootOptions, "(None)"), False, False, "Item"
        LineOut "    Current Local Time   : ", ConvertWMIDateTime(objItem.LocalDateTime), False, False, "Item"
        LineOut "    Last Boot Up Time    : ", ConvertWMIDateTime(objItem.LastBootUpTime), False, False, "Item"
    Next
    
    LineOut "", "", True, False, ""
    CloseTag "SubSection"
    
End Sub

Function ConvertWMIDateTime(ByVal WmiDatetime)
    On Error Resume Next
    
    Dim dtUTCDateTime, dtLocalDateTime, hr, ampm, mn, sec, intCurrentBiasfromWMIDateTime, strDate, strTime
    dtUTCDateTime = DateSerial(Left(WmiDatetime, 4), Mid(WmiDatetime, 5, 2), Mid(WmiDatetime, 7, 2)) + _
                    TimeSerial(Mid(WmiDatetime, 9, 2), Mid(WmiDatetime, 11, 2), Mid(WmiDatetime, 13, 2))
        
    If intCurrentBiasfromWMIDateTime = -1 Then
        intCurrentBiasfromWMIDateTime = -(CInt(Right(WmiDatetime, 4)) + intCurrentTzBias)
    End If
    dtLocalDateTime = DateAdd("n", intCurrentBiasfromWMIDateTime, dtUTCDateTime)
    
    hr = Hour(dtLocalDateTime)
    If hr >= 12 Then
      If hr <> 12 Then
          hr = CStr(hr - 12)
          hr = Right("0" & hr, 2)
      End If
      ampm = "PM"
    Else
      ampm = "AM"
      If hr = "0" Then
        hr = "12"
      Else
        hr = Right("0" & hr, 2)
      End If
    End If
    
    mn = Right("0" & Minute(dtLocalDateTime), 2)
    sec = Mid(WmiDatetime, 13, 2)
    
    strDate = Right("0" & Month(dtLocalDateTime), 2) & "/" & Right("0" & Day(dtLocalDateTime), 2) & "/" & CStr(Year(dtLocalDateTime))
    strTime = hr & ":" & mn & ":" & sec & " " & ampm
    ConvertWMIDateTime = strDate & " " & strTime
    
End Function

Function AddRootCause(strRootCauseName, intAlertType, ExpectedValue, CurrentValue, param1, param2)
    Dim strAlertType
    Select Case intAlertType
        Case ALERT_INFORMATION
            strAlertType = "Informational"
        Case ALERT_WARNING
            strAlertType = "Warning"
        Case ALERT_ERROR
            strAlertType = "Error"
        Case Else
            strAlertType = "Informational"
    End Select

    xmlRootCauses = xmlRootCauses + "<RootCause name=" + Chr(34) + strRootCauseName + Chr(34)
    xmlRootCauses = xmlRootCauses + " Type=" + Chr(34) + strAlertType + Chr(34)
    xmlRootCauses = xmlRootCauses + " ExpectedValue=" + Chr(34) + CStr(ExpectedValue) + Chr(34)
    xmlRootCauses = xmlRootCauses + " CurrentValue=" + Chr(34) + CStr(CurrentValue) + Chr(34)
    If Len(param1) > 0 Then
        xmlRootCauses = xmlRootCauses + " param1=" + Chr(34) + param1 + Chr(34)
    End If
    If Len(param2) > 0 Then
        xmlRootCauses = xmlRootCauses + " param2=" + Chr(34) + param2 + Chr(34)
    End If
    xmlRootCauses = xmlRootCauses + " />"
End Function

Function WriteMainMemoryCounters()
 
    On Error Resume Next
 
    Dim objItem, colItems
    Dim xmlDisplayValue, txtDisplayValue, RAWValue
    
    OpenTag "SubSection"
    
    LineOut " -- Machine Memory Performance Counters", "", False, False, "SectionTitle"
    LineOut "", "", True, False, ""

    Err.Clear
    
    Set colItems = objWMIService.ExecQuery("Select * from Win32_PerfRawData_PerfOS_Memory ", , 48)
    For Each objItem In colItems
        If Err.Number = 0 Then
            LineOut "    Pool Nonpaged Bytes Usage      : ", GetDisplayValue("Bytes", objItem.PoolNonpagedBytes), False, False, "Item"
            LineOut "    Pool Paged Bytes Usage         : ", GetDisplayValue("Bytes", objItem.PoolPagedBytes), False, False, "Item"
            
            txtDisplayValue = FormatNumber(objItem.FreeSystemPageTableEntries, 0)
            xmlDisplayValue = txtDisplayValue
            
            If (objItem.FreeSystemPageTableEntries < SYSPTES_LIMIT_MEDIUM) Then
                    Dim XMLMessage, xmlRecommendation, txtRecommendation, warningType
                    
                    If (objItem.FreeSystemPageTableEntries < SYSPTES_LIMIT_HIGH) Then
                        warningType = ALERT_ERROR
                        xmlDisplayValue = "<font face='Webdings' color='Red'>n </font><b>" + txtDisplayValue + "</b>"
                    Else
                        warningType = ALERT_WARNING
                        xmlDisplayValue = "<font face='Webdings' color='Orange'>n </font><b>" + txtDisplayValue + "</b>"
                    End If
                    
                    XMLMessage = "This system is currently running under low System PTEs"
                    xmlRecommendation = "This system is reporting that there are only <b>" + txtDisplayValue + "</b> System Page Table Entries (SysPTEs), while the minimum recommended value is <b>" + FormatNumber(SYSPTES_LIMIT_MEDIUM, 0) + "</b>. The following <a target='_blank' href='http://blogs.technet.com/askperf/archive/2007/09/25/troubleshooting-server-hangs-part-one.aspx'>Blog Entry</a> may contain more information about this problem."
                    txtRecommendation = "This system is reporting that there are only " + txtDisplayValue + " System Page Table Entries (SysPTEs), while the minimum recommended value is " + FormatNumber(SYSPTES_LIMIT_MEDIUM, 0) + ". The following blog entry may contain more information about this problem: http://blogs.technet.com/askperf/archive/2007/09/25/troubleshooting-server-hangs-part-one.aspx"
                    
                    AddRootCause "RC_LowSysPTEs", warningType, FormatNumber(SYSPTES_LIMIT_MEDIUM, 0), txtDisplayValue, "", ""
                    AddXMLAlert warningType, ALERT_CATEGORY_MEMORY_PERF, XMLMessage, xmlRecommendation, 1000
                    AddTXTAlert warningType, ALERT_CATEGORY_MEMORY_PERF, XMLMessage, txtRecommendation
                    AddExternalAlert warningType, ALERT_CATEGORY_MEMORY_PERF, XMLMessage, xmlRecommendation, 1000
            End If
            
            LineOut "    Free System Page Table Entries : ", xmlDisplayValue, False, True, "Item"
            LineOut "    Free System Page Table Entries : ", txtDisplayValue, True, False, "Item"
            
            RAWValue = objItem.PercentCommittedBytesInUse / objItem.PercentCommittedBytesInUse_Base * 100
            txtDisplayValue = FormatNumber(RAWValue, 1) + "%"
            xmlDisplayValue = txtDisplayValue
                    
            If (RAWValue > COMMITED_LIMIT_MEDIUM) Then
                    
                    If (RAWValue > COMMITED_LIMIT_HIGH) Then
                        warningType = ALERT_ERROR
                        xmlDisplayValue = "<font face='Webdings' color='Red'>n </font><b>" + txtDisplayValue + "</b>"
                    Else
                        warningType = ALERT_WARNING
                        xmlDisplayValue = "<font face='Webdings' color='Orange'>n </font><b>" + txtDisplayValue + "</b>"
                    End If
                    
                    XMLMessage = "This system is currently running under low virtual memory."
                    xmlRecommendation = "This system is reporting that there are only <b>" + FormatNumber(100 - RAWValue, 1) + "%</b> of available virtual memory on the system. This usually means that your page file is small or that there are processes using too much memory on the system. The following <a target='_blank' href='http://blogs.technet.com/askperf/archive/2008/01/25/an-overview-of-troubleshooting-memory-issues.aspx'>Blog Entry</a> may contain more information about this issue."
                    txtRecommendation = "This system is reporting that there are only " + FormatNumber(100 - RAWValue, 1) + "% of available virtual memory on the system. This usually means that your page file is small or that that there are processes using too much memory on the system. The following Blog entry may contain more information about this issue: http://blogs.technet.com/askperf/archive/2008/01/25/an-overview-of-troubleshooting-memory-issues.aspx"
                    AddXMLAlert warningType, ALERT_CATEGORY_MEMORY_PERF, XMLMessage, xmlRecommendation, 1000
                    AddTXTAlert warningType, ALERT_CATEGORY_MEMORY_PERF, XMLMessage, txtRecommendation
                    AddExternalAlert warningType, ALERT_CATEGORY_MEMORY_PERF, XMLMessage, xmlRecommendation, 1000
                    AddRootCause "RC_LowVirtualMemory", warningType, FormatNumber(COMMITED_LIMIT_MEDIUM, 1) + "%", txtDisplayValue, "", ""
            End If
            
            LineOut "    % Committed Bytes In Use       : ", txtDisplayValue, True, False, "Item"
            LineOut "    % Committed Bytes In Use       : ", xmlDisplayValue, False, True, "Item"
        Else
            DisplayError "WriteMainMemoryCounters", Err.Number, "Obtaining Machine counters from Win32_PerfRawData_PerfOS_Memory class", Err.Description
        End If
    Next
    LineOut "", "", True, False, ""
    CloseTag "SubSection"
End Function

Function GenerateRecordSet(objColWin32_Process)
    Dim objDataList, x, objProcess
 
    Set objDataList = CreateObject("ADODB.RecordSet")
    
    objDataList.Fields.Append "Caption", adVarChar, 500
    objDataList.Fields.Append "CommandLine", adVarChar, 500
    objDataList.Fields.Append "CreationTime", adDBTimeStamp
    objDataList.Fields.Append "ExecutablePath", adVarChar, 500
    objDataList.Fields.Append "ProcessID", adBigInt
    objDataList.Fields.Append "HandleCount", adBigInt
    objDataList.Fields.Append "WorkingSetSize", adBigInt
    objDataList.Fields.Append "QuotaPagedPoolUsage", adBigInt
    objDataList.Fields.Append "QuotaNonPagedPoolUsage", adBigInt
    objDataList.Fields.Append "VirtualSize", adBigInt
    objDataList.Fields.Append "ThreadCount", adBigInt
    objDataList.Fields.Append "Name", adVarChar, 500
    
    objDataList.Open
    
    For Each objProcess In objColWin32_Process
            objDataList.AddNew
            objDataList("Name") = objProcess.Name
            objDataList("ProcessID") = objProcess.ProcessID
            objDataList("HandleCount") = objProcess.HandleCount
            objDataList("WorkingSetSize") = objProcess.WorkingSetSize / 1024
            objDataList("VirtualSize") = objProcess.VirtualSize / 1024
            objDataList("QuotaPagedPoolUsage") = objProcess.QuotaPagedPoolUsage
            objDataList("QuotaNonPagedPoolUsage") = objProcess.QuotaPeakNonPagedPoolUsage
            objDataList("ThreadCount") = objProcess.ThreadCount
            objDataList.Update
    Next
    Set GenerateRecordSet = objDataList

End Function

Sub DumpProcessInformation()
    'On Error Resume Next
    
    Dim colItems, objItem, objRecordSet, lngMaxValue, x
    Dim strGraphColorStart, strGraphColorEnd
    
    OpenWMIService
    
    wscript.Echo ""
    wscript.Echo "Obtaining information from Top Processes"
    
    OpenTag "Section"
    LineOut " -- Process Statistics", "", False, False, "SectionTitle"
    LineOut "", "", True, False, ""

    Set colItems = objWMIService.ExecQuery("Select * from Win32_Process", , 48)
    Set objRecordSet = GenerateRecordSet(colItems)

    DumpTopProcessCollection "HandleCount", "Handle Count", "HandleCount desc", objRecordSet, False
    DumpTopProcessCollection "WorkingSetSize", "Working Set Size", "WorkingSetSize desc", objRecordSet, True
    DumpTopProcessCollection "VirtualSize", "Virtual Bytes", "VirtualSize desc", objRecordSet, True
    DumpTopProcessCollection "ThreadCount", "Thread Count", "ThreadCount desc", objRecordSet, False

    LineOut "", "", True, False, ""
        
    CloseTag "Section"
    LineOut "", "", True, False, ""
    
End Sub

Sub DumpKernelMemoryInformation()
        
    Dim strMemSnapLogPath, objRecordSet, objMemSnapLogFile, strLine, x
    Dim intNumberofSpaces, strGraphColorStart, strGraphColorEnd, lngMaxValue
    OpenWMIService
    
    intNumberofSpaces = 30
    
    wscript.Echo ""
    wscript.Echo "Obtaining information from Kernel Memory"
    
    strMemSnapLogPath = objFSO.BuildPath(objFSO.GetParentFolderName(wscript.ScriptName), "memsnap.txt")

    objShell.Run "memsnap.exe -p " & Chr(34) & strMemSnapLogPath & Chr(34), 0, True

    If objFSO.FileExists(strMemSnapLogPath) Then

        OpenTag "Section"
        LineOut " -- Kernel Memory Information", "", False, False, "SectionTitle"
        LineOut "", "", True, False, ""
    
        Set objRecordSet = CreateObject("ADODB.RecordSet")
        objRecordSet.Fields.Append "Tag", adVarChar, 5
        objRecordSet.Fields.Append "Type", adVarChar, 5
        objRecordSet.Fields.Append "Bytes", adBigInt
        objRecordSet.Open

        Set objMemSnapLogFile = objFSO.OpenTextFile(strMemSnapLogPath, 1, False, -2)
        
        Dim PagedPoolTotal, bPoolTag
        Dim NonPagedPoolTotal
    
        PagedPoolTotal = 0
        NonPagedPoolTotal = 0
    
        bPoolTag = True
    
        While (Not objMemSnapLogFile.AtEndOfStream)
            strLine = objMemSnapLogFile.ReadLine
            If Left(strLine, 10) = "!TickCount" Then
                strLine = objMemSnapLogFile.ReadLine
                While (Not objMemSnapLogFile.AtEndOfStream)
                    If Len(strLine) > 50 Then
                        objRecordSet.AddNew
                        objRecordSet.Fields("Tag") = Mid(strLine, 2, 4)
                        objRecordSet.Fields("Type") = Trim(Mid(strLine, 7, 5))
                        objRecordSet.Fields("Bytes") = GetMemSnapColValue(strLine, 6)
                        Select Case LCase(objRecordSet.Fields("Type"))
                            Case "paged"
                                PagedPoolTotal = PagedPoolTotal + cDbl(objRecordSet.Fields("Bytes"))
                            Case "nonp"
                                NonPagedPoolTotal = NonPagedPoolTotal + cDbl(objRecordSet.Fields("Bytes"))
                        End Select
                        objRecordSet.Update
                    End If
                    strLine = objMemSnapLogFile.ReadLine
                Wend
            ElseIf InStr(1, strLine, "C0000002") Then
                bPoolTag = False
            End If
        Wend
    
        objMemSnapLogFile.Close
        'objFSO.DeleteFile strMemSnapLogPath
        
        If (objRecordSet.RecordCount = 0) Then
            bPoolTag = False
        End If
        
        If bPoolTag Then
            PAGEDPOOL_LIMIT_MEDIUM = cDbl(PagedPoolTotal) * POOL_LIMIT_PERCENTAGE_OF_TOTAL_MEDIUM '60% of the total
            PAGEDPOOL_LIMIT_HIGH = cDbl(PagedPoolTotal) * POOL_LIMIT_PERCENTAGE_OF_TOTAL_HIGH '80% of the total
            
            OpenTag "SubSection"
            LineOut " -- Top Paged Pool Usage - Tags", "", False, False, "SectionTitle"
            LineOut "", "", True, False, ""
            OpenTag "KernelMemory"
            
            objRecordSet.Filter = "Type = 'Paged'"
            objRecordSet.Sort = "Bytes desc"
                
            While Not objRecordSet.EOF
                If x < MAX_ITEMS Then
                    OpenTag "PoolMemory"
                    LineOut "    " & FormatStr("Tag", intNumberofSpaces) & " : ", objRecordSet("Tag"), False, False, "Tag"
                    LineOut "    " & FormatStr("Paged Pool Kernel Memory Usage", intNumberofSpaces) & " : ", FormatRAWValue(cDbl(objRecordSet("Bytes")) / 1024), False, True, "Value"
                    LineOut "    " & FormatStr("Paged Pool Kernel Memory Usage", intNumberofSpaces) & " : ", GetDisplayValue("Bytes", cDbl(objRecordSet("Bytes"))), False, False, "ValueDisplay"
                    GetGraphColor "KernelPagedPoolMemory", x, cDbl(objRecordSet("Bytes")), strGraphColorStart, strGraphColorEnd
                    GenerateAlertsForCounter "KernelPagedPoolMemory", x, cDbl(objRecordSet("Bytes")), objRecordSet("Tag"), (cDbl(objRecordSet("Bytes")) / PagedPoolTotal)
                    LineOut "Start color : ", "#" & HexFormat(strGraphColorStart), False, True, "GraphColorStart"
                    LineOut "End color : ", "#" & HexFormat(strGraphColorEnd), False, True, "GraphColorEnd"
                    LineOut "", "", True, False, ""
                    CloseTag "PoolMemory"
                End If
                lngMaxValue = lngMaxValue + (cDbl(objRecordSet("Bytes")) / 1024)
                objRecordSet.MoveNext
                x = x + 1
            Wend
            LineOut "    Max        : ", FormatRAWValue(lngMaxValue), False, True, "MaxValue"
            CloseTag "KernelMemory"
            CloseTag "SubSection"
            
            OpenTag "SubSection"
            LineOut " -- Top Non-Paged Pool Usage - Tags", "", False, False, "SectionTitle"
            LineOut "", "", True, False, ""
            intNumberofSpaces = 34
            x = 0
            lngMaxValue = 0
            OpenTag "KernelMemory"
            
            objRecordSet.Filter = "Type = 'Nonp'"
            objRecordSet.Sort = "Bytes desc"
                
            NONPAGEDPOOL_LIMIT_MEDIUM = cDbl(NonPagedPoolTotal) * POOL_LIMIT_PERCENTAGE_OF_TOTAL_MEDIUM '60% of the total
            NONPAGEDPOOL_LIMIT_HIGH = cDbl(NonPagedPoolTotal) * POOL_LIMIT_PERCENTAGE_OF_TOTAL_HIGH '80% of the total
        
            While Not objRecordSet.EOF
                If x < MAX_ITEMS Then
                    OpenTag "PoolMemory"
                    LineOut "    " & FormatStr("Tag", intNumberofSpaces) & " : ", objRecordSet("Tag"), False, False, "Tag"
                    LineOut "    " & FormatStr("Non Paged Pool Kernel Memory Usage", intNumberofSpaces) & " : ", FormatRAWValue(cDbl(objRecordSet("Bytes")) / 1024), False, True, "Value"
                    LineOut "    " & FormatStr("Non Paged Pool Kernel Memory Usage", intNumberofSpaces) & " : ", GetDisplayValue("Bytes", cDbl(objRecordSet("Bytes"))), False, False, "ValueDisplay"
                    GetGraphColor "KernelNonPagedPoolMemory", x, cDbl(objRecordSet("Bytes")), strGraphColorStart, strGraphColorEnd
                    GenerateAlertsForCounter "KernelNonPagedPoolMemory", x, cDbl(objRecordSet("Bytes")), objRecordSet("Tag"), (cDbl(objRecordSet("Bytes")) / NonPagedPoolTotal)
                    LineOut "Start color : ", "#" & HexFormat(strGraphColorStart), False, True, "GraphColorStart"
                    LineOut "End color : ", "#" & HexFormat(strGraphColorEnd), False, True, "GraphColorEnd"
                    LineOut "", "", True, False, ""
                    CloseTag "PoolMemory"
                End If
                lngMaxValue = lngMaxValue + (cDbl(objRecordSet("Bytes")) / 1024)
                objRecordSet.MoveNext
                x = x + 1
            Wend
            LineOut "    Max        : ", FormatRAWValue(lngMaxValue), False, True, "MaxValue"
            CloseTag "KernelMemory"
            CloseTag "SubSection"
        Else
            LineOut "    Pool Information: ", "(Not Available)", False, False, "Item"
            AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_KERNEL_MEMORY_INFO, "Unable to query Kernel Pool memory information. Pool Tagging might not be enabled.", "Please check <a target='_blank' href='http://support.microsoft.com/kb/177415'>KB 177415</a> for more information", 2000
            AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_KERNEL_MEMORY_INFO, "Unable to query Kernel Pool memory information. Pool Tagging might not be enabled.", "Please check KB 177415 for more information"
        End If
        
        CloseTag "Section"
    Else
        DisplayError "DumpKernelMemoryInformation", 2, "MemSnap", "Memsnap did not generate output. Kernel memory allocation information not generated"
    End If
    
End Sub

Function GetMemSnapColValue(strLine, colNumber)
    'On Error Resume Next
    Dim intColStart, intColNumber, intColEnd, x, y
    intColNumber = 0
    For x = 1 To Len(strLine) - 1
        If Mid(strLine, x, 1) <> " " Then
            intColStart = x
            intColEnd = 0
            y = x + 1
            While intColEnd = 0
                If (Mid(strLine, y, 1) = " ") Or Len(strLine) = y Then
                    intColEnd = y
                End If
                y = y + 1
            Wend
            intColNumber = intColNumber + 1
            If colNumber = intColNumber Then
                GetMemSnapColValue = Mid(strLine, intColStart, intColEnd - intColStart)
            End If
            x = intColEnd
        End If
    Next
End Function

Function FormatRAWValue(lngValue)
    'This function makes sure the value is on US number format
    FormatRAWValue = Replace(lngValue, strSystemDecimalSymbol, ".")
End Function

Sub DumpTopProcessCollection(strItem, strItemDisplay, strSortStatement, objRecordSet, isMemory)
    Dim x, lngMaxValue, strGraphColorStart, strGraphColorEnd, intNumberofSpaces
    
    OpenTag "SubSection"
    wscript.Echo " -- Obtaining Top Processes By " & strItemDisplay
    If Not IsEmpty(arrAlwaysShowProcess) Then
        LineOut " -- " + strItemDisplay, "", False, False, "SectionTitle"
    Else
        LineOut " -- Top Processes By " & strItemDisplay, "", False, False, "SectionTitle"
    End If
    LineOut "", "", True, False, ""
    
    lngMaxValue = 0
    x = 0
    OpenTag "ProcessCollection"
    
    objRecordSet.Sort = strSortStatement
    
    intNumberofSpaces = Len(strItemDisplay) + 1
    
    If Not objRecordSet.EOF Then
        If Not (isMemory) Then
            LineOut "    Max        : ", FormatRAWValue(cDbl(objRecordSet(strItem)) * 1.05), False, True, "MaxValue" '5% is the maximum value
            lngMaxValue = cDbl(objRecordSet(strItem))
        Else
            LineOut "    Max        : ", FormatRAWValue(cDbl(objRecordSet(strItem)) * 1.05 / 1024), False, True, "MaxValue" '5% is the maximum value
            lngMaxValue = cDbl(objRecordSet(strItem)) / 1024
        End If
    End If
    
    While Not objRecordSet.EOF
        If (x < MAX_ITEMS) Or (ForceShowThisProcess(cDbl(objRecordSet("ProcessID")), objRecordSet("Name"))) Then
            OpenTag "Process"
            LineOut "    " & FormatStr("Process ID", intNumberofSpaces) & " : ", cDbl(objRecordSet("ProcessID")), False, False, "ProcessID"
            LineOut "    " & FormatStr("Process Name", intNumberofSpaces) & " : ", objRecordSet("Name"), False, False, "Name"
            If Not (isMemory) Then
                LineOut "    " & FormatStr(strItemDisplay, intNumberofSpaces) & " : ", FormatRAWValue(cDbl(objRecordSet(strItem))), False, True, "Value"
            Else
                LineOut "    " & FormatStr(strItemDisplay, intNumberofSpaces) & " : ", FormatRAWValue(cDbl(objRecordSet(strItem)) / 1024), False, True, "Value"
            End If
            LineOut "    " & FormatStr(strItemDisplay, intNumberofSpaces) & " : ", GetDisplayValue(strItem, cDbl(objRecordSet(strItem))), False, False, "ValueDisplay"
            GetGraphColor strItem, x, cDbl(objRecordSet(strItem)), strGraphColorStart, strGraphColorEnd
            LineOut "Start color : ", "#" & HexFormat(strGraphColorStart), False, True, "GraphColorStart"
            LineOut "End color : ", "#" & HexFormat(strGraphColorEnd), False, True, "GraphColorEnd"
            If ((cDbl(objRecordSet(strItem)) / lngMaxValue) < 0.01) Then
                LineOut "Text color : ", "Gray", False, True, "TextColor"
                If Not (isMemory) Then
                    LineOut "Text start : ", objRecordSet(strItem), False, True, "TextStartPos"
                Else
                    LineOut "Text start : ", cDbl(objRecordSet(strItem)) / 1024, False, True, "TextStartPos"
                End If
            Else
                LineOut "Text color : ", "White", False, True, "TextColor"
                LineOut "Text start : ", 1, False, True, "TextStartPos"
            End If
            
            LineOut "", "", True, False, ""
            CloseTag "Process"
            
            GenerateAlertsForCounter strItem, x, cDbl(objRecordSet(strItem)), objRecordSet("Name"), cDbl(objRecordSet("ProcessID"))
            
        End If
        lngMaxValue = lngMaxValue + cDbl(objRecordSet(strItem))
        objRecordSet.MoveNext
        x = x + 1
    Wend
    
    LineOut "    Total        : ", lngMaxValue, False, True, "Total"
    CloseTag "ProcessCollection"
    CloseTag "SubSection"
End Sub

Function ForceShowThisProcess(lngProcessID, strProcessName)
    'Check if a certain process is present on arrAlwaysShowProcess. In this case, always show this process in report
    
    Dim strProcess
    If Not IsEmpty(arrAlwaysShowProcess) Then
        For Each strProcess In arrAlwaysShowProcess
            If IsNumeric(strProcess) Then
                'Value is an integer - in this case, consider a Process ID
                If cDbl(strProcess) = lngProcessID Then
                    ForceShowThisProcess = True
                    Exit Function
                End If
            Else
                'Value is a string - in this case, consider a Process Name
                If LCase(strProcess) = LCase(strProcessName) Then
                    ForceShowThisProcess = True
                    Exit Function
                End If
            End If
        Next
    Else
        ForceShowThisProcess = False
    End If
    
End Function

Function GetDisplayValue(strItemName, lngCurrentValue)
    Select Case strItemName
        Case "WorkingSetSize", "VirtualSize", "QuotaPagedPoolUsage", "QuotaNonPagedPoolUsage"
            If ((lngCurrentValue > 0) And (lngCurrentValue < 1024)) Then
                        GetDisplayValue = FormatNumber(lngCurrentValue, 2) & " KB"
          ElseIf ((lngCurrentValue >= 1024) And (lngCurrentValue < 1048575)) Then
             GetDisplayValue = FormatNumber(lngCurrentValue / 1024) & " MB"
          Else
            GetDisplayValue = FormatNumber(lngCurrentValue / 1024 / 1024, 2) & " GB"
                    End If
        Case "Bytes"
            If ((lngCurrentValue > 0) And (lngCurrentValue < 1024)) Then
                        GetDisplayValue = FormatNumber(lngCurrentValue, 0) & " Bytes"
          ElseIf ((lngCurrentValue >= 1024) And (lngCurrentValue < 1048575)) Then
             GetDisplayValue = FormatNumber(lngCurrentValue / 1024, 2) & " KB"
          ElseIf ((lngCurrentValue >= 1048576) And (lngCurrentValue < 1073741824)) Then
            GetDisplayValue = FormatNumber(lngCurrentValue / 1024 / 1024) & " MB"
          Else
            GetDisplayValue = FormatNumber(lngCurrentValue / 1024 / 1024 / 1024, 2) & " GB"
                    End If
        Case Else
            GetDisplayValue = FormatNumber(lngCurrentValue, 0)
    End Select
End Function

Sub GenerateAlertsForCounter(strAttribute, intIndex, lngCurrentValue, txtDisplayName, intProcessID)
    
    Dim txtDisplayValue, warningType, xmlDisplayValue, XMLMessage, txtRecommendation, xmlRecommendation
    
    Select Case strAttribute
        Case "HandleCount"
            If (lngCurrentValue > HANDLE_LIMIT_MEDIUM) Then
                
                txtDisplayValue = FormatNumber(lngCurrentValue, 0)
                If (lngCurrentValue > HANDLE_LIMIT_HIGH) Then
                    warningType = ALERT_ERROR
                    xmlDisplayValue = "<font color='Red'><b>" + txtDisplayValue + "</b></font>"
                Else
                    warningType = ALERT_WARNING
                    xmlDisplayValue = "<b>" + txtDisplayValue + "</b>"
                End If
                
                XMLMessage = "A process is using a high number of handles."
                xmlRecommendation = "Process <b>" + txtDisplayName + "</b> (Process ID " + CStr(intProcessID) + ") is using " + xmlDisplayValue + " handles at this moment. This migh be considered a high number, depending on the characteristics of the process, or indicate a 'handle leak' on the process. The following <a target='_blank' href='http://blogs.technet.com/askperf/archive/2008/05/09/troubleshooting-server-hangs-part-three.aspx'>Blog Entry</a> may contain more information about this problem."
                txtRecommendation = "Process " + txtDisplayName + " (Process ID " + CStr(intProcessID) + ") is using " + xmlDisplayValue + " handles at this moment. This migh be considered a high number, depending on the characteristics of the process, or indicate a 'handle leak' on the process. The following Blog entry may contain more information about this issue: http://blogs.technet.com/askperf/archive/2008/05/09/troubleshooting-server-hangs-part-three.aspx"
                
                AddXMLAlert warningType, ALERT_CATEGORY_PROCESS_PERF, XMLMessage, xmlRecommendation, 1000
                AddTXTAlert warningType, ALERT_CATEGORY_PROCESS_PERF, XMLMessage, txtRecommendation
                AddExternalAlert warningType, ALERT_CATEGORY_PROCESS_PERF, XMLMessage, xmlRecommendation, 1000
                AddRootCause "RC_HighHandleCount", warningType, FormatNumber(HANDLE_LIMIT_MEDIUM, 0), txtDisplayValue, txtDisplayName, CStr(intProcessID)
            End If
        Case "KernelPagedPoolMemory"
            If lngCurrentValue > PAGEDPOOL_LIMIT_MEDIUM Then
                Dim ThresholdValue
                txtDisplayValue = GetDisplayValue("Bytes", lngCurrentValue)
                
                If (lngCurrentValue > PAGEDPOOL_LIMIT_HIGH) Then
                    warningType = ALERT_ERROR
                    xmlDisplayValue = "<font color='Red'><b>" + txtDisplayValue + "</b></font>"
                    ThresholdValue = FormatNumber(intProcessID * 100, 1)
                Else
                    warningType = ALERT_WARNING
                    xmlDisplayValue = "<b>" + txtDisplayValue + "</b>"
                    ThresholdValue = FormatNumber(intProcessID * 100, 1)
                End If
                
                XMLMessage = "High Paged Pool Memory usage by a Kernel Tag."
                xmlRecommendation = "Tag <b>" + txtDisplayName + "</b> is using " + xmlDisplayValue + " of Paged Pool memory at this moment. This migh be considered a high number since it represents " + ThresholdValue + "% of the total allocated Paged Pool Memory in the machine. The following <a target='_blank' href='http://blogs.technet.com/markrussinovich/archive/2009/03/26/3211216.aspx'>Blog Entry</a> may contain more information about this problem."
                txtRecommendation = "Tag '" + txtDisplayName + "' is using " + txtDisplayValue + " of Paged Pool memory at this moment. This migh be considered a high number since it represents " + ThresholdValue + "% of the total allocated Paged Pool Memory in the machine. The following Blog entry may contain more information about this issue: http://blogs.technet.com/markrussinovich/archive/2009/03/26/3211216.aspx"
                               
                AddXMLAlert warningType, ALERT_CATEGORY_KERNEL_MEMORY_PERF, XMLMessage, xmlRecommendation, 1000
                AddTXTAlert warningType, ALERT_CATEGORY_KERNEL_MEMORY_PERF, XMLMessage, txtRecommendation
                AddExternalAlert warningType, ALERT_CATEGORY_KERNEL_MEMORY_PERF, XMLMessage, xmlRecommendation, 1000
                
                AddRootCause "RC_KernelMemoryPerformanceIssue", warningType, ThresholdValue, txtDisplayValue, txtDisplayName, "Paged Pool"
                
            End If
        Case "KernelNonPagedPoolMemory"
            If lngCurrentValue > NONPAGEDPOOL_LIMIT_MEDIUM Then
                txtDisplayValue = GetDisplayValue("Bytes", lngCurrentValue)
                
                If (lngCurrentValue > NONPAGEDPOOL_LIMIT_HIGH) Then
                    warningType = ALERT_ERROR
                    xmlDisplayValue = "<font color='Red'><b>" + txtDisplayValue + "</b></font>"
                    ThresholdValue = FormatNumber(intProcessID * 100, 1)
                Else
                    warningType = ALERT_WARNING
                    xmlDisplayValue = "<b>" + txtDisplayValue + "</b>"
                    ThresholdValue = FormatNumber(intProcessID * 100, 1)
                End If
                
                XMLMessage = "High NonPaged Pool Memory usage by a Kernel Tag."
                xmlRecommendation = "Tag <b>" + txtDisplayName + "</b> is using " + xmlDisplayValue + " of NonPaged Pool memory at this moment. This migh be considered a high number since it represents more than " + ThresholdValue + "% of the total allocated NonPaged Pool Memory in the machine. The following <a target='_blank' href='http://blogs.technet.com/markrussinovich/archive/2009/03/26/3211216.aspx'>Blog Entry</a> may contain more information about this problem."
                txtRecommendation = "Tag '" + txtDisplayName + "' is using " + txtDisplayValue + " of NonPaged memory at this moment. This migh be considered a high number since it represents more than " + ThresholdValue + "% of the total allocated NonPaged Pool Memory in the machine. The following Blog entry may contain more information about this issue: http://blogs.technet.com/markrussinovich/archive/2009/03/26/3211216.aspx"
                
                AddXMLAlert warningType, ALERT_CATEGORY_KERNEL_MEMORY_PERF, XMLMessage, xmlRecommendation, 1000
                AddTXTAlert warningType, ALERT_CATEGORY_KERNEL_MEMORY_PERF, XMLMessage, txtRecommendation
                AddExternalAlert warningType, ALERT_CATEGORY_KERNEL_MEMORY_PERF, XMLMessage, xmlRecommendation, 1000
                
                AddRootCause "RC_KernelMemoryPerformanceIssue", warningType, ThresholdValue, txtDisplayValue, txtDisplayName, "NonPaged Pool"
                
            End If
    End Select
End Sub

Sub GetGraphColor(strAttribute, intIndex, lngCurrentValue, lngGraphStart, lngGraphEnd)
    Select Case strAttribute
        Case "HandleCount"
            If lngCurrentValue < HANDLE_LIMIT_MEDIUM Then
                lngGraphStart = &H336699 + (intIndex * &H10B)
                lngGraphEnd = &H538CC6 + (intIndex * &H70702)
            ElseIf lngCurrentValue < HANDLE_LIMIT_HIGH Then
                lngGraphStart = &HFF8000 - (intIndex * &H60000)
                lngGraphEnd = &HC66300 + (intIndex * &H10000)
            Else
                lngGraphStart = &HFF0000 + (intIndex * &HD0D)
                lngGraphEnd = &HF60000 + (intIndex * &HF0F)
            End If
        Case "KernelPagedPoolMemory"
            If lngCurrentValue < PAGEDPOOL_LIMIT_MEDIUM Then
                lngGraphStart = &H336699 + (intIndex * &H10B)
                lngGraphEnd = &H538CC6 + (intIndex * &H70702)
            ElseIf lngCurrentValue < PAGEDPOOL_LIMIT_HIGH Then
                lngGraphStart = &HFF8000 - (intIndex * &H60000)
                lngGraphEnd = &HC66300 + (intIndex * &H10000)
            Else
                lngGraphStart = &HFF0000 + (intIndex * &HD0D)
                lngGraphEnd = &HF60000 + (intIndex * &HF0F)
            End If
        Case "KernelNonPagedPoolMemory"
            If lngCurrentValue < NONPAGEDPOOL_LIMIT_MEDIUM Then
                lngGraphStart = &H336699 + (intIndex * &H10B)
                lngGraphEnd = &H538CC6 + (intIndex * &H70702)
            ElseIf lngCurrentValue < NONPAGEDPOOL_LIMIT_HIGH Then
                lngGraphStart = &HFF8000 - (intIndex * &H60000)
                lngGraphEnd = &HC66300 + (intIndex * &H10000)
            Else
                lngGraphStart = &HFF0000 + (intIndex * &HD0D)
                lngGraphEnd = &HF60000 + (intIndex * &HF0F)
            End If
        Case Else
            lngGraphStart = &H336699 + (intIndex * &H10B)
            lngGraphEnd = &H336699 + (intIndex * &H8080B)
    End Select
End Sub

Function FormatStr(strValue, NumberofChars)
    If Len(strValue) > NumberofChars Then
        FormatStr = Left(strValue, NumberofChars)
    Else
        FormatStr = strValue + Space(NumberofChars - Len(strValue))
    End If
End Function

Function GetOSSKU(intSKU)
    Select Case intSKU
        Case 0
            GetOSSKU = "Undefined"
        Case 1
            GetOSSKU = "Ultimate Edition"
        Case 2
            GetOSSKU = "Home Basic Edition"
        Case 3
            GetOSSKU = "Home Basic Premium Edition"
        Case 4
            GetOSSKU = "Enterprise Edition"
        Case 5
            GetOSSKU = "Home Basic N Edition"
        Case 6
            GetOSSKU = "Business Edition"
        Case 7
            GetOSSKU = "Standard Server Edition"
        Case 8
            GetOSSKU = "Datacenter Server Edition"
        Case 9
            GetOSSKU = "Small Business Server Edition"
        Case 10
            GetOSSKU = "Enterprise Server Edition"
        Case 11
            GetOSSKU = "Starter Edition"
        Case 12
            GetOSSKU = "Datacenter Server Core Edition"
        Case 13
            GetOSSKU = "Standard Server Core Edition"
        Case 14
            GetOSSKU = "Enterprise Server Core Edition"
        Case 15
            GetOSSKU = "Enterprise Server Edition for Itanium-Based Systems"
        Case 16
            GetOSSKU = "Business N Edition"
        Case 17
            GetOSSKU = "Web Server Edition"
        Case 18
            GetOSSKU = "Cluster Server Edition"
        Case 19
            GetOSSKU = "Home Server Edition"
        Case 20
            GetOSSKU = "Storage Express Server Edition"
        Case 21
            GetOSSKU = "Storage Standard Server Edition"
        Case 22
            GetOSSKU = "Storage Workgroup Server Edition"
        Case 23
            GetOSSKU = "Storage Enterprise Server Edition"
        Case 24
            GetOSSKU = "Server For Small Business Edition"
        Case 25
            GetOSSKU = "Small Business Server Premium Edition"
    End Select
End Function


Function ReplaceEnvVars(strString)
    Dim intFirstPercentPos, intSecondPercentPos
    Dim strEnvVar
    
    On Error Resume Next
    intFirstPercentPos = InStr(1, strString, "%")
    
    While intFirstPercentPos > 0
        intSecondPercentPos = InStr(intFirstPercentPos + 1, strString, "%")
        strEnvVar = Mid(strString, intFirstPercentPos + 1, intSecondPercentPos - intFirstPercentPos - 1)
        strString = Replace(strString, "%" & strEnvVar & "%", objShell.Environment("PROCESS").Item(strEnvVar))
        intFirstPercentPos = InStr(1, strString, "%")
    Wend
    ReplaceEnvVars = strString
End Function

Function AddtoArray(arrSourceArray, arrArrayToAdd)
    On Error Resume Next
    Dim y, varFirstMember
    
    If IsEmpty(arrSourceArray) Then
        If Not IsArray(arrArrayToAdd) Then
            ReDim arrSourceArray(0)
            arrSourceArray(0) = arrArrayToAdd
        Else
            arrSourceArray = arrArrayToAdd
        End If
    Else
        If Not IsArray(arrSourceArray) Then
            varFirstMember = arrSourceArray
            ReDim arrSourceArray(0)
            arrSourceArray(0) = varFirstMember
        End If
        If Not IsEmpty(arrArrayToAdd) Then
            If IsArray(arrArrayToAdd) Then
                For y = 0 To UBound(arrArrayToAdd)
                    ReDim Preserve arrSourceArray(UBound(arrSourceArray) + 1)
                    arrSourceArray(UBound(arrSourceArray)) = arrArrayToAdd(y)
                Next
            Else
                ReDim Preserve arrSourceArray(UBound(arrSourceArray) + 1)
                arrSourceArray(UBound(arrSourceArray)) = arrArrayToAdd
            End If
        End If
    End If
    AddtoArray = arrSourceArray
End Function

Sub AddMSDTPLAAlert(intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation, intPriority)
    
    Dim strAlertXML
    
    If bGenerateSDP2Alerts Then
        
        strAlertRecommendation = strAlertRecommendation + "<br/>For additional information, please open the file <i>" + _
                                                          objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                                                          "_" + OUTPUT_BASENAME + ".html</i>."
        
        Select Case intAlertType
            Case ALERT_INFORMATION
                intAlertType = 1
            Case ALERT_WARNING
                intAlertType = 2
            Case ALERT_ERROR
                intAlertType = 3
        End Select
        
        Dim objPLA
        Set objPLA = New ezPLA
        
        wscript.Echo "Creating PLA Alert: " & strAlertMessage
        objPLA.Section = "Processes/ Performance Related Alerts"
        objPLA.SectionPriority = 30
        
        objPLA.AlertType = intAlertType
        objPLA.Symptom = strAlertCategory
        objPLA.Details = strAlertMessage
        objPLA.MoreInformation = strAlertRecommendation
    
        objPLA.AddAlerttoPLA
    
    End If
    
End Sub

Sub AddXMLAlert(intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation, intPriority)
    
    Dim strAlertType, strAlertXML
    
    Select Case intAlertType
        Case ALERT_INFORMATION
            strAlertType = "Information"
        Case ALERT_WARNING
            strAlertType = "Warning"
        Case ALERT_ERROR
            strAlertType = "Error"
    End Select
    
    strAlertXML = "<AlertType>" & strAlertType & "</AlertType>" & _
                  "<AlertCategory>" & strAlertCategory & "</AlertCategory>" & _
                  "<AlertMessage><!" & Chr(91) & "CDATA" & Chr(91) & strAlertMessage & Chr(93) & Chr(93) & "></AlertMessage>" & _
                  "<AlertRecommendation><!" & Chr(91) & "CDATA" & Chr(91) & strAlertRecommendation & Chr(93) & Chr(93) & "></AlertRecommendation>" & _
                  "<AlertPriority>" & CStr(intPriority) & "</AlertPriority>"
                  
    AddtoArray arrAlertsXML, strAlertXML

End Sub

Sub WriteAlertsToXML()
    Dim strLine
    If Not IsEmpty(arrAlertsXML) Then
        OpenTag "Alerts"
        For Each strLine In arrAlertsXML
            OpenTag "Alert"
            objXMLFile.WriteLine strLine
            CloseTag "Alert"
        Next
        CloseTag "Alerts"
    End If
End Sub

Sub WriteAlertsToTXT(strOutputTXTFilePath)
     On Error Resume Next
    'Alerts in txt file needs to be in top of file
    Dim strTempTXTFilePath, objTempTXTFile, x, strAlertType
    Dim objOutputTXTFile
    
    If Not IsEmpty(arrAlertsTXTType) Then
    
        strTempTXTFilePath = objFSO.BuildPath(objFSO.GetSpecialFolder(2), OUTPUT_BASENAME + ".TXT")
        Set objTempTXTFile = objFSO.OpenTextFile(strTempTXTFilePath, ForWriting, True, OpenFileMode)
        
        objTempTXTFile.WriteLine "Alerts"
        objTempTXTFile.WriteLine "------"
        For x = 0 To UBound(arrAlertsTXTType)
            Select Case arrAlertsTXTType(x)
                Case ALERT_INFORMATION
                    strAlertType = "Information"
                Case ALERT_WARNING
                    strAlertType = "Warning"
                Case ALERT_ERROR
                    strAlertType = "Error"
            End Select
            
            objTempTXTFile.WriteLine " Alert Type: " & strAlertType
            objTempTXTFile.WriteLine " ------------" & String(Len(strAlertType), "-")
            objTempTXTFile.WriteLine ""
            objTempTXTFile.WriteLine "     Category:"
            objTempTXTFile.WriteLine "     --------"
            objTempTXTFile.WriteLine "     " & arrAlertsTXTCategory(x)
            objTempTXTFile.WriteLine ""
            objTempTXTFile.WriteLine "     Message:"
            objTempTXTFile.WriteLine "     --------"
            objTempTXTFile.WriteLine "     " & arrAlertsTXTMessage(x)
            objTempTXTFile.WriteLine ""
            objTempTXTFile.WriteLine "     Recommendation:"
            objTempTXTFile.WriteLine "     ---------------"
            objTempTXTFile.WriteLine "     " & arrAlertsTXTRecommendation(x)
            objTempTXTFile.WriteLine ""
        Next
        
        Set objOutputTXTFile = objFSO.OpenTextFile(strOutputTXTFilePath, ForReading, False, OpenFileMode)
        objTempTXTFile.Write objOutputTXTFile.ReadAll
        
        objTempTXTFile.Close
        objOutputTXTFile.Close
        Set objTempTXTFile = Nothing
        Set objOutputTXTFile = Nothing
        
        'Replace the contents and delete the temp file
        objFSO.CopyFile strTempTXTFilePath, strOutputTXTFilePath, True
        objFSO.DeleteFile strTempTXTFilePath, True
    End If
End Sub

Sub AddTXTAlert(intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation)
    AddtoArray arrAlertsTXTType, intAlertType
    AddtoArray arrAlertsTXTCategory, strAlertCategory
    AddtoArray arrAlertsTXTMessage, strAlertMessage
    AddtoArray arrAlertsTXTRecommendation, strAlertRecommendation
End Sub

Sub CreateHTMFile()
    On Error Resume Next
    Dim strErrText
    Err.Clear
    
    Dim strHTMLFileName, objHTMLFile, xmlStylesheet, xmlStylesheetPath, xmlFile, strXmlFilePath
        
    strXmlFilePath = objFSO.GetAbsolutePathName(".") & "\" & objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                     "_" + OUTPUT_BASENAME + ".XML"
        
    strHTMLFileName = objFSO.GetAbsolutePathName(".") & "\" & objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                                                    "_" + OUTPUT_BASENAME + ".htm"
        
    If ExtractEmbeddedXSL(xmlStylesheetPath) Then
    
        Set xmlStylesheet = CreateObject("Microsoft.XMLDOM")
        Set xmlFile = CreateObject("Microsoft.XMLDOM")
        
        xmlFile.Load strXmlFilePath
        
        If (Err.Number <> 0) Or (xmlFile.parseError.errorCode <> 0) Then
            If Err.Number <> 0 Then
                DisplayError "Loading XML file or XSLT " & strXmlFilePath & ".", Err.Number, Err.Source, Err.Description
            Else
                With xmlFile.parseError
                strErrText = "Failed to load XML file " & strXmlFilePath & "" & _
                        "due the following error:" & vbCrLf & _
                        "Error #: " & .errorCode & ": " & .reason & _
                        "Line #: " & .Line & vbCrLf & _
                        "Line Position: " & .linepos & vbCrLf & _
                        "Position In File: " & .filepos & vbCrLf & _
                        "Source Text: " & .srcText & vbCrLf & _
                        "Document URL: " & .url
                End With
                DisplayError "Loading " & strXmlFilePath & ".", 5000, "CreateHTMFile", strErrText
            End If
            objFSO.DeleteFile xmlStylesheetPath, True
            Exit Sub
        End If
    
        xmlStylesheet.Load xmlStylesheetPath
        
        If (Err.Number <> 0) Or (xmlFile.parseError.errorCode <> 0) Then
            If Err.Number <> 0 Then
                DisplayError "Loading XSLT " & xmlStylesheetPath & ".", Err.Number, Err.Source, Err.Description
            Else
                With xmlFile.parseError
                strErrText = "Failed to load XSL file " & xmlStylesheetPath & "" & _
                        "due the following error:" & vbCrLf & _
                        "Error #: " & .errorCode & ": " & .reason & _
                        "Line #: " & .Line & vbCrLf & _
                        "Line Position: " & .linepos & vbCrLf & _
                        "Position In File: " & .filepos & vbCrLf & _
                        "Source Text: " & .srcText & vbCrLf & _
                        "Document URL: " & .url
                End With
                DisplayError "Loading " & xmlStylesheetPath & ".", 5000, "CreateHTMFile", strErrText
            End If
            objFSO.DeleteFile xmlStylesheetPath, True
            Exit Sub
        End If
        
        wscript.Echo "Building file: '" & objFSO.GetFileName(strHTMLFileName) & "'"
        Set objHTMLFile = objFSO.OpenTextFile(strHTMLFileName, ForWriting, True, OpenFileMode)
    
        If Err.Number <> 0 Then
            DisplayError "Creating HTML file " & strHTMLFileName, Err.Number, Err.Source, Err.Description
            Exit Sub
        End If
        
        objHTMLFile.Write xmlFile.transformNode(xmlStylesheet)
        
        If Err.Number <> 0 Then
            DisplayError "Error transforming " & strXmlFilePath & " using stylesheet " & xmlStylesheetPath & ".", Err.Number, Err.Source, Err.Description
            objFSO.DeleteFile xmlStylesheetPath, True
            objHTMLFile.Close
            objFSO.DeleteFile strHTMLFileName, True
            Exit Sub
        End If
    
        objHTMLFile.Close
        
        Set xmlFile = Nothing
        Set xmlStylesheet = Nothing
        Set objXMLFile = Nothing
        
        objFSO.DeleteFile xmlStylesheetPath, True
        If Not (bGenerateScriptedDiagXMLAlerts) Then
            'Delete the xml file only for non-SDP 3.0 environments
            objFSO.DeleteFile strXmlFilePath, True
        End If
        If Err.Number <> 0 Then
            DisplayError "Error deleting files " & strXmlFilePath & "/ " & xmlStylesheetPath & ".", Err.Number, Err.Source, Err.Description
            Exit Sub
        End If
    End If
End Sub

Sub OpenWMIService()
    On Error Resume Next
    Err.Clear
    If IsEmpty(objWMIService) Then
        'wscript.Echo ("   Opening WMI Service")
        Set objWMIService = GetObject("winmgmts:" & _
        "{impersonationLevel=impersonate}!\\" & _
        ".\root\cimv2")
        If Err.Number <> 0 Then
           wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": binding to WMI Service"
           wscript.Echo Err.Source & " - " & Err.Description
           wscript.Quit
        End If
    End If
End Sub

Function HexFormat(intNumber)
    HexFormat = Right("00000000" & CStr(Hex(intNumber)), 8)
End Function

Sub LineOut(strName, strValue, bDoNotWriteToXML, bDoNotWritetoTXT, strXMLTag)
    
    If Not bDoNotWritetoTXT Then
        objTXTFile.WriteLine strName & strValue
    End If

    If Not bDoNotWriteToXML Then
        If Right(strName, 2) = ": " Then
            strName = Left(strName, Len(strName) - 2)
        End If
        If Left(strName, 4) = " -- " Then
            strName = Right(strName, Len(strName) - 4)
        End If
        strName = Trim(strName)
        
        WriteToXML strName, strValue, strXMLTag
    End If
End Sub

Function WriteToXML(strName, strValue, strXMLTag)
    If Len(strXMLTag) = 0 And Len(strValue) = 0 Then
        objXMLFile.WriteLine strName
    ElseIf Len(strValue) = 0 Then
        objXMLFile.WriteLine "<" & strXMLTag & " name=" & Chr(34) & Chr(34) & ">" & strName & "</" & strXMLTag & ">"
    ElseIf Len(strValue) > 0 Then
        
        objXMLFile.WriteLine "<" & strXMLTag & " name=" & Chr(34) & strName & Chr(34) & ">" & TranslateXMLChars(strValue) & "</" & strXMLTag & ">"
    End If
End Function

Function TranslateXMLChars(strRAWString)
    strRAWString = Replace(strRAWString, "&", "&amp;")
    strRAWString = Replace(strRAWString, "<", "&lt;")
    strRAWString = Replace(strRAWString, ">", "&gt;")
    strRAWString = Replace(strRAWString, "'", "&apos;")
    strRAWString = Replace(strRAWString, Chr(34), "&quot;")
    TranslateXMLChars = strRAWString
End Function

Function iif(Expression, Truepart, Falsepart)
    If Expression Then
        iif = Truepart
    Else
        iif = Falsepart
    End If
End Function

Function StringToArray(strString, strSeparator)
    On Error Resume Next
    Dim arrArray()
    ReDim arrArray(0)
    Dim intCommaPosition, intPreviousCommaPosition
    intPreviousCommaPosition = 1
    
    intCommaPosition = InStr(intPreviousCommaPosition, strString, strSeparator)
    
    Do While intCommaPosition <> 0
        arrArray(UBound(arrArray)) = Trim(Replace(Mid(strString, intPreviousCommaPosition, intCommaPosition - intPreviousCommaPosition), Chr(34), ""))
        intPreviousCommaPosition = intCommaPosition + 1
        intCommaPosition = InStr(intPreviousCommaPosition, strString, strSeparator)
        ReDim Preserve arrArray(UBound(arrArray) + 1)
    Loop
    arrArray(UBound(arrArray)) = Trim(Replace(Mid(strString, intPreviousCommaPosition, Len(strString)), Chr(34), ""))
    
    StringToArray = arrArray
    
    If Err.Number <> 0 Then
        DisplayError "Converting String " & strString & " to Array", Err.Number, Err.Source, Err.Description
        Exit Function
    End If
End Function

Function DetectScriptEngine()
    Dim ScriptHost
    ScriptHost = wscript.FullName
    ScriptHost = Right(ScriptHost, Len(ScriptHost) - InStrRev(ScriptHost, "\"))
    If (UCase(ScriptHost) <> "CSCRIPT.EXE") Then
        MsgBox "This script runs under CSCRIPT.EXE only." + Chr(13) + "Script aborting.", vbExclamation, "Script running by WScript or other processor"
        DetectScriptEngine = False
    Else
        DetectScriptEngine = True
    End If
End Function

Function ExtractEmbeddedXSL(ByRef strXSLPath)
    Dim objScriptFile
    Dim objXSL
    Dim bolXSLExtracted, strLine, bCDataBegin
    
    On Error Resume Next
    
    wscript.Echo "Building XSLT File..."
    
    Set objScriptFile = objFSO.OpenTextFile(wscript.ScriptFullName, ForReading, False, OpenFileMode)
    
    If Err.Number <> 0 Then
        DisplayError "Error opening script file to extract XSL file" & wscript.ScriptFullName & ".", Err.Number, Err.Source, Err.Description
        ExtractEmbeddedXSL = False
        Exit Function
    End If
    
    strXSLPath = objFSO.BuildPath(objFSO.GetSpecialFolder(2), objFSO.GetFileName(wscript.ScriptName) & ".XSL")
    Set objXSL = objFSO.OpenTextFile(strXSLPath, ForWriting, True, OpenFileMode)
    
    If Err.Number <> 0 Then
        DisplayError "Error creating XSL file " & strXSLPath & ".", Err.Number, Err.Source, Err.Description
        ExtractEmbeddedXSL = False
        Exit Function
    End If
    
    bolXSLExtracted = False
    While (Not objScriptFile.AtEndOfStream) And (Not bolXSLExtracted)
        strLine = objScriptFile.ReadLine
        If strLine = "Sub EmbeddedXSL()" Then
            bCDataBegin = False
            Do
                strLine = objScriptFile.ReadLine
                If Not bCDataBegin Then 'In SDP we cannot have the CDATA notation, therefore we are translating as indicated below
                    If InStr(1, strLine, "<!{CDATA{", vbTextCompare) > 0 Then
                        strLine = Replace(strLine, "<!{CDATA{", "<!" & Chr(91) & "CDATA" & Chr(91), 1, -1, vbTextCompare)
                        bCDataBegin = True
                    End If
                Else
                    If InStr(1, strLine, "}}>", vbTextCompare) > 0 Then
                        strLine = Replace(strLine, "}}>", Chr(93) & Chr(93) & ">", 1, -1, vbTextCompare)
                        bCDataBegin = False
                    End If
                End If
                If Left(strLine, 1) = "'" Then objXSL.WriteLine Right(strLine, Len(strLine) - 1)
            Loop While Left(strLine, 1) = "'"
            bolXSLExtracted = True
        End If
    Wend
    
    If Err.Number <> 0 Then
        DisplayError "Error extracting XSL file from script.", Err.Number, Err.Source, Err.Description
        ExtractEmbeddedXSL = False
    Else
        objXSL.Close
        objScriptFile.Close
        ExtractEmbeddedXSL = True
    End If
    
    Set objXSL = Nothing
    Set objScriptFile = Nothing
    
End Function

Sub EmbeddedXSL()
'<?xml version="1.0"?>
'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
'<xsl:output method="html" />
'<xsl:key name="EventType" match="SubSection" use="SectionTitle/text()" />
'<xsl:key name="AppNames" match="SubSection" use="concat(SectionTitle/text(), '|', AppName/text())" />
'<xsl:template match="/Root">
'<html dir="ltr" xmlns:v="urn:schemas-microsoft-com:vml" gpmc_reportInitialized="false">
'<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE8" />
'<head>
'<!-- Styles -->
'<style type="text/css">
'  body    { background-color:#FFFFFF; border:1px solid #666666; color:#000000; font-size:68%; font-family:MS Shell Dlg; margin:0,0,10px,0; word-break:normal; word-wrap:break-word; }
'
'  table   { font-size:100%; table-layout:fixed; width:100%; }
'
'  td,th   { overflow:visible; text-align:left; vertical-align:top; white-space:normal; }
'
'  .title  { background:#FFFFFF; border:none; color:#333333; display:block; height:24px; margin:0px,0px,-1px,0px; padding-top:4px; position:relative; table-layout:fixed; width:100%; z-index:5; }
'
'  .he0_expanded    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Tahoma; font-size:120%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%;
'  filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}
'
'  .he1_expanded    { background-color:#A0BACB; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he4_expanded { background-color:#DDE6EC; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he3_expanded { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:4px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he1old { background-color:#A0BACB; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he1    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Tahoma; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he2    { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he2g   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he2c   { background-color:F2F7F9; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he3    { background-color:#D9E3EA; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:30px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he4    { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:40px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he2b    { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he4h   { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:45px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he4i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:15px; margin-right:0px; padding-bottom:5px; padding-left:12px; padding-top:4px; position:relative; width:100%; }
'
'  .he5    { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:50px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he5h   { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; padding-right:5em; padding-top:4px; margin-bottom:-1px; margin-left:55px; margin-right:0px; position:relative; width:100%; }
'
'  .he5i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:55px; margin-right:0px; padding-left:21px; padding-bottom:5px; padding-top: 4px; position:relative; width:100%; }
'
'  DIV .expando { color:#000000; text-decoration:none; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:normal; position:absolute; right:10px; text-decoration:underline; z-index: 0; }
'
'  .he0 { font-size:100%; }
'
'  .info, .info0th, .info3, .info4, .disalign, .infoqfe, .infower { line-height:1.6em; padding:0px,0px,0px,0px; margin:0px,px,0px,0px;}
'
'  .disalign TD                      { padding-bottom:5px; padding-right:10px; }
'
'  .info5filename                    { padding-right:10px; width:30%; border-bottom:1px solid #CCCCCC; padding-right:10px;}
'
'  .info0th                          { padding-right:10px; width:12%; border-bottom:1px solid #CCCCCC; padding-right:10px;}
'
'  .info TD                          { padding-right:10px; width:50%; }
'
'  .infoqfe                          { table-layout:auto; }
'
'  .infoqfe TD, .infoqfe TH          { padding-right:10px;}
'
'  .info3 TD                         { padding-right:10px; width:33%; }
'
'  .info4 TD, .info4 TH              { padding-right:10px; width:25%;}
'
'  .infoFirstCol                     { padding-right:10px; width:20%; }
'  .infoSecondCol                     { padding-right:10px; width:80%; }
'
'  .info TH, .info0th, .info3 TH, .info4 TH, .disalign TH, .infoqfe TH, infower TH { border-bottom:1px solid #CCCCCC; padding-right:10px; }
'
'  .subtable, .subtable3             { border:1px solid #CCCCCC; margin-left:0px; background:#FFFFFF; margin-bottom:10px; }
'
'  .subtable TD, .subtable3 TD       { padding-left:10px; padding-right:5px; padding-top:3px; padding-bottom:3px; line-height:1.1em; width:10%; }
'
'  .subtable TH, .subtable3 TH       { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em;  }
'
'  .subtable .footnote               { border-top:1px solid #CCCCCC; }
'
'  .lines0                           {background-color: #F5F5F5;}
'  .lines1                           {background-color: #F9F9F9;}
'  .lines3                           {background-color: #FFFFF0;}
'
'  .subtable3 .footnote, .subtable .footnote { border-top:1px solid #CCCCCC; }
'
'  .subtable_frame     { background:#D9E3EA; border:1px solid #CCCCCC; margin-bottom:10px; margin-left:15px; }
'
'  .subtable_frame TD  { line-height:1.1em; padding-bottom:3px; padding-left:10px; padding-right:15px; padding-top:3px; }
'
'  .subtable_frame TH  { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em; }
'
'  .subtableInnerHead { border-bottom:1px solid #CCCCCC; border-top:1px solid #CCCCCC; }
'
'  .explainlink            { color:#000000; text-decoration:none; cursor:hand; }
'
'  .explainlink:hover      { color:#0000FF; text-decoration:underline; }
'
'  .spacer { background:transparent; border:1px solid #BBBBBB; color:#FFFFFF; display:block; font-family:MS Shell Dlg; font-size:100%; height:10px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top: 4px; position:relative; }
'
'  .filler { background:transparent; border:none; color:#FFFFFF; display:block; font:100% MS Shell Dlg; line-height:8px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top:4px; position:relative; }
'
'  .container { display:block; position:relative; }
'
'  .rsopheader { background-color:#A0BACB; border-bottom:1px solid black; color:#333333; font-family:Tahoma; font-size:130%; font-weight:bold; padding-bottom:5px; text-align:center;
'  filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=0,StartColorStr='#FFFFFF',EndColorStr='#A0BACB')}
'
'  .rsopname { color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }
'
'  .gponame{ color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }
'
'  .gpotype{ color:#333333; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; padding-left:11px; }
'
'  #uri    { color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; }
'
'  #dtstamp{ color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; text-align:left; width:30%; }
'
'  #objshowhide { color:#000000; cursor:hand; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; margin-right:0px; padding-right:10px; text-align:right; text-decoration:underline; z-index:2; word-wrap:normal; }
'
'  v\:* {behavior:url(#default#VML);}
'
'</style>
'<!-- Script 1 -->
'
'<script language="javascript">
'    var userAgent=navigator.userAgent;
'</script>
'
'<script language="vbscript" type="text/vbscript">
'<!{CDATA{
'<!--
''================================================================================
'' String "strShowHide(0/1)"
'' 0 = Hide all mode.
'' 1 = Show all mode.
'strShowHide = 1
'
''Localized strings
'strShow = "show"
'strHide = "hide"
'strShowAll = "show all"
'strHideAll = "hide all"
'strShown = "shown"
'strHidden = "hidden"
'strExpandoNumPixelsFromEdge = "10px"
'
''osVersion = 0
''if (instr(userAgent, "Windows NT 6.1")>0) then osVersion = 61
''if (instr(userAgent, "Windows NT 6.0")>0) then osVersion = 6
''if (not (instr(userAgent, "MSIE")>0)) then osVersion = 6
'
'Function IsSectionHeader(obj)
'    IsSectionHeader = (obj.className = "he0_expanded") Or (obj.className = "he1_expanded") Or (obj.className = "he1") Or (obj.className = "he2") Or (obj.className = "he2g") Or (obj.className = "he2c") or (obj.className = "he3") Or (obj.className = "he4") Or (obj.className = "he4h") Or (obj.className = "he5") Or (obj.className = "he5h")  or (obj.className = "he4_expanded")
'End Function
'
'
'Function IsSectionExpandedByDefault(objHeader)
'    IsSectionExpandedByDefault = (Right(objHeader.className, Len("_expanded")) = "_expanded")
'End Function
'
'
'' strState must be show | hide | toggle
'Sub SetSectionState(objHeader, strState)
'    ' Get the container object for the section.  It's the first one after the header obj.
'
'    i = objHeader.sourceIndex
'    Set all = objHeader.parentElement.document.all
'    While (all(i).className <> "container")
'        i = i + 1
'    Wend
'
'    Set objContainer = all(i)
'
'    If strState = "toggle" Then
'        If objContainer.style.display = "none" Then
'            SetSectionState objHeader, "show"
'        Else
'            SetSectionState objHeader, "hide"
'        End If
'
'    Else
'        Set objExpando = objHeader.children(1)
'
'        If strState = "show" Then
'            objContainer.style.display = "block"
'            'rem objExpando.innerText = strHide
'            'select case osVersion
'            '  case 61
'            '    objExpando.innerHTML = "<img src='res://sdiageng.dll/collapse.png' border=0 class='expando' width='16px' height='17px' alt='Colapse'/>"
'            '  case 6
'            '    objExpando.innerHTML = "<img src='res://wdc.dll/collapse.gif' border=0 class='expando' alt='Colapse'/>"
'            '  case else
'            '    objExpando.innerHTML =   "<v:group class=" & chr(34) & "expando" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " alt=" & chr(34) & "Show" & chr(34) & "><v:rect " & chr(34) & " stroked=" & chr(34) & "False" & chr(34) & "fillcolor=" & chr(34) & "#808080" & chr(34) & " style=" & chr(34) & "top:47;left:25;width:50;height:5" & chr(34) & " /></v:group>"
'            'end select
'            objExpando.innerHTML = "<v:group class=" & chr(34) & "expando" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & _
'                                                        " coordsize=" & chr(34) & "100,100" & chr(34) & " title=" & chr(34) & "Collapse" & chr(34) & "><v:oval class=" & chr(34) & "vmlimage" & chr(34) & _
'                                                        " style='width:100;height:100;z-index:0' fillcolor=" & chr(34) & "#B7B7B7" & chr(34) & " strokecolor=" & chr(34) & "#8F8F8F" & chr(34) & "><v:fill type=" & chr(34) & _
'                                                        "gradient" & chr(34) & " angle=" & chr(34) & "0" & chr(34) & " color=" & chr(34) & "#D1D1D1" & chr(34) & " color2=" & chr(34) & "#F5F5F5" & chr(34) & " /></v:oval><v:line class=" & chr(34) & _
'                                                        "vmlimage" & chr(34) & " style=" & chr(34) & "z-index:1" & chr(34) & " from=" & chr(34) & "25,65" & chr(34) & " to=" & chr(34) & "50,37" & chr(34) & " strokecolor=" & chr(34) & "#5D5D5D" & chr(34) & _
'                                                        " strokeweight=" & chr(34) & "2px" & chr(34) & "></v:line><v:line class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "z-index:2" & chr(34) & " from=" & chr(34) & "50,37" & chr(34) & _
'                                                        " to=" & chr(34) & "75,65" & chr(34) & " strokecolor=" & chr(34) & "#5D5D5D" & chr(34) & " strokeweight=" & chr(34) & "2px" & chr(34) & "></v:line></v:group>"
'
'        ElseIf strState = "hide" Then
'            objContainer.style.display = "none"
'            'rem objExpando.innerText = strShow
'            'select case osVersion
'            '  case 61
'            '    objExpando.innerHTML = "<img src='res://sdiageng.dll/expand.png' border=0 class='expando' width='16px' height='17px' alt='Expand'/>"
'            '  case 6
'            '    objExpando.innerHTML = "<img src='res://wdc.dll/expand.gif' border=0 class='expando' alt='Expand'/>"
'            '  case else
'            '    objExpando.innerHTML =   "<v:group class=" & chr(34) & "expando" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " alt=" & chr(34) & "Show" & chr(34) & "><v:rect fillcolor=" & chr(34) & "#808080" & chr(34) & " stroked=" & chr(34) & "False" & chr(34) & " style=" & chr(34) & "top:47;left:25;width:50;height:5" & chr(34) & " /><v:rect fillcolor=" & chr(34) & "#808080" & chr(34) & " stroked=" & chr(34) & "False" & chr(34) & " style=" & chr(34) & "top:25;left:47;width:5;height:50" & chr(34) & " /></v:group>"
'            'end select
'
'            objExpando.innerHTML = "<v:group class=" & chr(34) & "expando" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & _
'                                                           " coordsize=" & chr(34) & "100,100" & chr(34) & " title=" & chr(34) & "Expand" & chr(34) & "><v:oval class=" & chr(34) & "vmlimage" & chr(34) & _
'                                                           " style='width:100;height:100;z-index:0' fillcolor=" & chr(34) & "#B7B7B7" & chr(34) & " strokecolor=" & chr(34) & "#8F8F8F" & chr(34) & "><v:fill type=" & chr(34) & _
'                                                           "gradient" & chr(34) & " angle=" & chr(34) & "0" & chr(34) & " color=" & chr(34) & "#D1D1D1" & chr(34) & " color2=" & chr(34) & "#F5F5F5" & chr(34) & " /></v:oval><v:line class=" & _
'                                                           chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "z-index:1" & chr(34) & " from=" & chr(34) & "25,40" & chr(34) & " to=" & chr(34) & "50,68" & chr(34) & " strokecolor=" & chr(34) & _
'                                                           "#5D5D5D" & chr(34) & " strokeweight=" & chr(34) & "2px" & chr(34) & "></v:line><v:line class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "z-index:2" & chr(34) & " from=" & chr(34) & _
'                                                           "50,68" & chr(34) & " to=" & chr(34) & "75,40" & chr(34) & " strokecolor=" & chr(34) & "#5D5D5D" & chr(34) & " strokeweight=" & chr(34) & "2px" & chr(34) & "></v:line></v:group>"
'
'        End If
'
'    End If
'End Sub
'
'
'Sub ShowSection(objHeader)
'    SetSectionState objHeader, "show"
'End Sub
'
'
'Sub HideSection(objHeader)
'    SetSectionState objHeader, "hide"
'End Sub
'
'
'Sub ToggleSection(objHeader)
'    SetSectionState objHeader, "toggle"
'End Sub
'
'
''================================================================================
'' When user clicks anywhere in the document body, determine if user is clicking
'' on a header element.
''================================================================================
'Function document_onclick()
'    Set strsrc    = window.event.srcElement
'
'    While (strsrc.className = "sectionTitle" Or strsrc.className = "expando" Or strsrc.className = "vmlimage")
'        Set strsrc = strsrc.parentElement
'    Wend
'
'    ' Only handle clicks on headers.
'    If Not IsSectionHeader(strsrc) Then Exit Function
'
'    ToggleSection strsrc
'
'    window.event.returnValue = False
'End Function
'
''================================================================================
'' link at the top of the page to collapse/expand all collapsable elements
''================================================================================
'Function objshowhide_onClick()
'    Set objBody = document.body.all
'    Select Case strShowHide
'        Case 0
'            strShowHide = 1
'            objshowhide.innerText = strShowAll
'            For Each obji In objBody
'                If IsSectionHeader(obji) Then
'                    HideSection obji
'                End If
'            Next
'        Case 1
'            strShowHide = 0
'            objshowhide.innerText = strHideAll
'            For Each obji In objBody
'                If IsSectionHeader(obji) Then
'                    ShowSection obji
'                End If
'            Next
'    End Select
'End Function
'
''================================================================================
'' onload collapse all except the first two levels of headers (he0, he1)
''================================================================================
'Function window_onload()
'    ' Only initialize once.  The UI may reinsert a report into the webbrowser control,
'    ' firing onLoad multiple times.
'    If UCase(document.documentElement.getAttribute("gpmc_reportInitialized")) <> "TRUE" Then
'
'        ' Set text direction
'        Call fDetDir(UCase(document.dir))
'
'        ' Initialize sections to default expanded/collapsed state.
'        Set objBody = document.body.all
'
'        For Each obji in objBody
'            If IsSectionHeader(obji) Then
'                If IsSectionExpandedByDefault(obji) Then
'                    ShowSection obji
'                Else
'                    HideSection obji
'                End If
'            End If
'        Next
'
'        objshowhide.innerText = strShowAll
'
'        document.documentElement.setAttribute "gpmc_reportInitialized", "true"
'    End If
'End Function
'
'
'
'
''================================================================================
'' When direction (LTR/RTL) changes, change adjust for readability
''================================================================================
'Function document_onPropertyChange()
'    If window.event.propertyName = "dir" Then
'        Call fDetDir(UCase(document.dir))
'    End If
'End Function
'Function fDetDir(strDir)
'    strDir = UCase(strDir)
'    Select Case strDir
'        Case "LTR"
'            Set colRules = document.styleSheets(0).rules
'            For i = 0 To colRules.length -1
'                Set nug = colRules.item(i)
'                strClass = nug.selectorText
'                If nug.style.textAlign = "right" Then
'                    nug.style.textAlign = "left"
'                End If
'                Select Case strClass
'                    Case "DIV .expando"
'                        nug.style.Left = ""
'                        nug.style.right = strExpandoNumPixelsFromEdge
'                    Case "#objshowhide"
'                        nug.style.textAlign = "right"
'                End Select
'            Next
'        Case "RTL"
'            Set colRules = document.styleSheets(0).rules
'            For i = 0 To colRules.length -1
'                Set nug = colRules.item(i)
'                strClass = nug.selectorText
'                If nug.style.textAlign = "left" Then
'                    nug.style.textAlign = "right"
'                End If
'                Select Case strClass
'                    Case "DIV .expando"
'                        nug.style.Left = strExpandoNumPixelsFromEdge
'                        nug.style.right = ""
'                    Case "#objshowhide"
'                        nug.style.textAlign = "left"
'                End Select
'            Next
'    End Select
'End Function
'
''================================================================================
''When printing reports, if a given section is expanded, let's says "shown" (instead of "hide" in the UI).
''================================================================================
'Function window_onbeforeprint()
'    For Each obji In document.all
'        If obji.className = "expando" Then
'            If obji.innerText = strHide Then obji.innerText = strShown
'            If obji.innerText = strShow Then obji.innerText = strHidden
'        End If
'    Next
'End Function
'
''================================================================================
''If a section is collapsed, change to "hidden" in the printout (instead of "show").
''================================================================================
'Function window_onafterprint()
'    For Each obji In document.all
'        If obji.className = "expando" Then
'            If obji.innerText = strShown Then obji.innerText = strHide
'            If obji.innerText = strHidden Then obji.innerText = strShow
'        End If
'    Next
'End Function
'
''================================================================================
'' Adding keypress support for accessibility
''================================================================================
'Function document_onKeyPress()
'    If window.event.keyCode = "32" Or window.event.keyCode = "13" Or window.event.keyCode = "10" Then 'space bar (32) or carriage return (13) or line feed (10)
'        If window.event.srcElement.className = "expando" Then Call document_onclick() : window.event.returnValue = false
'        If window.event.srcElement.className = "sectionTitle" Then Call document_onclick() : window.event.returnValue = false
'        If window.event.srcElement.id = "objshowhide" Then Call objshowhide_onClick() : window.event.returnValue = false
'    End If
'End Function
'
'-->
'}}>
'</script>
'
'<!-- Script 2 -->
'
'<script language="javascript">
'  <!{CDATA{
'<!--
'function getExplainWindowTitle()
'{
'        return document.getElementById("explainText_windowTitle").innerHTML;
'}
'
'function getExplainWindowStyles()
'{
'        return document.getElementById("explainText_windowStyles").innerHTML;
'}
'
'function getExplainWindowSettingPathLabel()
'{
'        return document.getElementById("explainText_settingPathLabel").innerHTML;
'}
'
'function getExplainWindowExplainTextLabel()
'{
'        return document.getElementById("explainText_explainTextLabel").innerHTML;
'}
'
'function getExplainWindowPrintButton()
'{
'        return document.getElementById("explainText_printButton").innerHTML;
'}
'
'function getExplainWindowCloseButton()
'{
'        return document.getElementById("explainText_closeButton").innerHTML;
'}
'
'function getNoExplainTextAvailable()
'{
'        return document.getElementById("explainText_noExplainTextAvailable").innerHTML;
'}
'
'function getExplainWindowSupportedLabel()
'{
'        return document.getElementById("explainText_supportedLabel").innerHTML;
'}
'
'function getNoSupportedTextAvailable()
'{
'        return document.getElementById("explainText_noSupportedTextAvailable").innerHTML;
'}
'-->
'}}>
'</script>
'
'</head>
'
'<body>
'
'   <table class="title" cellpadding="0" cellspacing="0">
'   <tr><td colspan="2" class="rsopheader">Processes/Performance Information</td></tr>
'   <tr><td colspan="2" class="rsopname">Machine name: <xsl:value-of select="Title"/></td></tr>
'   <tr><td id="dtstamp">Data collected on: <xsl:value-of select="TimeField"/></td><td><div id="objshowhide" tabindex="0"></div></td></tr>
'   </table>
'   <div class="filler"></div>
'
'  <xsl:if  test="./Alerts/Alert">
'  <div class="container">
'   <div class="he0_expanded">
'    <span class="sectionTitle" tabindex="0">Alerts</span>
'    <a class="expando" href="#"></a>
'  </div>
'   <div class="container">
'   <xsl:for-each select="./Alerts/Alert">
'       <xsl:sort select="AlertPriority" order="descending" data-type="number"/>
'       <div class="he2b">
'           <span class="sectionTitle" tabindex="0">
'               <xsl:choose>
'                   <xsl:when test="AlertType = 'Information'">
'                           <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Information">
'                             <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="white" strokecolor="#336699" />
'                             <v:line class="vmlimage" style="z-index:1" from="50,15" to="50,25" strokecolor="#336699" strokeweight="3px" />
'                             <v:line class="vmlimage" style="z-index:2" from="50,35" to="50,80" strokecolor="#336699" strokeweight="3px" />
'                             </v:group>
'                   </xsl:when>
'                   <xsl:when test="AlertType = 'Warning'">
'                       <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Warning">
'                               <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="#C0C0C0">
'                               <v:path v="m 50,0 l 0,99 99,99 x e" />
'                               </v:shape>
'                               <v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
'                               </v:rect>
'                               <v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
'                               </v:rect>
'                       </v:group>
'                   </xsl:when>
'                   <xsl:when test="AlertType = 'Error'">
'                   <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Error">
'                       <v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="red">
'                       </v:oval>
'                       <v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
'                       </v:line>
'                       <v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
'                       </v:line>
'                   </v:group>
'                   </xsl:when>
'               </xsl:choose>
'               <xsl:value-of select="AlertType"/>
'           </span><a class="expando" href="#"></a>
'       </div>
'       <div class="container"><div class="he4i"><table cellpadding="0" class="info0">
'           <tr><td class="infoFirstCol">Category: </td><td class="infoSecondCol"><xsl:value-of disable-output-escaping="yes" select="AlertCategory"/></td><td></td></tr>
'           <tr><td class="infoFirstCol">Message: </td><td class="infoSecondCol"><xsl:value-of disable-output-escaping="yes" select="AlertMessage"/></td><td></td></tr>
'           <tr><td class="infoFirstCol">Recommendation: </td><td class="infoSecondCol"><xsl:value-of disable-output-escaping="yes" select="AlertRecommendation"/></td><td></td></tr>
'           </table>
'       </div>
'       </div>
'   </xsl:for-each>
'   </div>
'   </div>
'   <div class="filler"></div>
'  </xsl:if>
'
'   <xsl:for-each select="./Section">
'
'   <div class="he0_expanded"><span class="sectionTitle" tabindex="0"><xsl:value-of select="SectionTitle"/></span><a class="expando" href="#"></a></div>
'
'       <div class="container"><div class="he4i"><table cellpadding="0" class="info4" >
'       <tr><td></td><td></td><td></td><td></td><td></td></tr>
'       <xsl:for-each select="./Item">
'       <xsl:variable name="pos" select="position()" />
'       <xsl:variable name="mod" select="($pos mod 2)" />
'       <tr><td><xsl:value-of select="@name"/></td><td colspan="4"><xsl:value-of select="."/></td></tr>
'       </xsl:for-each>
'       </table>
'       <xsl:for-each select="./SubSection">
'           <div class="container">
'           <div class="he3_expanded"><span class="sectionTitle" tabindex="0"><xsl:value-of select="SectionTitle/@name"/><xsl:text> </xsl:text><a name="{SectionTitle}"><xsl:value-of select="SectionTitle"/></a></span><a class="expando" href="#"></a></div>
'           <div class="container"><div class="he4i"><table cellpadding="0" class="info4">
'               <tr><td></td><td></td><td></td><td></td><td></td></tr>
'               <xsl:for-each select="./Item">
'               <xsl:variable name="pos" select="position()" />
'               <xsl:variable name="mod" select="($pos mod 2)" />
'               <tr><td class="lines{$mod}"><xsl:value-of select="@name"/></td><td colspan="4" class="lines{$mod}"><xsl:value-of disable-output-escaping="yes" select="."/></td><td></td></tr>
'               </xsl:for-each>
'               </table>
'
'               <xsl:for-each select="./ProcessCollection">
'                   <xsl:variable name="MaxValue" select="MaxValue" />
'                   <table cellpadding="0" class="infoqfe" >
'                       <tr><th>Process Name</th><th>ProcessID</th><th><xsl:value-of select="./Process/Value/@name"/></th></tr>
'                           <xsl:for-each select="./Process">
'                               <xsl:variable name="pos" select="position()" />
'                               <xsl:variable name="mod" select="($pos mod 2)"/>
'                               <tr>
'                                   <td class="lines{$mod}"><xsl:value-of select="Name"/></td>
'                                   <td class="lines{$mod}"><xsl:value-of select="ProcessID"/></td>
'                                   <td class="lines{$mod}">
'                                       <v:group id="GraphValue" class="vmlimage" style="width:400px;height:15px;vertical-align:middle" coordsize="{$MaxValue},100" title="{ValueDisplay}">
'                                           <v:rect class="vmlimage" style="top:1;left:1;width:{$MaxValue};height:100" strokecolor="#336699">
'                                                 <v:fill type="gradient" angle="0" color="#C4CCC7" color2="white" />
'                                       </v:rect>
'                                           <v:rect class="vmlimage" style="top:2;left:1;width:{Value};height:99" strokecolor="{GraphColorEnd}">
'                                               <v:fill type="gradient" angle="270" color="{GraphColorStart}" color2="{GraphColorEnd}" />
'                                           </v:rect>
'                                           <v:rect style="top:-70;left:{TextStartPos};width:{$MaxValue};height:50" filled="false" stroked="false" textboxrect="top:19;left:1;width:{$MaxValue};height:30">
'                                               <v:textbox style="color:{TextColor};" inset="10px, 10px, 28px, 177px">
'                                                   <xsl:value-of select="ValueDisplay"/>
'                                               </v:textbox>
'                                           </v:rect>
'                                       </v:group>
'                                   </td>
'                               </tr>
'                           </xsl:for-each>
'                   </table>
'               </xsl:for-each>
'
'        <xsl:for-each select="./KernelMemory">
'          <xsl:variable name="MaxValue" select="MaxValue" />
'          <table cellpadding="0" class="infoqfe" >
'            <tr>
'              <th>Tag Name</th>
'              <th colspan="2">
'                <xsl:value-of select="./PoolMemory/Value/@name"/>
'              </th>
'            </tr>
'            <xsl:for-each select="./PoolMemory">
'              <xsl:variable name="pos" select="position()" />
'              <xsl:variable name="mod" select="($pos mod 2)"/>
'              <tr>
'                <td class="lines{$mod}">
'                  <xsl:value-of select="Tag"/>
'                </td>
'                <td class="lines{$mod}">
'                  <xsl:value-of select="ValueDisplay"/>
'                </td>
'                <td class="lines{$mod}">
'                  <v:group id="GraphValue" class="vmlimage" style="width:400px;height:15px;vertical-align:middle" coordsize="{$MaxValue},100" title="{ValueDisplay}">
'                    <v:rect class="vmlimage" style="top:1;left:1;width:{$MaxValue};height:100" strokecolor="#336699">
'                      <v:fill type="gradient" angle="0" color="#C4CCC7" color2="white" />
'                    </v:rect>
'                    <v:rect class="vmlimage" style="top:2;left:2;width:{Value};height:99" strokecolor="{GraphColorEnd}">
'                      <v:fill type="gradient" angle="270" color="{GraphColorStart}" color2="{GraphColorEnd}" />
'                    </v:rect>
'                  </v:group>
'                </td>
'              </tr>
'            </xsl:for-each>
'          </table>
'        </xsl:for-each>
'
'
'      </div></div>
'
'                   </div>
'       </xsl:for-each>
'
'       </div></div>
'   <div class="filler"></div>
'
'   </xsl:for-each>
'
'</body>
'</html>
'</xsl:template>
'</xsl:stylesheet>
End Sub

Class ezPLA
    '************************************************
    'ezPLA VB Class
    'Version 1.0.1
    'Date: 4-24-2009
    'Author: Andre Teixeira - andret@microsoft.com
    '************************************************
    
    Private objFSO
    Private objShell
    
    Public Section
    Public SectionPriority
    Public AlertType
    Public AlertPriority
    Public Symptom
    Public Details
    Public MoreInformation
    
    Private ALERT_INFORMATION
    Private ALERT_WARNING
    Private ALERT_ERROR
    Private ALERT_NOTE
    
    Public Function AddAlerttoPLA()
        
        Set objShell = CreateObject("WScript.Shell")
        Set objFSO = CreateObject("Scripting.FileSystemObject")
            
        ALERT_INFORMATION = 1
        ALERT_WARNING = 2
        ALERT_ERROR = 3
        ALERT_NOTE = 4
                
        On Error Resume Next
        
        'Validation
        
        If Len(Section) = 0 Then
            Section = "Messages"
        End If
        
        If Len(SectionPriority) = 0 Then
            If IsNumeric(SectionPriority) Then
                SectionPriority = CInt(SectionPriority)
            Else
                SectionPriority = 50 'Default Value
            End If
            SectionPriority = 50 'Default Value
        End If
    
        If Not IsNumeric(AlertType) Then
            AlertType = ALERT_NOTE
        ElseIf AlertType > 4 Then
            AlertType = ALERT_NOTE
        End If
        
        If Not IsNumeric(AlertPriority) Then
            AlertPriority = 20 - AlertType
        End If
        
        If Len(Symptom) = 0 Then
            DisplayError "Checking Values for Symptom", 5000, "AddAlertoPLA", "You have to assign a correct value for Symptom."
            Exit Function
        End If
    
        WriteAlertToPLA
        
    End Function
    
    Private Function WriteAlertToPLA()
        
        Dim strAlertType
        Dim XMLDoc 
        Dim XMLDoc2
        
        Dim objSectionElement
        Dim objTableElement
        Dim objXMLAtt
        Dim objReportElement
        Dim objHeaderElement
        Dim objItemElement
        Dim objDataElement 
        Dim strDiagnosticXMLPath
                
        strDiagnosticXMLPath = "..\ReportFiles\Diagnostic_Results.XML"
        
        Select Case AlertType
            Case ALERT_INFORMATION
                strAlertType = "info"
            Case ALERT_WARNING
                strAlertType = "warning"
            Case ALERT_ERROR
                strAlertType = "error"
            Case ALERT_NOTE
                strAlertType = "note"
        End Select
        
        Set XMLDoc = CreateObject("Microsoft.XMLDOM")
        XMLDoc.async = "false"
    
        If objFSO.FileExists(strDiagnosticXMLPath) Then 'A PLA reporting already exists
            XMLDoc.Load strDiagnosticXMLPath
            Set objSectionElement = XMLDoc.selectNodes("/Report/Section[@name='" & Section & "']").Item(0) 'Try to find the 'Section' section
            If CheckForError(XMLDoc, "Searching Section Object") <> 0 Then Exit Function
        Else
            wscript.Echo "      " & strDiagnosticXMLPath & " does not exist. Creating it..."
            If Not objFSO.FolderExists("..\ReportFiles") Then objFSO.CreateFolder ("..\ReportFiles")
            XMLDoc.loadXML ("<?xml version=""1.0""?><?xml-stylesheet type=""text/xsl"" href=""report.xsl""?><Report name=""msdtAdvisor"" level=""1"" version=""1"" top=""9999"" portable=""1""/>")
            If CheckForError(XMLDoc, "Loading Standard XML file") <> 0 Then Exit Function
        End If
              
        If XMLObjectIsEmptyorNothing(objSectionElement) Then  'Create the 'Messages' section if it does not exist
                Set objReportElement = XMLDoc.selectNodes("/Report").Item(0)
                
                Set objSectionElement = XMLDoc.createElement("Section")
                
                Set objXMLAtt = XMLDoc.createAttribute("name")
                objSectionElement.Attributes.setNamedItem(objXMLAtt).Text = Section
                Set objXMLAtt = XMLDoc.createAttribute("expand")
                objSectionElement.Attributes.setNamedItem(objXMLAtt).Text = "true"
                Set objXMLAtt = XMLDoc.createAttribute("key")
                objSectionElement.Attributes.setNamedItem(objXMLAtt).Text = CStr(SectionPriority)
                
                objReportElement.appendChild objSectionElement
                
                If CheckForError(XMLDoc, "Creating Section Object") <> 0 Then Exit Function
        End If
        
        'Setting Alert Type and Priority
        Set objTableElement = XMLDoc.createElement("Table")
        Set objXMLAtt = XMLDoc.createAttribute("name")
        objTableElement.Attributes.setNamedItem(objXMLAtt).Text = strAlertType
        Set objXMLAtt = XMLDoc.createAttribute("style")
        objTableElement.Attributes.setNamedItem(objXMLAtt).Text = "info"
        Set objXMLAtt = XMLDoc.createAttribute("key")
        objTableElement.Attributes.setNamedItem(objXMLAtt).Text = CStr(AlertPriority)
        
        Set objHeaderElement = XMLDoc.createElement("Header")
        objTableElement.appendChild objHeaderElement
        If CheckForError(XMLDoc, "Setting Alert Type and Priority to XML Header") <> 0 Then Exit Function
        
        Set objItemElement = XMLDoc.createElement("Item")
        Set objDataElement = XMLDoc.createElement("Data")
        
        Set objXMLAtt = XMLDoc.createAttribute("name")
        objDataElement.Attributes.setNamedItem(objXMLAtt).Text = "Symptom"
        Set objXMLAtt = XMLDoc.createAttribute("img")
        objDataElement.Attributes.setNamedItem(objXMLAtt).Text = strAlertType
        Set objXMLAtt = XMLDoc.createAttribute("message")
        objDataElement.Attributes.setNamedItem(objXMLAtt).Text = "standard_Message"
        
        objDataElement.appendChild XMLDoc.createTextNode(Symptom)
        objItemElement.appendChild objDataElement
    
        If CheckForError(XMLDoc, "Appending Symptom to XML") <> 0 Then Exit Function
    
        If Len(Details) > 0 Then
            Set XMLDoc2 = CreateObject("Microsoft.XMLDOM")
            XMLDoc2.async = "false"
            XMLDoc2.loadXML "<?xml version=""1.0""?><Data name=""Details"" message=""standard_Message"">" & Details & "</Data>"
            Set objDataElement = XMLDoc2.documentElement
            objItemElement.appendChild objDataElement
            If CheckForError(XMLDoc, "Appending Details to XML") <> 0 Then Exit Function
        End If
                    
        If Len(MoreInformation) > 0 Then
            Set XMLDoc2 = CreateObject("Microsoft.XMLDOM")
            XMLDoc2.async = "false"
            XMLDoc2.loadXML "<?xml version=""1.0""?><Data name=""Additional Information"" message=""standard_Message"">" & MoreInformation & "</Data>"
            Set objDataElement = XMLDoc2.documentElement
            objItemElement.appendChild objDataElement
            If CheckForError(XMLDoc, "Appending MoreInformation to XML") <> 0 Then Exit Function
        End If
        
        objTableElement.appendChild objItemElement
        If CheckForError(XMLDoc, "Appending Table to XML") <> 0 Then Exit Function
        
        objSectionElement.appendChild objTableElement
        If CheckForError(XMLDoc, "Appending Alert XML Element to XML") <> 0 Then Exit Function
        
        XMLDoc.Save strDiagnosticXMLPath
    
        If CheckForError(XMLDoc, "Saving Report.XML file") <> 0 Then Exit Function
    
    End Function
    
    Private Function XMLObjectIsEmptyorNothing(objXML)
        On Error Resume Next
        XMLObjectIsEmptyorNothing = (objXML Is Nothing)
        If Err.Number > 0 Then
            XMLObjectIsEmptyorNothing = IsEmpty(objXML)
        End If
        Err.Clear
    End Function
    
    Private Function TranslateXMLChars(strRAWString)
        strRAWString = Replace(strRAWString, "&", "&amp;")
        strRAWString = Replace(strRAWString, "<", "&lt;")
        strRAWString = Replace(strRAWString, ">", "&gt;")
        strRAWString = Replace(strRAWString, "'", "&apos;")
        strRAWString = Replace(strRAWString, Chr(34), "&quot;")
        TranslateXMLChars = strRAWString
    End Function
    
    Private Function CheckForError(xmlFile, strOperation)
        Dim strErrText
            If (Err.Number <> 0) Or (xmlFile.parseError.errorCode <> 0) Then
                If Err.Number <> 0 Then
                    DisplayError strOperation, Err.Number, Err.Source, Err.Description
                    CheckForError = Err.Number
                Else
                    With xmlFile.parseError
                        strErrText = "Failed to process/ load XML file " & _
                                "due the following error:" & vbCrLf & _
                                "Error #: " & .errorCode & ": " & .reason & _
                                "Line #: " & .Line & vbCrLf & _
                                "Line Position: " & .linepos & vbCrLf & _
                                "Position In File: " & .filepos & vbCrLf & _
                                "Source Text: " & .srcText & vbCrLf & _
                                "Document URL: " & .url
                        CheckForError = .errorCode
                    End With
                    DisplayError strOperation, 5001, "CheckForXMLError", strErrText
                End If
            Else
                CheckForError = 0
            End If
    End Function
    
    Private Sub DisplayError(strErrorLocation, errNumber, errSource, errDescription)
        On Error Resume Next
        If errNumber <> 0 Then
            wscript.Echo "Error " & HexFormat(errNumber) & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
            wscript.Echo errSource & " - " & errDescription
        Else
            wscript.Echo "An error has ocurred!. " & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
        End If
    End Sub
End Class
'' SIG '' Begin signature block
'' SIG '' MIIa9gYJKoZIhvcNAQcCoIIa5zCCGuMCAQExCzAJBgUr
'' SIG '' DgMCGgUAMGcGCisGAQQBgjcCAQSgWTBXMDIGCisGAQQB
'' SIG '' gjcCAR4wJAIBAQQQTvApFpkntU2P5azhDxfrqwIBAAIB
'' SIG '' AAIBAAIBAAIBADAhMAkGBSsOAwIaBQAEFA1XzuWifNn7
'' SIG '' O7HDFBxozVljwh/GoIIVgjCCBMMwggOroAMCAQICEzMA
'' SIG '' AABMoehNzLR0ezsAAAAAAEwwDQYJKoZIhvcNAQEFBQAw
'' SIG '' dzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
'' SIG '' b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
'' SIG '' Y3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWlj
'' SIG '' cm9zb2Z0IFRpbWUtU3RhbXAgUENBMB4XDTEzMTExMTIy
'' SIG '' MTEzMVoXDTE1MDIxMTIyMTEzMVowgbMxCzAJBgNVBAYT
'' SIG '' AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
'' SIG '' EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
'' SIG '' cG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsT
'' SIG '' Hm5DaXBoZXIgRFNFIEVTTjpDMEY0LTMwODYtREVGODEl
'' SIG '' MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
'' SIG '' dmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
'' SIG '' ggEBALHY+hsGK3eo5JRdfA/meqaS7opUHaT5hHWFl8zL
'' SIG '' XJbQ13Ut2Qj7W9LuLSXGNz71q34aU+VXvmvov8qWCtxG
'' SIG '' 8VoePgLSsuAmjgBke748k/hYMnmH0hpdI7ycUcQPEPoE
'' SIG '' WLUWdm7svMblvvytrMFB26rOefUcsplBp3olK/+reA1Y
'' SIG '' OrFeUN5kTODKFSrfpun+pGYvWxAJCSYh1D8NL23S+HeQ
'' SIG '' A2zeFBKljOc2H/SHpbBBF2/jTXRmwv2icUY1UcxrF1Fj
'' SIG '' +hWUkppfSyi65hZFSekstf6Lh6/8pW1D3KYw+iko75sN
'' SIG '' LFyD3hKNarTbce9cFFoqIyj/gXBX8YwHmhPYKlMCAwEA
'' SIG '' AaOCAQkwggEFMB0GA1UdDgQWBBS5Da2zTfTanxqyJyZV
'' SIG '' DSBE2Jji9DAfBgNVHSMEGDAWgBQjNPjZUkZwCu1A+3b7
'' SIG '' syuwwzWzDzBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
'' SIG '' Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
'' SIG '' cy9NaWNyb3NvZnRUaW1lU3RhbXBQQ0EuY3JsMFgGCCsG
'' SIG '' AQUFBwEBBEwwSjBIBggrBgEFBQcwAoY8aHR0cDovL3d3
'' SIG '' dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNyb3Nv
'' SIG '' ZnRUaW1lU3RhbXBQQ0EuY3J0MBMGA1UdJQQMMAoGCCsG
'' SIG '' AQUFBwMIMA0GCSqGSIb3DQEBBQUAA4IBAQAJik4Gr+jt
'' SIG '' gs8dB37XKqckCy2vmlskf5RxDFWIJBpSFWPikE0FSphK
'' SIG '' nPvhp21oVYK5KeppqbLV4wza0dZ6JTd4ZxwM+9spWhqX
'' SIG '' OCo5Vkb7NYG55D1GWo7k/HU3WFlJi07bPBWdc1JL63sM
'' SIG '' OsItwbObUi3gNcW5wVez6D2hPETyIxYeCqpZNyfQlVJe
'' SIG '' qH8/VPCB4dyavWXVePb3TDm73eDWNw6RmoeMc+dxZFL3
'' SIG '' PgPYxs1yuDQ0mFuM0/UIput4xlGgDQ5v9Gs8QBpgFiyp
'' SIG '' BlKdHBOQzm8CHup7nLP2+Jdg8mXR0R+HOsF18EKNeu2M
'' SIG '' crJ7+yyKtJFHVOIuacwWVBpZMIIE7DCCA9SgAwIBAgIT
'' SIG '' MwAAALARrwqL0Duf3QABAAAAsDANBgkqhkiG9w0BAQUF
'' SIG '' ADB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
'' SIG '' Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
'' SIG '' TWljcm9zb2Z0IENvcnBvcmF0aW9uMSMwIQYDVQQDExpN
'' SIG '' aWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQTAeFw0xMzAx
'' SIG '' MjQyMjMzMzlaFw0xNDA0MjQyMjMzMzlaMIGDMQswCQYD
'' SIG '' VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
'' SIG '' A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
'' SIG '' IENvcnBvcmF0aW9uMQ0wCwYDVQQLEwRNT1BSMR4wHAYD
'' SIG '' VQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24wggEiMA0G
'' SIG '' CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDor1yiIA34
'' SIG '' KHy8BXt/re7rdqwoUz8620B9s44z5lc/pVEVNFSlz7SL
'' SIG '' qT+oN+EtUO01Fk7vTXrbE3aIsCzwWVyp6+HXKXXkG4Un
'' SIG '' m/P4LZ5BNisLQPu+O7q5XHWTFlJLyjPFN7Dz636o9UEV
'' SIG '' XAhlHSE38Cy6IgsQsRCddyKFhHxPuRuQsPWj/ov0DJpO
'' SIG '' oPXJCiHiquMBNkf9L4JqgQP1qTXclFed+0vUDoLbOI8S
'' SIG '' /uPWenSIZOFixCUuKq6dGB8OHrbCryS0DlC83hyTXEmm
'' SIG '' ebW22875cHsoAYS4KinPv6kFBeHgD3FN/a1cI4Mp68fF
'' SIG '' SsjoJ4TTfsZDC5UABbFPZXHFAgMBAAGjggFgMIIBXDAT
'' SIG '' BgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUWXGm
'' SIG '' WjNN2pgHgP+EHr6H+XIyQfIwUQYDVR0RBEowSKRGMEQx
'' SIG '' DTALBgNVBAsTBE1PUFIxMzAxBgNVBAUTKjMxNTk1KzRm
'' SIG '' YWYwYjcxLWFkMzctNGFhMy1hNjcxLTc2YmMwNTIzNDRh
'' SIG '' ZDAfBgNVHSMEGDAWgBTLEejK0rQWWAHJNy4zFha5TJoK
'' SIG '' HzBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1p
'' SIG '' Y3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWND
'' SIG '' b2RTaWdQQ0FfMDgtMzEtMjAxMC5jcmwwWgYIKwYBBQUH
'' SIG '' AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1p
'' SIG '' Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY0NvZFNpZ1BD
'' SIG '' QV8wOC0zMS0yMDEwLmNydDANBgkqhkiG9w0BAQUFAAOC
'' SIG '' AQEAMdduKhJXM4HVncbr+TrURE0Inu5e32pbt3nPApy8
'' SIG '' dmiekKGcC8N/oozxTbqVOfsN4OGb9F0kDxuNiBU6fNut
'' SIG '' zrPJbLo5LEV9JBFUJjANDf9H6gMH5eRmXSx7nR2pEPoc
'' SIG '' sHTyT2lrnqkkhNrtlqDfc6TvahqsS2Ke8XzAFH9IzU2y
'' SIG '' RPnwPJNtQtjofOYXoJtoaAko+QKX7xEDumdSrcHps3Om
'' SIG '' 0mPNSuI+5PNO/f+h4LsCEztdIN5VP6OukEAxOHUoXgSp
'' SIG '' Rm3m9Xp5QL0fzehF1a7iXT71dcfmZmNgzNWahIeNJDD3
'' SIG '' 7zTQYx2xQmdKDku/Og7vtpU6pzjkJZIIpohmgjCCBbww
'' SIG '' ggOkoAMCAQICCmEzJhoAAAAAADEwDQYJKoZIhvcNAQEF
'' SIG '' BQAwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcGCgmS
'' SIG '' JomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWlj
'' SIG '' cm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
'' SIG '' MB4XDTEwMDgzMTIyMTkzMloXDTIwMDgzMTIyMjkzMlow
'' SIG '' eTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
'' SIG '' b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
'' SIG '' Y3Jvc29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWlj
'' SIG '' cm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EwggEiMA0GCSqG
'' SIG '' SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCycllcGTBkvx2a
'' SIG '' YCAgQpl2U2w+G9ZvzMvx6mv+lxYQ4N86dIMaty+gMuz/
'' SIG '' 3sJCTiPVcgDbNVcKicquIEn08GisTUuNpb15S3GbRwfa
'' SIG '' /SXfnXWIz6pzRH/XgdvzvfI2pMlcRdyvrT3gKGiXGqel
'' SIG '' cnNW8ReU5P01lHKg1nZfHndFg4U4FtBzWwW6Z1KNpbJp
'' SIG '' L9oZC/6SdCnidi9U3RQwWfjSjWL9y8lfRjFQuScT5EAw
'' SIG '' z3IpECgixzdOPaAyPZDNoTgGhVxOVoIoKgUyt0vXT2Pn
'' SIG '' 0i1i8UU956wIAPZGoZ7RW4wmU+h6qkryRs83PDietHdc
'' SIG '' pReejcsRj1Y8wawJXwPTAgMBAAGjggFeMIIBWjAPBgNV
'' SIG '' HRMBAf8EBTADAQH/MB0GA1UdDgQWBBTLEejK0rQWWAHJ
'' SIG '' Ny4zFha5TJoKHzALBgNVHQ8EBAMCAYYwEgYJKwYBBAGC
'' SIG '' NxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQU/dExTtMm
'' SIG '' ipXhmGA7qDFvpjy82C0wGQYJKwYBBAGCNxQCBAweCgBT
'' SIG '' AHUAYgBDAEEwHwYDVR0jBBgwFoAUDqyCYEBWJ5flJRP8
'' SIG '' KuEKU5VZ5KQwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDov
'' SIG '' L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVj
'' SIG '' dHMvbWljcm9zb2Z0cm9vdGNlcnQuY3JsMFQGCCsGAQUF
'' SIG '' BwEBBEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3d3dy5t
'' SIG '' aWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNyb3NvZnRS
'' SIG '' b290Q2VydC5jcnQwDQYJKoZIhvcNAQEFBQADggIBAFk5
'' SIG '' Pn8mRq/rb0CxMrVq6w4vbqhJ9+tfde1MOy3XQ60L/svp
'' SIG '' LTGjI8x8UJiAIV2sPS9MuqKoVpzjcLu4tPh5tUly9z7q
'' SIG '' QX/K4QwXaculnCAt+gtQxFbNLeNK0rxw56gNogOlVuC4
'' SIG '' iktX8pVCnPHz7+7jhh80PLhWmvBTI4UqpIIck+KUBx3y
'' SIG '' 4k74jKHK6BOlkU7IG9KPcpUqcW2bGvgc8FPWZ8wi/1wd
'' SIG '' zaKMvSeyeWNWRKJRzfnpo1hW3ZsCRUQvX/TartSCMm78
'' SIG '' pJUT5Otp56miLL7IKxAOZY6Z2/Wi+hImCWU4lPF6H0q7
'' SIG '' 0eFW6NB4lhhcyTUWX92THUmOLb6tNEQc7hAVGgBd3TVb
'' SIG '' Ic6YxwnuhQ6MT20OE049fClInHLR82zKwexwo1eSV32U
'' SIG '' jaAbSANa98+jZwp0pTbtLS8XyOZyNxL0b7E8Z4L5UrKN
'' SIG '' MxZlHg6K3RDeZPRvzkbU0xfpecQEtNP7LN8fip6sCvsT
'' SIG '' J0Ct5PnhqX9GuwdgR2VgQE6wQuxO7bN2edgKNAltHIAx
'' SIG '' H+IOVN3lofvlRxCtZJj/UBYufL8FIXrilUEnacOTj5XJ
'' SIG '' jdibIa4NXJzwoq6GaIMMai27dmsAHZat8hZ79haDJLmI
'' SIG '' z2qoRzEvmtzjcT3XAH5iR9HOiMm4GPoOco3Boz2vAkBq
'' SIG '' /2mbluIQqBC0N1AI1sM9MIIGBzCCA++gAwIBAgIKYRZo
'' SIG '' NAAAAAAAHDANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZIm
'' SIG '' iZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWlj
'' SIG '' cm9zb2Z0MS0wKwYDVQQDEyRNaWNyb3NvZnQgUm9vdCBD
'' SIG '' ZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDcwNDAzMTI1
'' SIG '' MzA5WhcNMjEwNDAzMTMwMzA5WjB3MQswCQYDVQQGEwJV
'' SIG '' UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
'' SIG '' UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
'' SIG '' cmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1T
'' SIG '' dGFtcCBQQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
'' SIG '' ggEKAoIBAQCfoWyx39tIkip8ay4Z4b3i48WZUSNQrc7d
'' SIG '' GE4kD+7Rp9FMrXQwIBHrB9VUlRVJlBtCkq6YXDAm2gBr
'' SIG '' 6Hu97IkHD/cOBJjwicwfyzMkh53y9GccLPx754gd6udO
'' SIG '' o6HBI1PKjfpFzwnQXq/QsEIEovmmbJNn1yjcRlOwhtDl
'' SIG '' KEYuJ6yGT1VSDOQDLPtqkJAwbofzWTCd+n7Wl7PoIZd+
'' SIG '' +NIT8wi3U21StEWQn0gASkdmEScpZqiX5NMGgUqi+YSn
'' SIG '' EUcUCYKfhO1VeP4Bmh1QCIUAEDBG7bfeI0a7xC1Un68e
'' SIG '' eEExd8yb3zuDk6FhArUdDbH895uyAc4iS1T/+QXDwiAL
'' SIG '' AgMBAAGjggGrMIIBpzAPBgNVHRMBAf8EBTADAQH/MB0G
'' SIG '' A1UdDgQWBBQjNPjZUkZwCu1A+3b7syuwwzWzDzALBgNV
'' SIG '' HQ8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwgZgGA1Ud
'' SIG '' IwSBkDCBjYAUDqyCYEBWJ5flJRP8KuEKU5VZ5KShY6Rh
'' SIG '' MF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAXBgoJkiaJ
'' SIG '' k/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jv
'' SIG '' c29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eYIQ
'' SIG '' ea0WoUqgpa1Mc1j0BxMuZTBQBgNVHR8ESTBHMEWgQ6BB
'' SIG '' hj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
'' SIG '' bC9wcm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmww
'' SIG '' VAYIKwYBBQUHAQEESDBGMEQGCCsGAQUFBzAChjhodHRw
'' SIG '' Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
'' SIG '' Y3Jvc29mdFJvb3RDZXJ0LmNydDATBgNVHSUEDDAKBggr
'' SIG '' BgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAgEAEJeKw1wD
'' SIG '' RDbd6bStd9vOeVFNAbEudHFbbQwTq86+e4+4LtQSooxt
'' SIG '' YrhXAstOIBNQmd16QOJXu69YmhzhHQGGrLt48ovQ7DsB
'' SIG '' 7uK+jwoFyI1I4vBTFd1Pq5Lk541q1YDB5pTyBi+FA+mR
'' SIG '' KiQicPv2/OR4mS4N9wficLwYTp2OawpylbihOZxnLcVR
'' SIG '' DupiXD8WmIsgP+IHGjL5zDFKdjE9K3ILyOpwPf+FChPf
'' SIG '' wgphjvDXuBfrTot/xTUrXqO/67x9C0J71FNyIe4wyrt4
'' SIG '' ZVxbARcKFA7S2hSY9Ty5ZlizLS/n+YWGzFFW6J1wlGys
'' SIG '' OUzU9nm/qhh6YinvopspNAZ3GmLJPR5tH4LwC8csu89D
'' SIG '' s+X57H2146SodDW4TsVxIxImdgs8UoxxWkZDFLyzs7BN
'' SIG '' Z8ifQv+AeSGAnhUwZuhCEl4ayJ4iIdBD6Svpu/RIzCzU
'' SIG '' 2DKATCYqSCRfWupW76bemZ3KOm+9gSd0BhHudiG/m4LB
'' SIG '' J1S2sWo9iaF2YbRuoROmv6pH8BJv/YoybLL+31HIjCPJ
'' SIG '' Zr2dHYcSZAI9La9Zj7jkIeW1sMpjtHhUBdRBLlCslLCl
'' SIG '' eKuzoJZ1GtmShxN1Ii8yqAhuoFuMJb+g74TKIdbrHk/J
'' SIG '' mu5J4PcBZW+JC33Iacjmbuqnl84xKf8OxVtc2E0bodj6
'' SIG '' L54/LlUWa8kTo/0xggTgMIIE3AIBATCBkDB5MQswCQYD
'' SIG '' VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
'' SIG '' A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
'' SIG '' IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQg
'' SIG '' Q29kZSBTaWduaW5nIFBDQQITMwAAALARrwqL0Duf3QAB
'' SIG '' AAAAsDAJBgUrDgMCGgUAoIH5MBkGCSqGSIb3DQEJAzEM
'' SIG '' BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
'' SIG '' BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTxWE32AEuY
'' SIG '' nXklshUTgAfZt+iV3TCBmAYKKwYBBAGCNwIBDDGBiTCB
'' SIG '' hqBsgGoARABJAEEARwBfAEMAVABTAF8ARwBlAG4AZQBy
'' SIG '' AGEAbABfAFIAZQBwAG8AcgB0AHMAXwBnAGwAbwBiAGEA
'' SIG '' bABfAFAAcgBvAGMAZQBzAHMAZQBzAFAAZQByAGYASQBu
'' SIG '' AGYAbwAuAHYAYgBzoRaAFGh0dHA6Ly9taWNyb3NvZnQu
'' SIG '' Y29tMA0GCSqGSIb3DQEBAQUABIIBACBmXx9ZZKSjZC/5
'' SIG '' ViKilhkze269QXXihOIOi2TtgaE7LHrl2dfmFGesTDug
'' SIG '' HyiTDG5Xt3sW6hGZf8FV3JzEQ55psitqRDkG5McZGnFy
'' SIG '' Dy4SdhFbCZ2VXQXmeR7U2cCnzLDrwNgu7vamorgOCt39
'' SIG '' rIE6c9m2pnZivfXgzaN2faouWo2tb86cBVkTdMy3S1Wn
'' SIG '' 21AfZBiyWbCmPm1zjqHU1MlMbzAr+0BpQt7y3PCJHfq3
'' SIG '' HMHwS7M9NDVCaoROUsDe+wZaD7jDm/q8pnfwgGPuhiDj
'' SIG '' YUY6hyg30FfnfwJo4z3bv1fbwC5BLbGhQaroQSxSaOo0
'' SIG '' SuC8ZfvUNmx7320CKaihggIoMIICJAYJKoZIhvcNAQkG
'' SIG '' MYICFTCCAhECAQEwgY4wdzELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUtU3RhbXAg
'' SIG '' UENBAhMzAAAATKHoTcy0dHs7AAAAAABMMAkGBSsOAwIa
'' SIG '' BQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
'' SIG '' CSqGSIb3DQEJBTEPFw0xNDAyMjQxNzM3NTlaMCMGCSqG
'' SIG '' SIb3DQEJBDEWBBTID+3R1UYIAYPUFO391Acs1XlPVjAN
'' SIG '' BgkqhkiG9w0BAQUFAASCAQBaQLBAs866PYnMxOnVu5vT
'' SIG '' C3hmCrV1Ldo7ZNyVfz7n0UErnXdYm34gD0OHgeEJPFRo
'' SIG '' Ec8JbnmHkA3S5pipu90kfBFASwDEyWQ5MxFSPIu80xUJ
'' SIG '' dOdKz7YQIYwsyK9+97x4OEBoBDzjbRi/7wHSjau3+/+1
'' SIG '' r+hXzXTZu5P6QA3Eq8gut0VU7GskF9y3PcNOhAObEHmt
'' SIG '' hvuree9t49xc2Ut75CS9KYqB3DQUeb06HGXZZghW9SHi
'' SIG '' eDXU0ClZxHHjtxIaiIXFKw09P4Au8FSNYhH1tG7Q2Ox9
'' SIG '' 1RUcFUaicDjLkpnKsgZ3JETjz9Q9y796VpivzlxSx9vs
'' SIG '' AJpm5TpLo4+c
'' SIG '' End signature block

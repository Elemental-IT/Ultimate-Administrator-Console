<#

Ultimate Administrator Console

.SYNOPSIS
The ultimate resource for system administration

.DESCRIPTION
This is a generalised tool created mostly in PowerShell to provide extended functionality too Active Directory exchange and other services and systems

.NOTES
Exchange an Active Directory tabs will save XML data “$env:PUBLIC\Ultimate Administrator Console” This is to recall data quickly as pulling this information can take a minute or so.

please see YouTube channel under about for full tutorial https://www.youtube.com/channel/UC8fXbspZUdX4MUFlBIueuNw

Author Theo bird (Bedlem55)
  
#>

# Create Dir for Ultimate Administrator Console and Import settings 
$Settings = $null
IF (-not(test-path "$env:PUBLIC\Ultimate Administrator Console")) { New-Item "$env:PUBLIC\Ultimate Administrator Console" -ItemType Directory -ErrorAction SilentlyContinue -Force | Out-Null }

$Admin_Tools = Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools" -Recurse | Sort-Object

# Assembly and Modules
#===========================================================
Add-Type -AssemblyName system.windows.forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# taken from https://social.technet.microsoft.com/Forums/scriptcenter/en-US/16444c7a-ad61-44a7-8c6f-b8d619381a27/using-icons-in-powershell-scripts?forum=winserverpowershell

$code = @"
using System;
using System.Drawing;
using System.Runtime.InteropServices;
namespace System
{
    public class IconExtractor
    {
        public static Icon Extract(string file, int number, bool largeIcon)
        {
        IntPtr large;
        IntPtr small;
        ExtractIconEx(file, number, out large, out small, 1);
        try
        {
        return Icon.FromHandle(largeIcon ? large : small);
        }
        catch
        {
        return null;
    }
}
[DllImport("Shell32.dll", EntryPoint = "ExtractIconExW", CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
private static extern int ExtractIconEx(string sFile, int iIndex, out IntPtr piLargeVersion, out IntPtr piSmallVersion, int amountIcons);
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies System.Drawing


# Variables
#===========================================================

$Exchangeserver = IF (test-path "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml") { Import-Clixml "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml" }

# Icons
$Icon_OK = [System.IconExtractor]::Extract("Shell32.dll", 302, $true)

# About & Messages
$About =  @"

    Author:      Theo Bird (Bedlem55)
    Github:      https://github.com/Bedlem55/Ultimate-Administrator-Console
    YouTube:     https://www.youtube.com/channel/UC8fXbspZUdX4MUFlBIueuNw
    linkedin:    https://www.linkedin.com/in/theo-bird-84740538/

"@

$RSAT_info = @"
   
   Install all RSAT Windows Optional Features? 

   Note - this will take some time to install.

"@

# AD 
$AD_Forest       = $null
$AD_Domain      = $null
$AD_Users       = $null
$AD_Computers   = $null
$AD_Groups      = $null
$AD_OUs         = $null

# Exchange
$Exchange_Users                  = $null
$Exchange_Mailboxes              = $null
$Exchange_DistributionGroups     = $null
$script:Exchange_Contacts        = $null

# AzureAD

$AzureAD_Users = $null

 
#=========================================================================#
#                           Base Functions                                # 
#=========================================================================#

# Set ForeColor
Function Set-ForeColor {

    $Red = $TrackBar_TextColourRed.Value
    $Green = $TrackBar_TextColourGreen.Value
    $Blue = $TrackBar_TextColourBlue.Value
  

    $ListBox_windows.ForeColor                    = "$Red,$Green,$Blue" 
    $ListBox_WindowServer.ForeColor               = "$Red,$Green,$Blue"
    $ListBox_ControlPanel.ForeColor               = "$Red,$Green,$Blue"
    $TextBox_Output.ForeColor                     = "$Red,$Green,$Blue"
    $ComboBox_Users.ForeColor                     = "$Red,$Green,$Blue"
    $ListBox_Users.ForeColor                      = "$Red,$Green,$Blue"
    $ListBox_Computers.ForeColor                  = "$Red,$Green,$Blue"
    $ComboBox_Computers.ForeColor                 = "$Red,$Green,$Blue"
    $ListBox_Computers.ForeColor                  = "$Red,$Green,$Blue"
    $ComboBox_Groups.ForeColor                    = "$Red,$Green,$Blue"
    $ListBox_Groups.ForeColor                     = "$Red,$Green,$Blue"
    $ComboBox_Mailbox.ForeColor                   = "$Red,$Green,$Blue"
    $ListBox_Mailbox.ForeColor                    = "$Red,$Green,$Blue"
    $ComboBox_Distributionlist.ForeColor          = "$Red,$Green,$Blue"
    $ListBox_Distributionlist.ForeColor           = "$Red,$Green,$Blue"
    $StatusBarLabel.ForeColor                     = "$Red,$Green,$Blue"

}

# Set BackColor
Function Set-BackColor {

    $Red = $TrackBar_BackColourRed.Value
    $Green = $TrackBar_BackColourGreen.Value
    $Blue = $TrackBar_BackColourBlue.Value

    $ListBox_windows.BackColor                    = "$Red,$Green,$Blue" 
    $ListBox_WindowServer.BackColor               = "$Red,$Green,$Blue" 
    $ListBox_ControlPanel.BackColor               = "$Red,$Green,$Blue" 
    $TextBox_Output.BackColor                     = "$Red,$Green,$Blue" 
    $ComboBox_Users.BackColor                     = "$Red,$Green,$Blue" 
    $ListBox_Users.BackColor                      = "$Red,$Green,$Blue" 
    $ComboBox_Computers.BackColor                 = "$Red,$Green,$Blue" 
    $ListBox_Computers.BackColor                  = "$Red,$Green,$Blue" 
    $ComboBox_Groups.BackColor                    = "$Red,$Green,$Blue" 
    $ListBox_Groups.BackColor                     = "$Red,$Green,$Blue" 
    $ComboBox_Mailbox.BackColor                   = "$Red,$Green,$Blue" 
    $ListBox_Mailbox.BackColor                    = "$Red,$Green,$Blue" 
    $ComboBox_Distributionlist.BackColor          = "$Red,$Green,$Blue" 
    $ListBox_Distributionlist.BackColor           = "$Red,$Green,$Blue" 
    $StatusBar.BackColor                          = "$Red,$Green,$Blue" 
    
}

Function Set-Opacity {

    $Form.Opacity = "0." + $TrackBar_Opacity.Value
}

Function Save-settings {

   TRY {
        
        New-Object PSObject -Property @{

        ### Forecolor

    TextColourRed     = $TrackBar_TextColourRed.Value 
    TextColourGreen   = $TrackBar_TextColourGreen.Value  
    TextColourBlue    = $TrackBar_TextColourBlue.Value   

        ### Backcolor

    BackColourRed     = $TrackBar_BackColourRed.Value
    BackColourGreen   = $TrackBar_BackColourGreen.Value   
    BackColourBlue    = $TrackBar_BackColourBlue.Value    
        
        } | Export-Clixml "$env:PUBLIC\Ultimate Administrator Console\Settings.xml"
    } CATCH { Write-OutError }
}

# Clear output 
Function Clear-Output {
  
    $Red = $TrackBar_TextColourRed.Value
    $Green = $TrackBar_TextColourGreen.Value
    $Blue = $TrackBar_TextColourBlue.Value
  
    $TextBox_Output.ForeColor = "$Red,$Green,$Blue"
    $TextBox_Output.Clear()
}

# Error
Function Write-OutError {
    Clear-Output
    $TextBox_Output.ForeColor = [Drawing.Color]::Red
    $Err = $Error[0]
    $TextBox_Output.AppendText("Error: $Err")
}

# Error
Function Write-OutErrorFull {
    Clear-Output
    $TextBox_Output.ForeColor = [Drawing.Color]::Red
    $TextBox_Output.AppendText($Error)
}

Function Write-OutInfo {
    $TextBox_Output.ForeColor = [Drawing.Color]::Yellow
}

Function Write-Cancelled {
    Clear-Output
    Set-StatusBarReady
    $TextBox_Output.ForeColor = [Drawing.Color]::Yellow
    $TextBox_Output.AppendText("Operation Cancelled")
}

# About
Function Show-About {
   Clear-Output
   $TextBox_Output.AppendText($About)    
} 

# Set system Brightness less 
Function Set-Brightness_Less {
    $CurrentBrightness = (Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightness).CurrentBrightness -10
    IF ($CurrentBrightness -le 10){$CurrentBrightness = 0}
    (Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods -ErrorAction SilentlyContinue).WmiSetBrightness(1,$CurrentBrightness)
} 
 
# Set system Brightness more
Function Set-Brightness_More {
    $CurrentBrightness = (Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightness).CurrentBrightness +10
    (Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods).WmiSetBrightness(1,$CurrentBrightness)
} 

# Copys outbox text 
Function Copy-Outbox {
    $TextBox_Output.SelectAll()
    $TextBox_Output.Copy()
} 

# Cuts outbox text 
Function Cut_Outbox {
    $TextBox_Output.SelectAll()
    $TextBox_Output.Cut()
} 

# Copy outbox text to notepad
Function Copy-Notepad { 
    $filename = [System.IO.Path]::GetTempFileName() 
    Add-Content -Value $TextBox_Output.text -Path $filename
    notepad $filename
}

# Runs Commands typed into the TextBox_Output
Function Start-OutPutCommand {
    $Command = $TextBox_Output.text
        TRY {
        Clear-Output
        $TextBox_Output.Text = Invoke-Expression $Command -ErrorAction Stop | Out-String
    } CATCH { Write-OutError } 
}

Function Set-StatusBarReady {
    $StatusBarLabel.text = "  Ready"
}

Function Restart-PC{
    
    TRY {
    $UserPrompt = new-object -comobject wscript.shell
    $Answer = $UserPrompt.popup("   Restart PC?", 0, "  Restart PC", 0x4 + 0x30)
        IF ($Answer -eq 6) {
            Restart-Computer -Force
        } ELSE { Write-Cancelled }
    } CATCH { Write-OutError }
}

Function Stop_PC {

    TRY {
    $UserPrompt = new-object -comobject wscript.shell
    $Answer = $UserPrompt.popup("   Shutdown PC?", 0, "   Shutdown PC", 0x4 + 0x30)
        IF ($Answer -eq 6) {
            Stop-Computer -Force
        } ELSE { Write-Cancelled }
    } CATCH { Write-OutError }

}


#=========================================================================#
#                          Windows Functions                              # 
#=========================================================================#

#================= Windows Tools Functions =================

# Start windows App
Function Start-WindowsApp {

    IF ($ListBox_windows.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    ELSE { 
      TRY { 
        SWITCH ($ListBox_windows.SelectedItem) {

            'Backup Credentials'                    { Start-Process credwiz.exe -ErrorAction Stop    }
            'Clean Disk Manager'                    { cleanmgr.exe }
            'DirectX Diagnostic Tool'               { Start-Process dxdiag.exe -ErrorAction Stop }
            'Disk Manager'                          { Start-Process diskmgmt.msc -ErrorAction Stop }
            'Device Management'                     { Start-Process devmgmt.msc -ErrorAction Stop }
            'Default Apps'                          { Start-Process ComputerDefaults.exe -ErrorAction Stop }
            'Enable Ultimate Performance'           { Enable-Ultimate_Performance }
            'Event Viewer'                          { Start-Process eventvwr.msc -ErrorAction Stop }
            'Firewall'                              { Start-Process firewall.cpl -ErrorAction Stop }
            'Internet Properties'                   { Start-Process inetcpl.cpl -ErrorAction Stop }
            'Invoke Group policy update'            { Start-Gpupdate }
            'Network Properties'                    { Start-Process control -ArgumentList netconnections -ErrorAction Stop}
            'Optional Features'                     { Start-Process OptionalFeatures.exe -ErrorAction Stop }
            'RegisTRY Editor'                       { Start-Process regedit -ErrorAction Stop }
            'Reliability Monitor'                   { Start-Process perfmon /rel -ErrorAction Stop}
            'Remote Desktop'                        { Start-Process mstsc.exe -ErrorAction Stop}
            'Services'                              { Start-Process services.msc -ErrorAction Stop }
            'Start Windows Defender Offline Scan'   { Start-WindowsDefenderOfflineScan } 
            'System Information'                    { Start-Process msinfo32.exe -ErrorAction Stop } 
            'System Configuration Utility'          { Start-Process msconfig.exe -ErrorAction Stop }
            'System Properties'                     { Start-Process sysdm.cpl -ErrorAction Stop }
            'Task Scheduler'                        { Start-Process taskschd.msc -ErrorAction Stop }
            'Task Manager'                          { Start-Process taskmgr.exe -ErrorAction Stop }
            'Windows Version'                       { Start-Process winver.exe -ErrorAction Stop }
            'Windows Update'                        { Start-Process control -ArgumentList update -ErrorAction Stop }

            } 
        } CATCH { Write-OutError }
    }
}

# Start Server app
Function start_windowAdminapp {

    IF ($ListBox_WindowServer.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    ELSE { 
        TRY { 
            
            $Tool = $ListBox_WindowServer.SelectedItem
            $Path = (Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools" | Where-Object{$_.BaseName -like $Tool}).FullName 
            Invoke-Item -Path $Path -ErrorAction SilentlyContinue

        } CATCH { Write-OutError }
    }
}

# Starts selected control panel item 
Function Start-ControlPanelItem {
    IF ($ListBox_ControlPanel.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No control panel item selected") } 
    ELSE {  
        TRY{
            Show-ControlPanelItem -Name $ListBox_ControlPanel.SelectedItem -ErrorAction Stop
        } CATCH { Write-OutError }
    }
} 

# Installs all are missing available off Rstat tools 
Function Add-AllRsatTools {
    $UserPrompt = new-object -comobject wscript.shell
    $Answer = $UserPrompt.popup($RSAT_info, 0, "  Install RSAT", 0x4 + 0x30)
    IF ($Answer -eq 6) {
        TRY {
        $StatusBarLabel.text = "  Installing RSAT"
        Start-Sleep 0.5
    
        # Get list of all Rsat
        $RSAT = (Get-WindowsCapability -Online | Where-Object {($_.Name -like "*RSAT*") -and ($_.State -eq "NotPresent")}).name
    
            IF ($RSAT -eq $null) {
        
                Write-OutInfo
                $TextBox_Output.Text = "RSAT Features are already Intalled" 
                Set-StatusBarReady

            } ELSE {
    
                # Open optionalfeatures - to show install progress 
                Start-Process "ms-settings:optionalfeatures"
        
                # Install all Rsat items
                FOREACH($Object in $RSAT) {Add-WindowsCapability -name $Object -Online} 
                
                # Add Items to listbox
                $Admin_Tools = Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools" -Recurse | Sort-Object
                FOREACH($Tool in $Admin_Tools.BaseName){[void]$ListBox_WindowServer.Items.Add($Tool)}
                Set-StatusBarReady
                
                }

            } CATCH {
                Set-StatusBarReady
                Write-OutError
            }
               
        } ELSE { Write-Cancelled }
}


# Outputs gets-computerinfo to output 
Function Get-ComputerInfo_Output {
    Clear-Output
    $TextBox_Output.Text = Invoke-Expression "Get-computerinfo" -ErrorAction Stop | Out-String    
}

# Outputs detailed summary of system information 
Function Get-SystemInfo_Output {
    Clear-Output
    $TextBox_Output.Text = Invoke-Expression "SystemInfo" -ErrorAction Stop | Out-String    
}

# Outputs IP configuration 
Function Get-IpconfigInfo_Output {
    Clear-Output
    $TextBox_Output.Text = Invoke-Expression "Ipconfig /all" -ErrorAction Stop | Out-String    
}

# Start an offline Windows Defender scan 
Function Start-WindowsDefenderOfflineScan { 
    
    TRY {
        $UserPrompt = new-object -comobject wscript.shell
        $Answer = $UserPrompt.popup("Start offline Windows Defender scan? `n`n Note: this will restart your PC", 0, "Start Scan", 0x4 + 0x30)
            IF ($Answer -eq 6) {
                Clear-Output
                Start-MpWDOScan -ErrorAction Stop | Out-Null
                $TextBox_Output.AppendText("Starting Scan")
            
            } ELSE {Write-Cancelled }
        } CATCH { Write-OutError }
}

# Start GP update with a restart 
Function Start-Gpupdate {

    TRY {
        $UserPrompt = new-object -comobject wscript.shell
        $Answer = $UserPrompt.popup("Invoke Gpupdate? `n`n Note: this will restart your PC", 0, "Invoke Gpupdate", 0x4 + 0x30)
            IF ($Answer -eq 6) {
                Start-Process gpupdate -ArgumentList "/force /boot" -ErrorAction Stop  -Wait | Out-Null
            } ELSE { Write-Cancelled }
        } CATCH { Write-OutError }
}

# Creates GodMode folder and opens folder 
# See for info: https://www.howtogeek.com/402458/enable-god-mode-in-windows-10/
Function Godmode {
    $path = "$env:PUBLIC\Ultimate Administrator Console.{ED7BA470-8E54-465E-825C-99712043E01C}"
    IF ((Test-path $path) -ne $true) { New-item -Path $path -ItemType Directory }
    Invoke-Item $path 
} 

 # Restart selected service from list 
Function Restart-LocalService {
    
    TRY {
        Clear-Output
        $Service =  (Get-Service | Out-GridView -PassThru -Title "Select Service to start").name 
        IF($Service.Length -eq '0')  { Write-OutInfo ; $TextBox_Output.text = "No Service Selected"}
        ELSE {Restart-Service -Name $Service -Force -ErrorAction Stop ; $TextBox_Output.text = "Starting $Service service" }
    
    } CATCH { Write-OutError }
} 

# Stops local service from selected list 
Function Stop-LocalService {
   
    TRY {
        Clear-Output
        $Service =  (Get-Service | Out-GridView -PassThru -Title "Select Service to stop").name 
        IF($Service.Length -eq '0')  { Write-OutInfo ; $TextBox_Output.text = "No Service Selected"}
        ELSE { Stop-Service -Name $Service -Force -ErrorAction Stop  ; $TextBox_Output.text = "Stopping $Service service" }
    
    } CATCH { Write-OutError }
} 

# Kills local selected process 
Function Stop-LocalProcess {
   
    TRY {
        Clear-Output
        $Process =  (Get-Process | Out-GridView -PassThru -Title "Select Process to stop").name 
        IF($Process.Length -eq '0')  { Write-OutInfo ; $TextBox_Output.text = "No Process Selected"}
        ELSE { Stop-Process -Name $Process -Force -ErrorAction Stop ; $TextBox_Output.text = "Stopping $Process service" }
    
    } CATCH { Write-OutError }
} 

# Start ping to specified target 
Function Start-Ping {
     IF ( $Textbox_Nettools.Text -eq '' ) {
        Clear-Output
        Write-OutInfo
        $TextBox_Output.AppendText("No IP/URI provided")}
     ELSE {
        $IP_URI = $Textbox_Nettools.Text.ToString()
        $TextBox_Output.text = Invoke-Expression "Ping $IP_URI" -ErrorAction Stop | Out-String
    }
}

# Runs traceroute to specified 
Function Start-TraceRoute {
    IF ( $Textbox_Nettools.Text -eq '' ) {
        Clear-Output
        Write-OutInfo
        $TextBox_Output.AppendText("No IP/URI provided")}
    ELSE {
        $IP_URI = $Textbox_Nettools.Text.ToString()
        $Path = "$env:PUBLIC\TraceRoute$IP_URI.txt"
        Start-Process Powershell -ArgumentList "Start-Transcript -Path $Path ; Test-NetConnection -TraceRoute $IP_URI ; Stop-Transcript ; Invoke-item $path" -Wait
    }
}

# Does an NS look up to specified 
Function Get-nslookup {
    IF ( $Textbox_Nettools.Text -eq '' ) {
        Clear-Output
        Write-OutInfo
        $TextBox_Output.AppendText("No IP/URI provided")}
    ELSE {
        TRY {
        $IP_URI = $Textbox_Nettools.Text.ToString()
        $TextBox_Output.text = Invoke-Expression "Resolve-DnsName $IP_URI -ErrorAction Stop" | Out-String
        } CATCH { Write-OutError }
    }
}

# Reset all local network settings 
Function Reset-Networksettings {
    TRY {
        $UserPrompt = new-object -comobject wscript.shell
        $Answer = $UserPrompt.popup("Reset all network settings? `n`n Note: this will restart your PC", 0, "Reset Network", 0x4 + 0x30)
        IF ($Answer -eq 6) {
            Clear-Output
            Start-Process "netsh" -ArgumentList "winsock reset" -ErrorAction Stop -Wait 
            Restart-Computer -Force
        } ELSE { Write-Cancelled }
    } CATCH { Write-OutError } 
}

# Start get folder ACL application 
# This will allow you to export a CSV with all the existing permissions at a folder level 
# Note This will only read folders that have account has permissions to
Function Start-GetFolderACL {
#======================= Assemblys =========================
Add-Type -AssemblyName system.windows.forms

#======================== Functions ========================
Function FolderImport {
    $TextBox_GetFolder.Clear()
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $FolderBrowser.RootFolder = "MyComputer"
    $FolderBrowser.ShowDialog()
    $TextBox_GetFolder.AppendText($FolderBrowser.SelectedPath.tostring())
}


Function Run {

    IF ( $GetFolderTB.Text -eq '' ) {

    [System.Windows.Forms.MessageBox]::Show("No folder selected", "Warning:",0,48) 
    
    } ELSE {

        $Path = $TextBox_GetFolder.text.tostring()
        IF(Test-Path $Path) {

        $SaveFile = New-Object -TypeName System.Windows.Forms.SaveFileDialog
        $SaveFile.Title = "Export ACL Permissions"
        $SaveFile.FileName = "Folder Permissions Export"
        $SaveFile.Filter = "CSV Files (*.csv)|*.csv"
        $SaveFile.ShowDialog()

        Get-ChildItem -Path $Path -Recurse | Where-Object{$_.psiscontainer}|
        Get-Acl | FOREACH {
        $path = $_.Path
        $_.Access | FOREACH-Object {
            New-Object PSObject -Property @{
                Folder = $path.Replace("Microsoft.PowerShell.Core\FileSystem::","")
                Access = $_.FileSystemRights
                Control = $_.AccessControlType
                User = $_.IdentityReference
                Inheritance = $_.IsInherited
                    }
                }
            } | select-object -Property Folder,User,Access,Control,Inheritance | export-csv $SaveFile.FileName.tostring() -NoTypeInformation -force
        } ELSE { [System.Windows.Forms.MessageBox]::Show("No folder selected", "Warning:",0,48) }
    }
}


## From
#===========================================================

$Form_GetACL = New-Object system.Windows.Forms.Form -Property @{
    ClientSize            = '460,60'
    text                  = "  ACL Folder Info"
    TopMost               = $false
    ShowIcon              = $false
    FormBorderStyle       = 1
    MaximizeBox           = $false
}

$Button_Run = New-Object System.Windows.Forms.Button -Property @{
    Location              = "400, 10"
    Size                  = "50,40"
    Text                  = "Export"
}

$Button_Run.add_Click({ Run })


## Get Folder GroupBox
#===========================================================

$GroupBox_GetFolder = New-Object System.Windows.Forms.GroupBox -Property @{
    Location              = "10, 5"
    Size                  = "380,45"
    Text                  = "Select Folder"
}

$TextBox_GetFolder = New-Object System.Windows.Forms.TextBox -Property @{
    Location              = "10, 15"
    Size                  = "330,30"
}

$Button_GetFolder =  New-Object System.Windows.Forms.Button -Property @{
    Location              = "345, 14"
    Size                  = "25, 22"
    Text                  = "..."
}

$Button_GetFolder.add_Click({ FolderImport })

$GroupBox_GetFolder.controls.AddRange(@(
    $TextBox_GetFolder
    $Button_GetFolder
))

# Controls
#===========================================================

$Form_GetACL.controls.AddRange(@(
    $GroupBox_GetFolder
    $Button_Run
))

[void]$Form_GetACL.ShowDialog()
}

# This application leverages the voice synthesiser component of windows 
# This will allow you to playback and save text to wave file format 
Function Start-TexttoWave {  

<#
.SYNOPSIS
  text to wave 
.DESCRIPTION
  Save text to Wave format  
.NOTES
  Author Theo bird
#>

# Assembly
#==========================================

Add-Type -AssemblyName System.speech
$Speak = New-Object System.Speech.Synthesis.SpeechSynthesizer

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# Variables
#===========================================================

$Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

$About = @'
  Text to Wave
   
  Version: 1.0
  Github: https://github.com/Bedlem55/PowerShell
  Author: Theo bird (Bedlem55)
    
'@

$Eva = @'
Windows RegisTRY Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech_OneCore\Voices\Tokens\MSTTS_V110_enUS_EvaM]
@="Microsoft Eva Mobile - English (United States)"
"LangDataPath"="%windir%\\Speech_OneCore\\Engines\\TTS\\en-US\\MSTTSLocenUS.dat"
"LangUpdateDataDirectory"="%SystemDrive%\\Data\\SharedData\\Speech_OneCore\\Engines\\TTS\\en-US"
"VoicePath"="%windir%\\Speech_OneCore\\Engines\\TTS\\en-US\\M1033Eva"
"VoiceUpdateDataDirectory"="%SystemDrive%\\Data\\SharedData\\Speech_OneCore\\Engines\\TTS\\en-US"
"409"="Microsoft Eva Mobile - English (United States)"
"CLSID"="{179F3D56-1B0B-42B2-A962-59B7EF59FE1B}"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech_OneCore\Voices\Tokens\MSTTS_V110_enUS_EvaM\Attributes]
"Version"="11.0"
"Language"="409"
"Gender"="Female"
"Age"="Adult"
"DataVersion"="11.0.2013.1022"
"SharedPronunciation"=""
"Name"="Microsoft Eva Mobile"
"Vendor"="Microsoft"
"PersonalAssistant"="1"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices\Tokens\MSTTS_V110_enUS_EvaM]
@="Microsoft Eva Mobile - English (United States)"
"LangDataPath"="%windir%\\Speech_OneCore\\Engines\\TTS\\en-US\\MSTTSLocenUS.dat"
"LangUpdateDataDirectory"="%SystemDrive%\\Data\\SharedData\\Speech_OneCore\\Engines\\TTS\\en-US"
"VoicePath"="%windir%\\Speech_OneCore\\Engines\\TTS\\en-US\\M1033Eva"
"VoiceUpdateDataDirectory"="%SystemDrive%\\Data\\SharedData\\Speech_OneCore\\Engines\\TTS\\en-US"
"409"="Microsoft Eva Mobile - English (United States)"
"CLSID"="{179F3D56-1B0B-42B2-A962-59B7EF59FE1B}"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices\Tokens\MSTTS_V110_enUS_EvaM\Attributes]
"Version"="11.0"
"Language"="409"
"Gender"="Female"
"Age"="Adult"
"DataVersion"="11.0.2013.1022"
"SharedPronunciation"=""
"Name"="Microsoft Eva Mobile"
"Vendor"="Microsoft"
"PersonalAssistant"="1"

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\SPEECH\Voices\Tokens\MSTTS_V110_enUS_EvaM]
@="Microsoft Eva Mobile - English (United States)"
"LangDataPath"="%windir%\\Speech_OneCore\\Engines\\TTS\\en-US\\MSTTSLocenUS.dat"
"LangUpdateDataDirectory"="%SystemDrive%\\Data\\SharedData\\Speech_OneCore\\Engines\\TTS\\en-US"
"VoicePath"="%windir%\\Speech_OneCore\\Engines\\TTS\\en-US\\M1033Eva"
"VoiceUpdateDataDirectory"="%SystemDrive%\\Data\\SharedData\\Speech_OneCore\\Engines\\TTS\\en-US"
"409"="Microsoft Eva Mobile - English (United States)"
"CLSID"="{179F3D56-1B0B-42B2-A962-59B7EF59FE1B}"

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\SPEECH\Voices\Tokens\MSTTS_V110_enUS_EvaM\Attributes]
"Version"="11.0"
"Language"="409"
"Gender"="Female"
"Age"="Adult"
"DataVersion"="11.0.2013.1022"
"SharedPronunciation"=""
"Name"="Microsoft Eva Mobile"
"Vendor"="Microsoft"
"PersonalAssistant"="1"
'@

$Mark = @'
Windows RegisTRY Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices\Tokens\MSTTS_V110_enUS_MarkM]
@="Microsoft Mark - English (United States)"
"409"="Microsoft Mark - English (United States)"
"CLSID"="{179F3D56-1B0B-42B2-A962-59B7EF59FE1B}"
"LangDataPath"=hex(2):25,00,77,00,69,00,6e,00,64,00,69,00,72,00,25,00,5c,00,53,\
  00,70,00,65,00,65,00,63,00,68,00,5f,00,4f,00,6e,00,65,00,43,00,6f,00,72,00,\
  65,00,5c,00,45,00,6e,00,67,00,69,00,6e,00,65,00,73,00,5c,00,54,00,54,00,53,\
  00,5c,00,65,00,6e,00,2d,00,55,00,53,00,5c,00,4d,00,53,00,54,00,54,00,53,00,\
  4c,00,6f,00,63,00,65,00,6e,00,55,00,53,00,2e,00,64,00,61,00,74,00,00,00
"VoicePath"=hex(2):25,00,77,00,69,00,6e,00,64,00,69,00,72,00,25,00,5c,00,53,00,\
  70,00,65,00,65,00,63,00,68,00,5f,00,4f,00,6e,00,65,00,43,00,6f,00,72,00,65,\
  00,5c,00,45,00,6e,00,67,00,69,00,6e,00,65,00,73,00,5c,00,54,00,54,00,53,00,\
  5c,00,65,00,6e,00,2d,00,55,00,53,00,5c,00,4d,00,31,00,30,00,33,00,33,00,4d,\
  00,61,00,72,00,6b,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices\Tokens\MSTTS_V110_enUS_MarkM\Attributes]
"Age"="Adult"
"DataVersion"="11.0.2013.1022"
"Gender"="Male"
"Language"="409"
"Name"="Microsoft Mark"
"SharedPronunciation"=""
"Vendor"="Microsoft"
"Version"="11.0"

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\SPEECH\Voices\Tokens\MSTTS_V110_enUS_MarkM]
@="Microsoft Mark - English (United States)"
"409"="Microsoft Mark - English (United States)"
"CLSID"="{179F3D56-1B0B-42B2-A962-59B7EF59FE1B}"
"LangDataPath"=hex(2):25,00,77,00,69,00,6e,00,64,00,69,00,72,00,25,00,5c,00,53,\
  00,70,00,65,00,65,00,63,00,68,00,5f,00,4f,00,6e,00,65,00,43,00,6f,00,72,00,\
  65,00,5c,00,45,00,6e,00,67,00,69,00,6e,00,65,00,73,00,5c,00,54,00,54,00,53,\
  00,5c,00,65,00,6e,00,2d,00,55,00,53,00,5c,00,4d,00,53,00,54,00,54,00,53,00,\
  4c,00,6f,00,63,00,65,00,6e,00,55,00,53,00,2e,00,64,00,61,00,74,00,00,00
"VoicePath"=hex(2):25,00,77,00,69,00,6e,00,64,00,69,00,72,00,25,00,5c,00,53,00,\
  70,00,65,00,65,00,63,00,68,00,5f,00,4f,00,6e,00,65,00,43,00,6f,00,72,00,65,\
  00,5c,00,45,00,6e,00,67,00,69,00,6e,00,65,00,73,00,5c,00,54,00,54,00,53,00,\
  5c,00,65,00,6e,00,2d,00,55,00,53,00,5c,00,4d,00,31,00,30,00,33,00,33,00,4d,\
  00,61,00,72,00,6b,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\SPEECH\Voices\Tokens\MSTTS_V110_enUS_MarkM\Attributes]
"Age"="Adult"
"DataVersion"="11.0.2013.1022"
"Gender"="Male"
"Language"="409"
"Name"="Microsoft Mark"
"SharedPronunciation"=""
"Vendor"="Microsoft"
"Version"="11.0"
'@

$Message = @'
Enable Eva and Mark system voices? 

Warning: this will modIFy the system regisTRY.
'@

$OS = @'
OS does not meet requirements:

Windows 10 or Server 2016 and higher is required.
'@

$AdminMeg = @'
Requires elevation to enable. 

Run text to wave as administrator 
'@

$Restart = @'
Restart required, restart computer now?
'@

# Base Form
#==========================================

Function PlaySound {

  IF ($null -eq $SelectVoiceCB.SelectedItem) {
    [System.Windows.Forms.MessageBox]::Show("No voice selected", "Warning:",0,48) 
  }
  ELSE {
    $Speak.SetOutputToDefaultAudioDevice() ; 
    $Speak.Rate = ($speed.Value)
    $Speak.Volume = $Volume.Value 
    $Speak.SelectVoice($SelectVoiceCB.Text) 
    $Speak.Speak($SpeakTextBox.Text)
  } 
}

Function SaveSound {
  IF ($null -eq $SelectVoiceCB.SelectedItem) {
    [System.Windows.Forms.MessageBox]::Show("No voice selected", "Warning:",0,48) 
  }
  ELSE {
    $SaveChooser = New-Object -TypeName System.Windows.Forms.SaveFileDialog
    $SaveChooser.Title = "Save text to Wav file"
    $SaveChooser.FileName = "SpeechSynthesizer"
    $SaveChooser.Filter = 'Wave file (.wav) | *.wav'
    $Answer = $SaveChooser.ShowDialog(); $Answer

    IF ( $Answer -eq "OK" ) {
      $Speak.SetOutputToDefaultAudioDevice() ; 
      $Speak.Rate = ($speed.Value)
      $Speak.Volume = $Volume.Value 
      $Speak.SelectVoice($SelectVoiceCB.Text) 
      $Speak.SetOutputToWaveFile($SaveChooser.Filename)
      $Speak.Speak($SpeakTextBox.Text)
      $Speak.SetOutputToNull()
      $Speak.SpeakAsyncCancelAll()
    }
  }
}

Function EnableMarkandEva { 

  IF (-not(Get-WmiObject -Class win32_operatingsystem).version.remove(2) -eq 10 ) { 
    [System.Windows.Forms.MessageBox]::Show("$OS","Warning:",0,48) 
  }

  ELSE {
    IF ($Admin -eq $true) {

    $UserPrompt = new-object -comobject wscript.shell
    $Answer = $UserPrompt.popup($Message, 0, "Enable system Voices", 4)

      IF ($Answer -eq 6) {
        New-Item -Value $eva -Path $env:SystemDrive\Eva.reg
        New-Item -Value $Mark -Path $env:SystemDrive\Mark.reg
        Start-Process regedit.exe -ArgumentList  /s, $env:SystemDrive\Eva.reg -Wait  
        Start-Process regedit.exe -ArgumentList  /s, $env:SystemDrive\Mark.reg -Wait
        Remove-Item $env:SystemDrive\Mark.reg -Force
        Remove-Item $env:SystemDrive\Eva.reg  -Force

        $UserPrompt = new-object -comobject wscript.shell
        $Answer = $UserPrompt.popup($Restart, 0, "Restart prompt", 4)
          IF ($Answer -eq 6) { Restart-Computer -Force }

      } 
    }   ELSE { [System.Windows.Forms.MessageBox]::Show("$AdminMeg","Warning:",0,48) } 
  }
}

# Base Form
#==========================================

$Form = New-Object system.Windows.Forms.Form
$Form.ClientSize = '798,525'
$Form.MinimumSize = '815,570'
$Form.text = "Text to Wave"
$Form.ShowIcon = $false
$Form.TopMost = $false

# Menu
#==========================================

$Menu = New-Object System.Windows.Forms.MenuStrip

$MenuFile = New-Object System.Windows.Forms.ToolStripMenuItem
$MenuFile.Text = "&File"
[void]$Menu.Items.Add($MenuFile)

$MenuExit = New-Object System.Windows.Forms.ToolStripMenuItem
$MenuExit.Text = "&Exit"
$menuExit.Add_Click( { $Form.close() })
[void]$MenuFile.DropDownItems.Add($MenuExit)


$MenuVoices = New-Object System.Windows.Forms.ToolStripMenuItem
$MenuVoices.Text = "&Voice"
[void]$Menu.Items.Add($MenuVoices)

$InstallVoices = New-Object System.Windows.Forms.ToolStripMenuItem
$InstallVoices.Text = "&Enable MarkandEva"
$InstallVoices.Add_Click( { EnableMarkandEva })
[void]$MenuVoices.DropDownItems.Add($InstallVoices)

$MenuHelp = New-Object System.Windows.Forms.ToolStripMenuItem
$MenuHelp.Text = "&Help"
[void]$Menu.Items.Add($MenuHelp)

$MenuAbout = New-Object System.Windows.Forms.ToolStripMenuItem
$MenuAbout.Text = "&About"
$MenuAbout.Add_Click( { [System.Windows.Forms.MessageBox]::Show("$About", "About",0,64) })
[void]$MenuHelp.DropDownItems.Add($MenuAbout)

$SpeakButtion = New-Object system.Windows.Forms.Button
$SpeakButtion.location = "660, 401"
$SpeakButtion.Size = "127, 43"
$SpeakButtion.Anchor = "Bottom"
$SpeakButtion.text = "Play"
$SpeakButtion.Font = 'Microsoft Sans SerIF,10'
$SpeakButtion.add_Click( { PlaySound })

$SaveButtion = New-Object system.Windows.Forms.Button
$SaveButtion.location = "660, 456"
$SaveButtion.Size = "127, 55"
$SaveButtion.Anchor = "Bottom"
$SaveButtion.text = "Save"
$SaveButtion.Font = 'Microsoft Sans SerIF,10'
$SaveButtion.add_Click( { SaveSound })

# Text Group Box
#==========================================

$TextGB = New-Object system.Windows.Forms.Groupbox
$TextGB.Anchor = "Top, Bottom, Left, Right"
$TextGB.location = "10, 35"
$TextGB.Size = "775, 350"
$TextGB.text = "Enter or drag text here"

$SpeakTextBox = New-Object System.Windows.Forms.RichTextBox
$SpeakTextBox.location = "10, 15"
$SpeakTextBox.Size = "755, 325"
$SpeakTextBox.Anchor = "Top, Bottom, Left, Right"
$SpeakTextBox.Text = "Hello World"
$speakTextbox.AllowDrop = $true
$speakTextbox.EnableAutoDragDrop = $true
$SpeakTextBox.multiline = $true
$SpeakTextBox.AcceptsTab = $true
$SpeakTextBox.ScrollBars = "both"
$SpeakTextBox.Font = 'Microsoft Sans SerIF,10'
$SpeakTextBox.Cursor = "IBeam"
$TextGB.Controls.Add( $SpeakTextBox )

# Select Group Box
#==========================================

$SelectGB = New-Object system.Windows.Forms.Groupbox
$SelectGB.location = "11, 395"
$SelectGB.Size = "640, 50"
$SelectGB.Anchor = "Bottom"
$SelectGB.text = "Select Voice"

$SelectVoiceCB = New-Object system.Windows.Forms.ComboBox
$SelectVoiceCB.location = "11, 15"
$SelectVoiceCB.Size = "618,24"
$SelectVoiceCB.Text = $speak.Voice.Name
$SelectVoiceCB.DropDownStyle = 'DropDownList'

$SelectVoiceCB.Font = 'Microsoft Sans SerIF,10'
$Voices = ($speak.GetInstalledVoices() | FOREACH-Object { $_.voiceinfo }).Name
FOREACH ($Voice in $Voices) {
  [void]$SelectVoiceCB.Items.add($voice) 
}
$SelectGB.Controls.Add($SelectVoiceCB)

# Speed Group Box
#==========================================

$SpeedGB = New-Object system.Windows.Forms.Groupbox
$SpeedGB.location = "11, 450"
$SpeedGB.Size = "310,62"
$SpeedGB.Anchor = "Bottom"
$SpeedGB.text = "Speed"

$Speed = New-Object Windows.Forms.TrackBar
$Speed.Orientation = "Horizontal"
$Speed.location = "5,15"
$Speed.Size = "300,40"
$Speed.TickStyle = "TopLeft"
$Speed.SetRange(-10, 10)
$SpeedGB.Controls.Add( $Speed )

# Volume Group Box
#==========================================

$VolumeGB = New-Object system.Windows.Forms.Groupbox
$VolumeGB.location = "340, 450"
$VolumeGB.Size = "311,62"
$VolumeGB.Anchor = "Bottom"
$VolumeGB.text = "Volume"

$Volume = New-Object Windows.Forms.TrackBar
$Volume.Orientation = "Horizontal"
$Volume.location = "5,15"
$Volume.Size = "300,40"
$Volume.TickStyle = "TopLeft"
$Volume.TickFrequency = 10
$Volume.SetRange(10, 100)
$Volume.Value = 100
$VolumeGB.Controls.Add( $Volume )

# Controls
#==========================================

$Form.controls.AddRange(@( $Menu, $SpeechGB, $SpeakButtion, $SaveButtion, $SelectGB, $SpeedGB, $VolumeGB, $TextGB ))

[void]$form.ShowDialog()

}

# Get All wIFi passwords
# Credit to https://itfordummies.net/2018/11/05/get-known-wIFi-networks-passwords-powershell/
Function Get-WIFiPassword {

    Clear-Output

    netsh wlan show profile | Select-Object -Skip 3| Where-Object -FilterScript {($_ -like '*:*')} | FOREACH-Object -Process {
        $NetworkName = $_.Split(':')[-1].trim()
        $PasswordDetection = $(netsh wlan show profile name =$NetworkName key=clear) | Where-Object -FilterScript {($_ -like '*contenu de la clé*') -or ($_ -like '*key content*')}

       $WIFi = New-Object -TypeName PSObject -Property @{
            NetworkName = $NetworkName
            Password = IF($PasswordDetection){$PasswordDetection.Split(':')[-1].Trim()}ELSE{'Unknown'}
        } -ErrorAction SilentlyContinue | Select NetworkName, Password | Out-String
        $TextBox_Output.AppendText($WIFi)  
    }
}


Function Enable-Ultimate_Performance {

    Clear-Output
    powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
    powercfg /SETACTIVE d5e245dc-791c-4cee-8e19-e0d75e1ca319 | Out-Null
    Show-ControlPanelItem -Name "Power Options"
    $TextBox_Output.AppendText("Ultimate Performance power Plan set")

}

#=========================================================================#
#                    Active Directory Functions                           # 
#=========================================================================#

# This will import the XML saved the public folder If the XML file does not exist it will run the command below 
Function Import-ADxml {

 $AD_XML = Import-Clixml "$env:PUBLIC\Ultimate Administrator Console\AD.xml"
            
    $script:AD_Forest      = (Get-ADForest).Name
    $script:AD_Domain      = (Get-ADForest).UPNSuffixes
    $script:AD_Users       = $AD_XML.Users | Sort-Object
    $script:AD_Computers   = $AD_XML.Computers | Sort-Object
    $script:AD_Groups      = $AD_XML.Groups | Sort-Object
    $script:AD_OUs         = $AD_XML.OUs | Sort-Object
     
}

# If the application is run for the first time it will export all of the Active Directory data to an XML file 
Function Import-ADdata {

    $script:AD_Forest      = (Get-ADForest).Name
    $script:AD_Domain      = (Get-ADForest).UPNSuffixes
    $script:AD_Users       = (Get-ADUser -Filter * -Properties SamAccountName).SamAccountName | Sort-Object 
    $script:AD_Computers   = (Get-ADComputer -Filter * -Properties Name).Name | Sort-Object
    $script:AD_Groups      = (Get-ADGroup -Filter * -Properties SamAccountName).SamAccountName | Sort-Object
    $script:AD_OUs         = Get-ADOrganizationalUnit -Filter * -Properties * | Sort-Object | Select-Object CanonicalName,DistinguishedName  | Sort-Object

}

# Imports All AD objects 
Function Enable-ActiveDirectory {
    
    Clear-Output
    $Button_ActiveDirectory_StartButtion.Enabled = $false 
    $StatusBarLabel.text = "  Loading Active Directory Objects"
        
    #Import AD Module
    TRY { 
        Import-Module activedirectory -ErrorAction Stop -WarningAction SilentlyContinue 
                
        IF (test-path "$env:PUBLIC\Ultimate Administrator Console\AD.xml") {
            $LastWriteTime = (Get-ItemProperty "$env:PUBLIC\Ultimate Administrator Console\AD.xml").LastWriteTime
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("Load Active Directory data from local cache? `n`nCache was Last updated on $LastWriteTime", 0, " Load from cache", 0x4 + 0x20)
    
         SWITCH ($Answer) {

            6           { Import-ADxml }
            Default     { Import-ADdata }  
             
            }
                    
        } ELSE { Import-ADdata }     
        
        FOREACH ($User in $AD_Users) { [void]$ComboBox_Users.Items.Add($user) }
        $ComboBox_Users.AutoCompleteSource = "CustomSource" 
        $ComboBox_Users.AutoCompleteMode = "SuggestAppend"
        $AD_Users | FOREACH-Object { [void]$ComboBox_Users.AutoCompleteCustomSource.Add($_) }

        FOREACH ($CPU in $AD_Computers) { [void]$ComboBox_Computers.Items.Add($CPU) }
        $ComboBox_Computers.AutoCompleteSource = "CustomSource" 
        $ComboBox_Computers.AutoCompleteMode = "SuggestAppend"
        $AD_Computers | FOREACH-Object { [void]$ComboBox_Computers.AutoCompleteCustomSource.Add($_) }
        
        FOREACH ($Group in $AD_Groups) { [void]$ComboBox_Groups.Items.Add($Group) }
        $ComboBox_Groups.AutoCompleteSource = "CustomSource" 
        $ComboBox_Groups.AutoCompleteMode = "SuggestAppend"
        $AD_Groups | FOREACH-Object { [void]$ComboBox_Groups.AutoCompleteCustomSource.Add($_) }
            
        $Panel_ActiveDirectory.Enabled = $true
        $Menu_AD.Enabled = $true
       
        Save-ADdata
        Set-StatusBarReady
        $TextBox_Output.AppendText("*** Active Directory object have been loaded ***")    
        
        
    } CATCH {
    Write-OutError
    Set-StatusBarReady
    $Button_ActiveDirectory_StartButtion.Enabled = $true
    } 
}

# Save AD data to cache
Function Save-ADdata {
        
    TRY {
        
        New-Object PSObject -Property @{

            Users      = $AD_users
            Computers  = $AD_Computers
            Groups     = $AD_Groups
            OUs        = $AD_OUs  
        
        } | Export-Clixml "$env:PUBLIC\Ultimate Administrator Console\AD.xml"
    } CATCH { Write-OutError }
}

# starts selected action
Function Start-AD_UserFunction {

    IF ($ListBox_users.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    ELSE { 
      TRY { 
        SWITCH ($ListBox_users.SelectedItem) {

            "Account info"                           { Get-AD_UserFullInfo }
            "List all groups"                        { Get-AD_UserMembers }
            "Reset Password"                         { Set-AD_UserPasswordReset }
            "Unlock account"                         { Set-AD_UserUnlockAccount }
            "Disable/Enable Account"                 { Set-AD_UserDisableOrEnable }
            "Set password to never expire"           { Set-PasswordToNeverExpire }
            "Set password to cannot be change"       { Set-PasswordToCannotBeChanged }
            "Add to Group"                           { Add-AD_UserToGroup }
            "Copy all Groups from another Account"   { Copy-AD_UserMemberships }
            "Remove Groups"                          { Remove-AD_UserfromGroup }
            "Remove All Groups"                      { Remove-AD_UserfromAllGroups }
            "Move OU"                                { Move-AD_User }
            "Remove Account"                         { Remove-AD_User }

            } 
        } CATCH { Write-OutError }
    }
}

# starts selected action
Function Start-AD_ComputerFunction {

    IF ($ListBox_Computers.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    ELSE { 
      TRY { 
        SWITCH ($ListBox_computers.SelectedItem) {
        
        "Computer info"                                { Get-AD_ComputerFullInfo }
        "System info"                                  { Get-AD_systemInfo }
        "List all Groups"                              { Get-AD_ComputerMembers }
        "Ping"                                         { Start-AD_ComputerPing }
        "Remote Desktop"                               { Connect-AD_Computer }
        "Event Viewer"                                 { Start-AD_ComputerEventViewer }
        "Computer Management"                          { Start-AD_ComputerManagement }
        "Add to Group"                                 { Add-AD_ComputerToGroup }
        "Copy all Groups from another Account"         { Copy-AD_ComputerMembers }
        "Remove Group"                                 { Remove-AD_ComputerFromGroup }
        "Remove All Groups"                            { Remove-AD_ComputerFromAllGroups }
        "Move OU"                                      { Move-AD_Computer }
        "Remove Account"                               { Remove-AD_Computer }
        "Update Group policy"                          { Invoke-AD_ComputerPolicyUpdate }
        "Restart PC"                                   { Restart-AD_Computer } 

            } 
        } CATCH { Write-OutError }
    }
}

# starts selected action
Function Start-AD_GroupFunction {

    IF ($ListBox_Groups.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    ELSE { 
      TRY { 
        SWITCH ($ListBox_Groups.SelectedItem) {
        
        "Group info"               { GroupInfo }
        "List Members"             { GroupMembers }
        "Add User"                 { Add-UserMember }
        "Add Computer"             { Add-ComputerMember }
        "Add Group"                { Add-GroupMember }
        "Remove Members"           { Remove-Member }
        "Move OU"                  { Move-AD_Group} 
        "Remove Group"             { Remove-AD_Group }
 

            } 
        } CATCH { Write-OutError }
    }
}

# Set output message for Null SelectedItem
Function Set-Output_ADuserNull {
    Clear-Output
    Write-OutInfo
    $TextBox_Output.AppendText("No User Selected")
}

Function Set-Output_ADComputerNull {
    Clear-Output
    Write-OutInfo
    $TextBox_Output.AppendText("No Computer Selected")
}

Function Set-Output_ADGroupNull {
    Clear-Output
    Write-OutInfo
    $TextBox_Output.AppendText("No Group Selected")
}

#============== User Account Functions =====================

# Create new user tool
Function New-UserUI {  

$NewUserFrom = New-Object Windows.forms.form -Property @{
    Text = "  User creation tool"
    Size = "550, 310"
    TopMost = $false
    ShowIcon = $false
    ShowInTaskbar = $False
    MinimizeBox = $False
    MaximizeBox = $False
    FormBorderStyle = 3
}

$Label_FirstName = New-Object System.Windows.Forms.Label -Property @{
    Location = "15, 15"
    Width = 70
    Text = "First name:"
}

$TextBox_FirstName = New-Object System.Windows.Forms.TextBox -Property @{
    Location = "93, 11"
    Width = 430
}

$Label_LastName = New-Object System.Windows.Forms.Label -Property @{
    Location = "15, 45"
    Width = 70
    Text = "Last name:"
}

$TextBox_LastName = New-Object System.Windows.Forms.TextBox -Property @{
    Location = "93, 41"
    Width = 430
}

$GroupBox_UPN = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "15, 70"
    Size = "508, 45"
    Text = "User Name"
}

$TextBox_UPN = New-Object System.Windows.Forms.TextBox -Property @{
    Location = "8, 15"
    Width = 340
}

$ComboBox_UPN = New-Object System.Windows.Forms.ComboBox -Property @{
    Location = "350, 15"
    Width = 150
}

$GroupBox_OU = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "15, 120" 
    Size = "508, 45"
    Text = "Select OU"
}

$ComboBox_OU = New-Object System.Windows.Forms.ComboBox -Property @{
    Location = "8, 14"
    Width = 493
}

$GroupBox_CopyUser = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "15,170"
    Size = "508, 45"
    Text = "User account to copy ( not requered )"
}

$ComboBox_CopyUser = New-Object System.Windows.Forms.ComboBox -Property @{ 
    Location = "7, 14"
    DropDownStyle = "DropDown"
    Width = 493
}


$Button_NewUser_Cancel = New-Object System.Windows.Forms.Button -Property @{
    Location = "140, 225"
    Size = "128,35"
    Text = "Cancel"
    FlatStyle = "Flat"
}


$Button_NewUser_OK = New-Object System.Windows.Forms.Button -Property @{
    Location = "275, 225"
    Size = "128,35"
    Text = "Ok"
    FlatStyle = "Flat"
}

# Button Appearance
$Button_NewUser_Cancel.FlatAppearance.BorderSize = 0
$Button_NewUser_OK.FlatAppearance.BorderSize = 0

# Events
$Button_NewUser_Cancel.add_Click( { $NewUserFrom.Close(); $NewUserFrom.Dispose() })
$Button_NewUser_OK.add_Click( { New-AD_User })

# Populate ComboBoxes
FOREACH ($Domain in $AD_Domain) { [void]$ComboBox_UPN.Items.Add("@$Domain") }
[void]$ComboBox_UPN.Items.Add("@$AD_Forest") 

FOREACH ($User in $AD_Users) { [void]$ComboBox_CopyUser.Items.Add($User) }
$ComboBox_CopyUser.AutoCompleteSource = "CustomSource" 
$ComboBox_CopyUser.AutoCompleteMode = "SuggestAppend"
$AD_users | FOREACH-Object { [void]$ComboBox_CopyUser.AutoCompleteCustomSource.Add($_) }

FOREACH ($OU in $AD_OUs.CanonicalName) { [void]$ComboBox_OU.Items.Add($OU) }
$ComboBox_OU.AutoCompleteSource = "CustomSource" 
$ComboBox_OU.AutoCompleteMode = "SuggestAppend"
$AD_OUs.CanonicalName | FOREACH-Object { [void]$ComboBox_OU.AutoCompleteCustomSource.Add($_) }

# Controls
$GroupBox_CopyUser.Controls.Add($ComboBox_CopyUser)
$GroupBox_OU.Controls.Add($ComboBox_OU)

$GroupBox_UPN.Controls.AddRange(@(
    $TextBox_UPN
    $ComboBox_UPN
))

$NewUserFrom.controls.AddRange(@( 
    $Label_FirstName
    $TextBox_FirstName
    $Label_LastName
    $TextBox_LastName
    $GroupBox_UPN
    $GroupBox_OU
    $GroupBox_CopyUser
    $Button_NewUser_Cancel
    $Button_NewUser_OK
))

[void]$NewUserFrom.ShowDialog()

}

#  creates New user 
Function New-AD_User { 

    $Seasons = Get-Random @('Spring', 'Summer', 'Autumn', 'Winter') 
    $Num = Get-Random @(10..99)
    $UserName = $TextBox_UPN.text.ToString()
    $CreatedInOU = $ComboBox_OU.SelectedItem.ToString()

    # CN convert is taken from https://gist.github.com/joegasper/3fafa5750261d96d5e6edf112414ae18
    $obj = $ComboBox_OU.SelectedItem.Replace(',','\,').Split('/')
    [string]$DN = "OU=" + $obj[$obj.count - 1]
    for ($i = $obj.count - 2;$i -ge 1;$i--){$DN += ",OU=" + $obj[$i]}
    $obj[0].split(".") | FOREACH-Object { $DN += ",DC=" + $_}
    # the rest is my code

    $NewUser = @{

        'Name'              = $TextBox_UPN.text.ToString()
        'GivenName'         = $TextBox_FirstName.text.ToString()
        'Surname'           = $TextBox_LastName.text.ToString()
        'DisplayName'       = $TextBox_FirstName.text.ToString() + '.' + $TextBox_LastName.text.ToString()
        'SamAccountName'    = $TextBox_UPN.text.ToString()
        'UserPrincipalName' = $TextBox_UPN.text.ToString() + $ComboBox_UPN.SelectedItem.ToString()
        'Path'              = $DN
        'Enabled'           = $true
        'AccountPassword'   = $Seasons+$Num | ConvertTo-SecureString -AsPlainText -Force

    } 

    TRY { 
        
    $StatusBarLabel.text = "  Creating new user account for $UserName"
    New-ADUser @NewUser -ErrorAction Stop

        IF($ComboBox_CopyUser.SelectedItem -ne $null) {

            Start-Sleep -Milliseconds 0.2
            $CopyUser = $ComboBox_CopyUser.SelectedItem.ToString()
            $CopyFromUser = Get-ADUser $CopyUser -Properties MemberOf
            $CopyToUser = Get-ADUser $UserName -Properties MemberOf
            $CopyFromUser.MemberOf | Where{$UserName.MemberOf -notcontains $_} |  Add-ADGroupMember -Members $UserName -ErrorAction SilentlyContinue
               
        }
    
        Clear-Output
        $TextBox_Output.AppendText("

$UserName account has been successfully created
Account created in $CreatedInOU
Password is $Seasons$Num and must be chagned at next login."
              
        ) 
        $ComboBox_Users.Text = $Null
        $Script:AD_Users += $UserName
        [void]$ComboBox_Users.Items.add($UserName)
        [void]$ComboBox_Users.AutoCompleteCustomSource.add($UserName) 
        Save-ADdata
        Set-StatusBarReady

    } CATCH { Write-OutError ; Set-StatusBarReady }
}


# display full user account info to output 
Function Get-AD_UserFullInfo {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
    } ELSE {
        TRY {
            Clear-Output
            $UserAccount = $ComboBox_Users.Text.ToString()
            $TextBox_Output.text = get-aduser $UserAccount -Properties * | Format-List | Out-String -Width 2147483647
            
        } CATCH { Write-OutError }
    }
}

# list all groups user account is member of to output
Function Get-AD_UserMembers {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
    } ELSE {
        TRY {
            Clear-Output
            $UserAccount = $ComboBox_Users.Text.ToString()
            $results = get-aduser $UserAccount -Properties * | FOREACH-Object {($_.memberof | Get-ADGroup | Select-Object -ExpandProperty Name)} | Sort-Object | Format-List | Out-String -Width 2147483647
            IF( $results.Length -eq '0' )  { Write-OutInfo ; $TextBox_Output.text = "$UserAccount is not a member of any groups"}
            ELSE { $TextBox_Output.AppendText($results) }
        } CATCH { Write-OutError }
    }
}


# resets password to random one - password must be changed at next login
Function Set-AD_UserPasswordReset {        

    IF ($ComboBox_Users.SelectedItem -eq $null) {
      Set-Output_ADuserNull
    } ELSE {
        TRY {
            $UserAccount = $ComboBox_Users.Text.ToString()
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("         Reset $UserAccount Password?", 0, "Reset Password Prompt", 4)
    
            IF ($Answer -eq 6) {
                Clear-Output
                $Seasons = Get-Random @('Spring', 'Summer', 'Autumn', 'Winter') 
                $Num = Get-Random @(10..99)
                Set-ADAccountPassword -Identity $ComboBox_Users.SelectedItem -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$Seasons$Num" -Force)  -ErrorAction Stop
                Set-ADuser -Identity $ComboBox_Users.SelectedItem -ChangePasswordAtLogon $True
                $TextBox_Output.AppendText("$UserAccount's password has been reset to $Seasons$Num and must be changed at next logon")
            } ELSE { Write-Cancelled }
        } CATCH { Write-OutError }
    }
}

# Unlocks account 
Function Set-AD_UserUnlockAccount {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
    } ELSE {
        TRY {
            $UserAccount = $ComboBox_Users.Text.ToString()                
            Clear-Output
            Unlock-ADAccount -Identity $ComboBox_Users.Text -ErrorAction Stop
            $TextBox_Output.AppendText("$UserAccount's account is now unlocked")
        } CATCH { Write-OutError }
    }
}
                        
# disables or enables user account 
Function Set-AD_UserDisableOrEnable {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
       Set-Output_ADuserNull
    } ELSE {
        IF ((Get-ADUser -Identity $ComboBox_Users.SelectedItem).Enabled -eq $true) { 
            TRY {
    
                $UserAccount = $ComboBox_Users.Text.ToString()
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Disable $UserAccount`?", 0, "Disable Account Prompt", 0x4 + 0x30)
    
                IF ($Answer -eq 6) {
                    Clear-Output
                    Disable-ADAccount -Identity $ComboBox_Users.SelectedItem -ErrorAction Stop
                    $TextBox_Output.AppendText("$UserAccount account is now disabled")
                } ELSE {
                    Clear-Output
                    Write-OutInfo
                    $TextBox_Output.AppendText("Account disabled operation canceled") 
                }

            } CATCH { Write-OutError }
        } ELSE { 
            TRY {
    
                $UserAccount = $ComboBox_Users.Text.ToString()
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        $UserAccount is disabled, Enable this account`?", 0, "Enable Account Prompt", 0x4 + 0x30)
    
                IF ($Answer -eq 6) {
                    Clear-Output
                    Enable-ADAccount -Identity $ComboBox_Users.SelectedItem -ErrorAction Stop
                    $TextBox_Output.AppendText("$UserAccount account is now Enabled")
                } ELSE {Write-Cancelled }
            } CATCH { Write-OutError }
        }
    }
}

# sets password to never expire 
Function Set-PasswordToNeverExpire {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
    } ELSE {
        IF ((Get-ADUser $ComboBox_Users.SelectedItem -Properties *).PasswordNeverExpires -eq $false ) {

            TRY {
                Clear-Output
                $UserAccount = $ComboBox_Users.Text.ToString()
                set-aduser $ComboBox_Users.SelectedItem -PasswordNeverExpires:$true 
                $TextBox_Output.AppendText("$UserAccount account is set to 'Password Never Expires'")
        
            } CATCH { Write-OutError }
        } ELSE {
            TRY {
                Clear-Output
                $UserAccount = $ComboBox_Users.Text.ToString()
                set-aduser $ComboBox_Users.SelectedItem -PasswordNeverExpires:$false 
                $TextBox_Output.AppendText("$UserAccount Password is now expired and must be changed")
            } CATCH { Write-OutError }
        }
    }
}

# set password to cannot be changed
Function Set-PasswordToCannotBeChanged {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
    } ELSE {
            IF ((Get-ADUser $ComboBox_Users.SelectedItem -Properties *).CannotChangePassword -eq $false ) {

                TRY {
                    Clear-Output
                    $UserAccount = $ComboBox_Users.Text.ToString()
                    set-aduser $ComboBox_Users.SelectedItem -CannotChangePassword:$true
                    $TextBox_Output.AppendText("$UserAccount's account is set to 'Cannot Change Password'")
        
                } CATCH { Write-OutError }
            } ELSE {
                TRY {
                    Clear-Output
                    $UserAccount = $ComboBox_Users.Text.ToString()
                    Set-Aduser $ComboBox_Users.SelectedItem -CannotChangePassword:$false 
                    $TextBox_Output.AppendText("$UserAccount's Password can now be changed by user")
            } CATCH { Write-OutError }
        }
    }
}

# Added account to selected groups
Function Add-AD_UserToGroup {

     IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } ELSE {
        TRY {
            Clear-Output
            $UserAccount = $ComboBox_Users.Text.ToString()
            $List = $AD_Groups | Out-GridView -PassThru -Title "Select Group(s)"
            IF ($list.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Groups selected")}
            ELSE {
                FOREACH($Group in $List) { Add-ADGroupMember -Identity $Group -Members $UserAccount -Confirm:$false } 
                $TextBox_Output.AppendText("$UserAccount has now been added to selected Groups")
            }
        } CATCH { Write-OutError }
    }
} 

# Copies All selected users members
Function Copy-AD_UserMemberships {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } ELSE {
        TRY {
            $UserAccount = $ComboBox_Users.Text.ToString()
            $CopyUser = $AD_Users | Sort-Object | Out-GridView -PassThru -Title "Select Account" 
            IF ($CopyUser.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Account selected")}
            ELSE {
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Copy all Groups form $CopyUser'?", 0, "Copy",0x4 + 0x20)
                SWITCH ($Answer) {
                6 {
                    $StatusBar.text = "Copying All Groups from $UserAccount"
                    Start-Sleep -Milliseconds 0.2
                    $List = Get-ADUser $CopyUser -Properties * | FOREACH-Object {($_.memberof | Get-ADGroup).SamAccountName } 
                    FOREACH($Group in $List) { Add-ADGroupMember -Identity $Group -Members $UserAccount -Confirm:$false -ErrorAction SilentlyContinue } 
                    Clear-Output
                    $TextBox_Output.AppendText("All groups from $CopyUser have been added to $UserAccount")
                    Set-StatusBarReady
                    }  Default  { Write-Cancelled }
                }
            }
        } CATCH { Write-OutError }
    }
}

# Rmmoves All selected users Group membership
Function Remove-AD_UserfromAllGroups {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } ELSE {
        TRY {
            Clear-Output
            $UserAccount = $ComboBox_Users.Text.ToString()
            $UserPrompt = new-object -comobject wscript.shell
            $List = get-aduser $UserAccount -Properties * | FOREACH-Object {($_.memberof | Get-ADGroup).SamAccountname} 
            IF ($list.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("Account is not a member of any Groups")}
            ELSE {
                $List = get-aduser $UserAccount -Properties * | FOREACH-Object {($_.memberof | Get-ADGroup).SamAccountName}
                $Answer = $UserPrompt.popup("        Remove all Groups from $UserAccount`?", 0, "Remove", 0x4 + 0x30)
                SWITCH ($Answer) {
                6 {
                    Clear-Output
                    $StatusBar.text = "Removing All Groups"
                    Start-Sleep -Milliseconds 0.2
                    FOREACH($Group in $List) { Remove-ADGroupMember -Identity $Group -Members $UserAccount -Confirm:$false } 
                    Set-StatusBarReady 
                    $TextBox_Output.AppendText("Removed all groups form $UserAccount") 
                    }  Default  { Write-Cancelled }
                }
            }
        } CATCH { Write-OutError }
    }
}

Function Remove-AD_UserfromGroup {
    
    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } ELSE {
        TRY {
            Clear-Output
            $UserAccount = $ComboBox_Users.Text.ToString()
            $List = get-aduser $UserAccount -Properties * | FOREACH-Object {($_.memberof | Get-ADGroup).SamAccountname} | Sort-Object | Out-GridView -PassThru -Title "Select Groups"
            IF ($list.Length -eq '0' ) {$TextBox_Output.AppendText("Account is not a member of any Groups")}
            ELSE {
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("      Remove groups from $UserAccount`?", 0, "Remove", 0x4 + 0x30)
                SWITCH ($Answer) {
                6 {
                    IF ($list.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Groups selected")}
                    ELSE {
                        FOREACH($Group in $List) { Remove-ADGroupMember -Identity $Group -Members $UserAccount -Confirm:$false } 
                        $TextBox_Output.AppendText("All selected groups have been removed form $UserAccount")
                        }
                    } Default  { Write-Cancelled }
                }
            }
        } CATCH { Write-OutError }
    }
}


# Moves Account OU
Function Move-AD_User {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } ELSE {
        TRY {
            Clear-Output
            $ORG = $AD_OUs | Out-GridView -PassThru -Title "Select Organizational Unit"
            IF ($list.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Organizational Unit selected")}
            ELSE {$User = $ComboBox_Users.SelectedItem.ToString() 
                $ORG_move = $ORG.CanonicalName
                $User_Move = Get-ADuser -Identity $ComboBox_Users.SelectedItem -Properties * | select DistinguishedName 
                Move-ADObject -Identity $User_Move.DistinguishedName -TargetPath $ORG.DistinguishedName
                $TextBox_Output.text = "Moved $User to $ORG_move"
            }
        } CATCH { Write-OutError }
    }
}

# Removes AD account
Function Remove-AD_User {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } ELSE {
        TRY {
            $UserAccount = $ComboBox_Users.SelectedItem.ToString()
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("   Remove $UserAccount from AD?", 0, "Remove User account", 0x4 + 0x10)
            SWITCH ($Answer) {
            6 {
             Clear-Output
                $User = $ComboBox_Users.SelectedItem.ToString() 
                Remove-ADuser $User -Confirm:$false -ErrorAction Stop
                $TextBox_Output.text = "Removed $User from Active Directory"

                $script:AD_Users -ne $user
                [void]$ComboBox_Users.Items.remove($user)
                [void]$ComboBox_Users.AutoCompleteCustomSource.Remove($user) 
                Save-ADdata
            } Default { 
                Clear-Output
                Write-OutInfo
                $TextBox_Output.AppendText("Remove account operation canceled") 
                }
            }
        } CATCH { Write-OutError }
    }
}



# Computer Functions
#===========================================================

# Provides full information for computer account 
Function Get-AD_ComputerFullInfo {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
    } ELSE {
    TRY {
        Clear-Output
        $TextBox_Output.text = Get-ADComputer $ComboBox_Computers.SelectedItem -Properties * | Format-List | Out-String -Width 2147483647 
        } CATCH { Write-OutError }
    }
}

# This will provide hardware information to computer account 
Function Get-AD_systemInfo {
 
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
    } ELSE {
    TRY {
        Clear-Output
        $Sys = $ComboBox_Computers.SelectedItem.ToString()
        $TextBox_Output.text = Invoke-Expression "systeminfo /s $Sys" -ErrorAction Stop | Out-String
        } CATCH { Write-OutError }
    }
}

# This will ping the selected computer 
Function Start-AD_ComputerPing {

  IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
    } ELSE {
    TRY {
        Clear-Output
        $Sys = $ComboBox_Computers.SelectedItem.ToString()
        $TextBox_Output.text = Invoke-Expression "Ping $Sys" -ErrorAction Stop | Out-String
        } CATCH { Write-OutError }
    }
}

# This will start a traceroute to selected computer 
Function Start-AD_TraceRoute {
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
    } ELSE {
        $IP_URI = $ComboBox_Computers.SelectedItem.ToString()
        $Path = "$env:PUBLIC\TraceRoute$IP_URI.txt"
        Start-Process Powershell -ArgumentList "Start-Transcript -Path $Path ; Test-NetConnection -TraceRoute $IP_URI ; Invoke-item $path" 
    }
}

# This will do an NS look up to specify computer 
Function Get-AD_nslookup {
   IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
    } ELSE {
        TRY {
        $IP_URI = $ComboBox_Computers.SelectedItem.ToString()
        $TextBox_Output.text = Invoke-Expression "Resolve-DnsName $IP_URI -ErrorAction Stop" | Out-String
        } CATCH { Write-OutError }
    }
}

# This will restart a service on selected computer 
Function Restart-AD_Service {
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
       } ELSE {
            TRY {
            Clear-Output
            $Computer = $ComboBox_Computers.SelectedItem.ToString()
            $Service = (Get-Service -ComputerName $Computer | Out-GridView -PassThru -Title "Select Service to (Re)start").name 
            IF ($Service.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No service selected")}
            ELSE {
                Get-Service -ComputerName $Computer -Name $Service | Restart-Service -Force -ErrorAction Stop 
                $TextBox_Output.text = "Starting $Service service on $Computer"
            }
        } CATCH { Write-OutError }
    }
}

# This will stop a service on selected computer 
Function Stop_AD_Service {
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
      } ELSE {
            TRY {
            Clear-Output
            $Computer = $ComboBox_Computers.SelectedItem.ToString()
            $Service = (Get-Service -ComputerName $Computer | Out-GridView -PassThru -Title "Select Service to (Re)start").name
            IF ($Service.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No service selected")}
            ELSE {
                Get-Service -ComputerName $Computer -Name $Service | Stop-Service -Force -ErrorAction Stop 
                $TextBox_Output.text = "Stopping $Service service on $Computer"
            }
        } CATCH { Write-OutError }
    }
}
 
# This will stop selected process on selected computer 
Function Stop_AD_Process {
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
    } ELSE {
            TRY {
            Clear-Output
            $Computer = $ComboBox_Computers.SelectedItem.ToString()
            $StatusBarLabel.text = " Running WMI query on $Computer"
            Start-Sleep 0.2
            $Process = (Get-WmiObject Win32_Process -ComputerName $Computer | Select Name, @{Name="UserName";Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}} | Sort-Object UserName, Name | Out-GridView -Title "Select Process" -PassThru).name 
            IF ($Process.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No process selected") ; Set-StatusBarReady}
            ELSE {
                (Get-WmiObject Win32_Process -ComputerName $Computer | Where { $_.ProcessName -match $Process }).Terminate()
                $TextBox_Output.text = "Stopping $process Process on $Computer"
                Set-StatusBarReady
            }
        } CATCH { Write-OutError ; Set-StatusBarReady}
    }
}
 
 # This will remotely connect to specific computer 
Function Connect-AD_Computer{

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            Clear-Output
            $TextBox_Output.text = "Connceting to $Computer"
            Start-Process mstsc.exe -ArgumentList "/v:$Computer"
        } CATCH { Write-OutError }
    }
}

# This will remotely connect to event viewer for specified computer 
Function Start-AD_ComputerEventViewer {
    
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
        } ELSE {
        TRY {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            Clear-Output
            $TextBox_Output.text = "Opening Event viewer to $Computer"
            Start-Process eventvwr.exe -ArgumentList "$Computer"
        } CATCH { Write-OutError }
    }
}

# This will start computer management on specified computer 
Function Start-AD_ComputerManagement {
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            Clear-Output
            $TextBox_Output.text = "Opening Computer Management to $Computer"
            Start-Process compmgmt.msc -ArgumentList "/s /computer:\\$Computer"
        } CATCH { Write-OutError }
    }
}

# This will list all groups computer is a member of 
Function Get-AD_ComputerMembers {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            Clear-Output
            $Computer = $ComboBox_Computers.SelectedItem.ToString()
            $TextBox_Output.text = Get-ADComputer $Computer -Properties * | FOREACH-Object {($_.memberof | Get-ADGroup | Select-Object -ExpandProperty Name)} | Format-List | Out-String -Width 2147483647
        } CATCH { Write-OutError }
    }
}

# Will add computer to specified group or groups 
Function Add-AD_ComputerToGroup {

     IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            Clear-Output
            $ComputerAccount = $ComboBox_Computers.Text.ToString()
            $List = $AD_Groups | Out-GridView -PassThru -Title "Select Group(s)"
            IF ($List.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Groups selected")}
            ELSE {
                FOREACH($Group in $List) { Add-ADGroupMember -Identity $Group -Members "$ComputerAccount$" -Confirm:$false } 
                $TextBox_Output.AppendText("$ComputerAccount has now been added to selected Groups")
            }
        } CATCH { Write-OutError }
    }
} 

# this will copy all memberships from specified computer account 
Function Copy-AD_ComputerMembers {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            $ComputerAccount = $ComboBox_Computers.Text.ToString()
            $CopyComputer = $AD_Computers | Sort-Object | Out-GridView -PassThru -Title "Select Account" 
            IF ($CopyComputer.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Computer selected")}
            ELSE {
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Copy all Groups form $CopyComputer?", 0, "Copy", 0x4 + 0x20)
                IF ($Answer -eq 6) {
                    $StatusBar.text = "Copying All Groups from $CopyComputer"
                    $List = Get-ADComputer $CopyComputer -Properties * | FOREACH-Object {($_.memberof | Get-ADGroup).SamAccountName } 
                    FOREACH($Group in $List) { Add-ADGroupMember -Identity $Group -Members "$ComputerAccount`$" -Confirm:$false -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 0.2 } 
                    Clear-Output
                    $TextBox_Output.AppendText("All groups from $CopyComputer have been added to $ComputerAccount")
                    Set-StatusBarReady
                }
            }
        } CATCH { Write-OutError }
    }
}

# remotes all groups form computer account
Function Remove-AD_ComputerFromAllGroups {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            Clear-Output
            $ComputerAccount = $ComboBox_Computers.Text.ToString()      
            $List = Get-ADComputer $ComputerAccount -Properties * | FOREACH-Object {($_.memberof | Get-ADGroup).SamAccountName}
            IF ($List.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("Computer is not a member of any groups")}
            ELSE {
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Remove all Groups from $ComputerAccount?", 0, "Remove", 0x4 + 0x30)
                IF ($Answer -eq 6) {
                    $StatusBar.text = "Removing All Groups"
                    Start-Sleep -Milliseconds 0.2
                    FOREACH($Group in $List) { Remove-ADGroupMember -Identity $Group -Members "$ComputerAccount$" -Confirm:$false } 
                    $TextBox_Output.AppendText("Removed all groups form $ComputerAccount") 
                    Set-StatusBarReady 
                } ELSE { Write-Cancelled }
            }
        } CATCH { Write-OutError }
    }
}

# remotes selected groups form computer account
Function Remove-AD_ComputerFromGroup {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            Clear-Output
            $ComputerAccount = $ComboBox_Computers.Text.ToString()      
            $List = Get-ADComputer $ComputerAccount -Properties * | FOREACH-Object {($_.memberof | Get-ADGroup | Select-Object -ExpandProperty Name)} | Sort-Object | Out-GridView -PassThru -Title "Select Groups"
            IF ($List.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Group seleceted")}
            ELSE {
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Remove selceted Groups from $ComputerAccount?", 0, "Remove", 0x4 + 0x30)
                IF ($Answer -eq 6) {
                    Clear-Output
                    FOREACH($Group in $List) { Remove-ADGroupMember -Identity $Group -Members "$ComputerAccount$" -Confirm:$false } 
                    $TextBox_Output.AppendText("All selected groups have been removed form $ComputerAccount")
                } ELSE { Write-Cancelled }
            }
        } CATCH { Write-OutError }
    }
}

# Moves Computers OU
Function Move-AD_Computer {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            Clear-Output
            $ORG = $AD_OUs | Out-GridView -PassThru -Title "Select Organizational Unit"
            IF ($ORG.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Organizational Unit seleceted")}
            ELSE {
                $Computer = $ComboBox_Computers.SelectedItem.ToString() 
                $ORG_move = $ORG.CanonicalName
                $Computer_Move = Get-ADComputer $ComboBox_Computers.SelectedItem -Properties * | select DistinguishedName 
                Move-ADObject -Identity $Computer_Move.DistinguishedName -TargetPath $ORG.DistinguishedName
                $TextBox_Output.text = "Moved $Computer to $ORG_move"
                }
        } CATCH { Write-OutError }
    }
}

# Removes AD Computer account
Function Remove-AD_Computer {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("        Remove $Computer from AD?", 0, "Remove", 0x4 + 0x10)
    
            IF ($Answer -eq 6) {
                Clear-Output
                Remove-ADComputer $Computer -Confirm:$false -ErrorAction Stop
                $TextBox_Output.text = "Removed $Computer from Active Directory"

                $Script:AD_Computers -ne $Computer
                [void]$ComboBox_Computers.Items.remove($Computer)
                [void]$ComboBox_Computers.AutoCompleteCustomSource.Remove($Computer) 
                Save-ADdata

            } ELSE { Write-Cancelled }
        } CATCH { Write-OutError }
    }
}

# This will invoke remote GP update to selected computer and restart computer if specified
Function Invoke-AD_ComputerPolicyUpdate {
    
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("Restart $Computer after group policy update?", 0, "Gpupdate", 0x4 + 0x10)
    
                IF ($Answer -eq 6) {
                Clear-Output
                Invoke-GPUpdate -Computer $Computer -Force -Boot -ErrorAction Stop
                $TextBox_Output.text = "Group policy update request sent to $Computer with restart"
            } ELSE { 
                Clear-Output
                Invoke-GPUpdate -Computer $Computer -Force -ErrorAction Stop
                $TextBox_Output.Text = "Group policy update request sent to $Computer"
            }
        } CATCH { Write-OutError }
    }
}

# restarts PC
Function Restart-AD_Computer {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } ELSE {
        TRY {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("    Restart $Computer`?", 0, "Restart?", 0x4 + 0x10)
    
                IF ($Answer -eq 6) {
                
                Clear-Output
                
                Restart-Computer $Computer -Force -Confirm:$false -ErrorAction Stop
                $TextBox_Output.text = "Restart request sent to $Computer"
            } ELSE { Write-Cancelled }
        } CATCH { Write-OutError }
    }
}

# Groups Functions
#===========================================================

# Opens new Groups App
Function New-GroupUI {  

$NewGroupFrom = New-Object Windows.forms.form -Property @{
    Text = "  Group creation tool"
    Size = "550, 310"
    TopMost = $false
    ShowIcon = $false
    ShowInTaskbar = $False
    MinimizeBox = $False
    MaximizeBox = $False
    FormBorderStyle = 3
}

$GroupBox_Groupname = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "15, 5"
    Size = "445,44"
    Text = "Group Name"
}

$TextBox_GroupName = New-Object System.Windows.Forms.TextBox -Property @{
    Location = "7, 14"
    Width = 430
}

$GroupBox_GroupCategory = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "15,50"
    Size = "115, 53"
    Text = "Select Group Type"
}

$ListBox_GroupCategory = New-Object System.Windows.Forms.ListBox -Property @{
    name                = "ListBox_Group_type"
    Location            = "7, 14"
    Size                = "100,30"
}

$ListBox_GroupCategory.Items.AddRange(@(
    "Security"
    "Distribution"
))


$GroupBox_Group_Scope = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "135,50"
    Size = "135, 65"
    Text = "Select Group Scope"
}


$ListBox_Group_Scope = New-Object System.Windows.Forms.ListBox -Property @{
    name                = "ListBox_Group_Scope"
    Location            = "7, 14"
    Size                = "120,50"
}

$ListBox_Group_Scope.Items.AddRange(@(
    "DomainLocal"
    "Global"
    "Universal"
))

$GroupBox_OU = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "15, 120" 
    Size = "508, 45"
    Text = "Select OU"
}

$ComboBox_OU = New-Object System.Windows.Forms.ComboBox -Property @{
    Location = "8, 14"
    Width = 493
}

$GroupBox_CopyGroup = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "15,170"
    Size = "508, 45"
    Text = "Copy members from Group ( not requered )"
}

$ComboBox_CopyGroup= New-Object System.Windows.Forms.ComboBox -Property @{ 
    Location = "7, 14"
    DropDownStyle = "DropDown"
    Width = 493
}

$Button_NewGroup_Cancel = New-Object System.Windows.Forms.Button -Property @{
    Location = "140, 225"
    Size = "128,35"
    Text = "Cancel"
    FlatStyle = "Flat"
}

$Button_NewGroup_OK = New-Object System.Windows.Forms.Button -Property @{
    Location = "275, 225"
    Size = "128,35"
    Text = "Ok"
    FlatStyle = "Flat"
}

$Button_NewGroup_Cancel.FlatAppearance.BorderSize = 0
$Button_NewGroup_OK.FlatAppearance.BorderSize = 0

# Controls
$Button_NewGroup_Cancel.add_Click( { $NewGroupFrom.Close(); $NewGroupFrom.Dispose() })
$Button_NewGroup_OK.add_Click( { New-AD_Group })

# Populate ComboBoxes
FOREACH ($Group in $AD_Groups) { [void]$ComboBox_CopyGroup.Items.Add($Group) }
$ComboBox_CopyGroup.AutoCompleteSource = "CustomSource" 
$ComboBox_CopyGroup.AutoCompleteMode = "SuggestAppend"
$AD_Group | FOREACH-Object { [void]$ComboBox_CopyGroup.AutoCompleteCustomSource.Add($_) }

FOREACH ($OU in $AD_OUs.CanonicalName) { [void]$ComboBox_OU.Items.Add($OU) }
$ComboBox_OU.AutoCompleteSource = "CustomSource" 
$ComboBox_OU.AutoCompleteMode = "SuggestAppend"
$AD_OUs.CanonicalName | FOREACH-Object { [void]$ComboBox_OU.AutoCompleteCustomSource.Add($_) }

#Defaults
$ListBox_GroupCategory.SelectedItem = "Security"
$ListBox_Group_Scope.SelectedItem = "Global"

# Controls
$GroupBox_Groupname.Controls.Add($TextBox_GroupName)
$GroupBox_Group_Scope.Controls.Add($ListBox_Group_Scope)
$GroupBox_GroupCategory.Controls.Add($ListBox_GroupCategory)
$GroupBox_CopyGroup.Controls.Add($ComboBox_CopyGroup)
$GroupBox_OU.Controls.Add($ComboBox_OU)

$NewGroupFrom.controls.AddRange(@( 
    $GroupBox_Groupname
    $GroupBox_GroupCategory
    $GroupBox_Group_Scope
    $GroupBox_OU
    $GroupBox_CopyGroup
    $Button_NewGroup_Cancel
    $Button_NewGroup_OK
))

[void]$NewGroupFrom.ShowDialog()

}


# Create new AD groups
Function New-AD_Group { 

    $GroupName = $TextBox_GroupName.text.ToString()
    $CreatedInOU = $ComboBox_OU.SelectedItem.ToString()

    # CN convert is taken from https://gist.github.com/joegasper/3fafa5750261d96d5e6edf112414ae18
    $obj = $ComboBox_OU.SelectedItem.Replace(',','\,').Split('/')
    [string]$DN = "OU=" + $obj[$obj.count - 1]
    for ($i = $obj.count - 2;$i -ge 1;$i--){$DN += ",OU=" + $obj[$i]}
    $obj[0].split(".") | FOREACH-Object { $DN += ",DC=" + $_}
    # the rest is my code

    $Name              = $TextBox_GroupName.text.ToString()
    $Path              = $DN
    $GroupScope        = $ListBox_Group_Scope.SelectedItem.ToString()
    $GroupCategory     = $ListBox_GroupCategory.SelectedItem.ToString() 


           
    $StatusBarLabel.text = "  Creating new Group for $GroupName in $CreatedInOU OU"
    
    TRY {

    New-ADGroup -name $name -GroupScope $GroupScope -GroupCategory  $GroupCategory -Path $DN -ErrorAction Stop

        IF($ComboBox_CopyGroup.SelectedItem -ne $null) {

            Start-Sleep -Milliseconds 0.2
            $CopyGroup = $ComboBox_CopyGroup.SelectedItem.ToString()
            $CopyFromGroup = Get-ADGroup $CopyGroup -Properties MemberOf
            $CopyToGroup = Get-ADGroup $GroupName -Properties MemberOf
            $CopyFromGroup.MemberOf | Where{$GroupName.MemberOf -notcontains $_} |  Add-ADGroupMember -Members $GroupName -ErrorAction SilentlyContinue
               
        }
    
        Clear-Output
        $TextBox_Output.AppendText("$GroupName Group has been successfully created in $CreatedInOU")
        $ComboBox_Groups.Text = $Null
        $Script:AD_Groups += $GroupName
        [void]$ComboBox_Groups.Items.add($GroupName)
        [void]$ComboBox_Groups.AutoCompleteCustomSource.add($GroupName) 
        Save-ADdata
        Set-StatusBarReady

    } CATCH { Write-OutError }
}


# Lists all group members
Function GroupMembers {
    
        IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
        } ELSE {
            TRY {
            Clear-Output
            $TextBox_Output.text = (Get-ADGroupMember -Identity $ComboBox_Groups.SelectedItem).Name  | Sort-Object | Out-String -Width 2147483647
        } CATCH { Write-OutError }
    }
}

# lists group info
Function GroupInfo {
    
    IF ($ComboBox_Groups.SelectedItem -eq $null) {
    Set-Output_ADGroupNull
    } ELSE {
        TRY {
        Clear-Output
        $TextBox_Output.text = Get-ADGroup $ComboBox_Groups.SelectedItem -Properties * | Format-List | Out-String -Width 2147483647
        } CATCH { Write-OutError }
    }
}


# adds a user object
Function Add-UserMember {

    IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
        } ELSE {
        TRY {
            $GroupOBJ = $ComboBox_Groups.Text.ToString()
            Clear-Output
            $Members = $AD_Users | Out-GridView  -Title "Select Member(s) to add to $GroupOBJ" -PassThru 
            IF ($Members.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Members seleceted")}
            ELSE {
                $Members = (Get-ADUser $Members -Properties *).SamAccountname 
                Add-ADGroupMember -Identity $ComboBox_Groups.text -Members $Members -ErrorAction Stop 
                $TextBox_Output.AppendText("Members added to $GroupOBJ Group")
            }
        } CATCH { Write-OutError }
    }
}

# adds a computer object
Function Add-ComputerMember {

   IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
    } ELSE {
        TRY {
            $GroupOBJ = $ComboBox_Groups.Text.ToString()
            Clear-Output
            $Members = Get-ADComputer -Filter * | select Name, SamAccountname | Out-GridView  -Title "Select Member(s) to add to $GroupOBJ" -PassThru
            IF ($Members.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Members seleceted")}
            ELSE {
                Add-ADGroupMember -Identity $ComboBox_Groups.text -Members $Members.SamAccountName -ErrorAction Stop 
                $TextBox_Output.AppendText("Members added to $GroupOBJ Group")
            }
        } CATCH { Write-OutError }
    }
}

# adds a group object
Function Add-GroupMember {

   IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
    } ELSE {
        TRY {
            $GroupOBJ = $ComboBox_Groups.Text.ToString()
            Clear-Output
            $Members = Get-ADGroup -Filter * | select Name | Out-GridView  -Title "Select Member(s) to add to $GroupOBJ" -PassThru 
            IF ($Members.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Members seleceted")}
            ELSE {
                Add-ADGroupMember -Identity $ComboBox_Groups.text -Members $Members.SamAccountName -ErrorAction Stop 
                $TextBox_Output.AppendText("Members added to $GroupOBJ Group")
            }
        } CATCH { Write-OutError }
    }
}


# Remove selected objects 
Function Remove-Member {

    IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull 
    } ELSE {
        TRY {
            Clear-Output
            $GroupOBJ = $ComboBox_Groups.Text.ToString()
            $Members = Get-ADGroup $ComboBox_Groups.SelectedItem | Get-ADGroupMember | Select-Object Name,SamAccountName | Out-GridView -Title "Select Member(s) to remove from $GroupOBJ" -PassThru
            IF ($Members.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("Groups has no members")}
            ELSE{
                Get-ADGroup $ComboBox_Groups.SelectedItem | remove-adgroupmember -Members $members.SamAccountName -Confirm:$false -ErrorAction Stop
                $TextBox_Output.AppendText("Removed members from $GroupOBJ Group")
            }
        } CATCH { Write-OutError }
    }
}

# Moves group to new organisational unit
Function Move-AD_Group {

    IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
        } ELSE {
        TRY {
            Clear-Output
            $ORG = $AD_OUs | Out-GridView -PassThru -Title "Select Organizational Unit"
            IF ($ORG.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("Groups has no members")}
            ELSE {
                $Group = $ComboBox_Groups.SelectedItem.ToString() 
                $ORG_move = $ORG.CanonicalName
                $Group_Move = Get-ADGroup $ComboBox_$Groups.SelectedItem -Properties * | select DistinguishedName 
                Move-ADObject -Identity $Computer_Move.DistinguishedName -TargetPath $ORG.DistinguishedName
                $TextBox_Output.text = "Moved $Group to $ORG_move"
            }
        } CATCH { Write-OutError }
    }
}

# Removes Group
Function Remove-AD_Group {

    IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
        } ELSE {
        TRY {
        $Group = $ComboBox_Groups.Text.ToString()
        $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Remove $Group from AD?", 0, "Remove", 0x4 + 0x10)
    
            IF ($Answer -eq 6) {
                Clear-Output
                Remove-ADGroup $Group -Confirm:$false -ErrorAction Stop
                $TextBox_Output.text = "Removed $Group from Active Directory"

                $Script:AD_Groups -ne $Group
                [void]$ComboBox_Groups.Items.remove($Group)
                [void]$ComboBox_Groups.AutoCompleteCustomSource.Remove($Group) 
                Save-ADdata 
            } ELSE {Write-Cancelled }
        } CATCH { Write-OutError }
    }
}

#===================== Menu Functions ======================

# Exports all user detail to CSV
Function CSVAdUserExport {

    $StatusBarLabel.text = "  Export User Objects to CSV..."
    $List = @()

    $SaveFile = New-Object -TypeName System.Windows.Forms.SaveFileDialog -Property @{
        Title = "Export User Accounts"
        FileName = "$AD_Domain User Export"
        Filter = "CSV Files (*.csv)|*.csv"
    }

    $Answer = $SaveFile.ShowDialog(); $Answer
                
        IF ( $Answer -eq "OK") {
                                                              
            Get-ADUser -Filter * -Properties SamAccountName,Name,Mail,Enabled,whenCreated,LastLogonDate,DistinguishedName | `
            Select-Object SamAccountName,Name,Mail,Enabled,whenCreated,LastLogonDate,DistinguishedName | Export-Csv $SaveFile.FileName -NoTypeInformation
            
            $SaveOut = $SaveFile.FileName.ToString()
            Clear-Output
            Set-StatusBarReady
            $TextBox_Output.AppendText("Exported user acconunts to $SaveOut")
        } ELSE { Write-Cancelled }
}

# Exports all computer detail to CSV
Function CSVComputerExport { 
    
    $StatusBarLabel.text = "  Export Computer Objects to CSV..."
    $SaveFile = New-Object -TypeName System.Windows.Forms.SaveFileDialog
    $SaveFile.Title = "Export Computers"
    $SaveFile.FileName = "$AD_Domain Computers Export"
    $SaveFile.Filter = "CSV Files (*.csv)|*.csv"
    $Answer = $SaveFile.ShowDialog(); $Answer

        IF ( $Answer -eq "OK") {

            Get-ADComputer -Filter * -Properties Name, Created, Enabled, OperatingSystem, OperatingSystemVersion, IPv4Address, LastLogonDate, logonCount | `
            Select-Object Name, Created, Enabled, OperatingSystem, OperatingSystemVersion, IPv4Address, LastLogonDate, logonCount | export-csv $SaveFile.FileName -NoTypeInformation
            $SavePath = $SaveFile.FileName.ToString()
            Clear-Output
            Set-StatusBarReady
            $TextBox_Output.AppendText("Exported Computer acconunts to $SavePath")
        } ELSE { Write-Cancelled }
} 

# Exports all Groups detail to CSV
Function CSVGroupsExport {

    $StatusBarLabel.text = "  Export Group Objects to CSV..."
    $SaveFile = New-Object -TypeName System.Windows.Forms.SaveFileDialog
    $SaveFile.Title = "Export Groups"
    $SaveFile.FileName = "$AD_Domain Groups Export"
    $SaveFile.Filter = "CSV Files (*.csv)|*.csv"
    $Answer = $SaveFile.ShowDialog(); $Answer
        IF ( $Answer -eq "OK") {

            $Groups = Get-ADGroup -Filter * -Properties Name,groupcategory 
            $List = @()
            $List += FOREACH($Group in $Groups) { New-Object PSObject -Property @{

            GroupName = $Group.Name
            Type      = $Group.GroupCategory
            Members   = ($Group.Name | Get-ADGroupMember -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ", " 
            
                } 
            }  
            
            $List | Select-Object GroupName, Type, Members | Export-Csv $SaveFile.FileName -NoTypeInformation
                   
            $SavePath = $SaveFile.FileName.ToString()
            Clear-Output
            Set-StatusBarReady
            $TextBox_Output.AppendText("Exported Groups acconunts to $SavePath")
        } ELSE { Write-Cancelled }
}

#=========================================================================#
#                         Exchange Functions                              # 
#=========================================================================#

#===================== Base Exchange Functions ======================
Function Import-ExchangeXML{

    $Exchange_XML = Import-Clixml "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml"
            
    $script:Exchange_Users                       = $Exchange_XML.Users | Sort-Object
    $script:Exchange_Mailboxes                   = $Exchange_XML.Mailboxs | Sort-Object
    $script:Exchange_DistributionGroups          = $Exchange_XML.Groups | Sort-Object
}

Function Import-ExchangeData {

    $script:Exchange_Users                  = (Get-User -ResultSize Unlimited | Where-Object {$_.RecipientType -eq "user" -and $_.RecipientTypeDetails -ne "DisabledUser"}).SamAccountName | Sort-Object
    $script:Exchange_Mailboxes              = (Get-mailbox -ResultSize Unlimited -WarningAction SilentlyContinue).UserPrincipalName | Sort-Object
    $script:Exchange_DistributionGroups     = (Get-DistributionGroup -ResultSize Unlimited).Name | Sort-Object
}

# Imports All Exchange objects 
Function Enable-Exchange {
    
    Clear-Output
    $GroupBox_ConnectToExchange.Enabled = $false    
    $StatusBarLabel.text = "  Loading Exchange Objects"

    #Connect to Exchange
    TRY { 

        $ConnectionUri = $Textbox_Exchange.text
        $UserCredential = Get-Credential
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ConnectionUri/PowerShell/" -Authentication Kerberos -Credential $UserCredential -ErrorAction Stop
        Import-PSSession $Session -DisableNameChecking -ErrorAction Stop

        IF (test-path "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml") {
        
            $LastWriteTime = (Get-ItemProperty "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml").LastWriteTime
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("Load Exchange data from local cache? `n`nCache was Last updated on $LastWriteTime", 0, " Load from cache", 0x4 + 0x20)

            SWITCH ($Answer) {

            6           { Import-ExchangeXML }
            Default     { Import-ExchangeData }  
            
            }
        
        } ELSE { Import-ExchangeData }
         
        FOREACH ($Mailbox in $Exchange_Mailboxes) { [void]$ComboBox_Mailbox.Items.Add($Mailbox) }
        $ComboBox_Mailbox.AutoCompleteSource = "CustomSource" 
        $ComboBox_Mailbox.AutoCompleteMode = "SuggestAppend"
        $Exchange_Mailboxes | FOREACH-Object { [void]$ComboBox_Mailbox.AutoCompleteCustomSource.Add($_) }

        FOREACH ($DistributionGroup in $Exchange_DistributionGroups) { [void]$ComboBox_Distributionlist.Items.Add($DistributionGroup) }
        $ComboBox_Distributionlist.AutoCompleteSource = "CustomSource" 
        $ComboBox_Distributionlist.AutoCompleteMode = "SuggestAppend"
        $Exchange_DistributionGroups | FOREACH-Object { [void]$ComboBox_Distributionlist.AutoCompleteCustomSource.Add($_) }

        $Panel_Exchange.Enabled = $true
        $Menu_Exchange.Enabled = $true
       
        Clear-Host
        Save-Exchangedata
        Set-StatusBarReady
        $TextBox_Output.AppendText("*** Exchange objects have been loaded ***")  
                                
        
    } CATCH {
        Write-OutError
        Set-StatusBarReady
        $GroupBox_ConnectToExchange.Enabled = $true
    } 

}


# Start Mailbox Action
Function Start-Mailbox_Action {


    IF ($ListBox_Mailbox.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    ELSE { 
      TRY { 
        SWITCH ($ListBox_Mailbox.SelectedItem) {
        
            "Mailbox info"                                      { Get-MailBox_info }
            "Get Mailbox size"                                  { Get-MailBox_Size }
            "List all permissions"                              { Get-MailBox_Permissions }
            "Add full access permissions to mailbox"            { Add-MailBox_FullAccessPermissions }
            "Add send as permissions"                           { Add-MailBox_SendasPermissions }
            "Add send on behalf of permissions"                 { Add-MailBox_SendOnBehalfToPermissions  }
            "Remove full access permissions"                    { Remove-MailBox_FullAccessPermissions }
            "Remove all full access permissions"                { Remove-MailBox_AllFullAccessPermissions }
            "Enable/Disable ActiveSync"                         { Set-Mailbox_ActiveSync }
            "Enable/Disable OWA access"                         { Set-Mailbox_OWA }
            "Set out of office message"                         { Set-Mailbox_Outofoffice }
            "Set mail forwarding"                               { Set-Mailbox_ForwardingAddress }
            "Convert to ..."                                    { Set-Mailbox_Type }
            "Hide/un-hide form global address list"             { Set-Mailbox_ToHidden}
            "Move to Database"                                  { Move-Mailbox_DataBase }
            "Export to .PST"                                    { Export-Mailbox }
            "Remove mailbox"                                    { Remove-Mailbox_fromuser }

            } 
        } CATCH { Write-OutError }
    }
}

# Start Distributionlist Action
Function Start-Distributionlist_Action {


    IF ($ListBox_Distributionlist.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    ELSE { 
      TRY { 
        SWITCH ($ListBox_Distributionlist.SelectedItem) {
        
            "Distribution Group info"                           { Get-DL_info }
            "List all members"                                  { Get-DL_Members }
            "Add members"                                       { Add-DL_Members }
            "Copy members"                                      { Copy-DL_Members }
            "Remove members"                                    { Remove-DL_Members }
            "Remove all members"                                { Remove-DL_Members_all}        
            "Set Owner"                                         { Set_DL_Manger }
            "Hide/un-hide form global address list"             { Set-Dl_ToHidden }
            "Remove Distribution Group"                         { Remove_DL }
    
            } 
        } CATCH { Write-OutError }
    }
}

# Null selected items
Function Set-Output_MailBoxNull {
    Clear-Output
    $TextBox_Output.AppendText("No Mailbox Selected")
}

Function Set-Output_DistributionlistNull {
    Clear-Output
    $TextBox_Output.AppendText("No Distribution Group Selected")
}

# Save Exchange data to cache
Function Save-Exchangedata {
        
    TRY {
        
        New-Object PSObject -Property @{

            Server          = $Textbox_Exchange.text.toString()
            Users           = $Exchange_Users  
            Mailboxs        = $Exchange_Mailboxes  
            Groups          = $Exchange_DistributionGroups  
                    
        } | Export-Clixml "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml"
    } CATCH { Write-OutError }
}

#===================== Mailbox Functions ======================

# Enables a mailbox for an existing Active Directory user 
# This does not define the database of the mailbox isn't able to please use the move mailbox command to move it to the desired mailbox 
function Enable-Mailbox_foruser {
   
    TRY{

        $list = $Exchange_Users | Out-GridView -PassThru -Title "Select User"
        $User = $list.ToString()
        Enable-Mailbox $User -ErrorAction Stop    
        $StatusBarLabel.text = "  Creating Mailbox for $User"
        Start-Sleep 5
        $Mailbox = (Get-mailbox $User).UserPrincipalName
        $ComboBox_Users.Text = $Null

        Start-Sleep 0.2
        $Script:Exchange_Users -ne $User
        $Script:Exchange_Mailboxes += $Mailbox
        [void]$ComboBox_Mailbox.Items.add($Mailbox)
        [void]$ComboBox_Mailbox.AutoCompleteCustomSource.add($Mailbox) 
        $TextBox_Output.text = "$User mailbox $Mailbox is now enabled"
        Save-Exchangedata
        Set-StatusBarReady

    } CATCH { Write-OutError }
}

# Disable the mailbox but does not remove the Active Directory account 
function Remove-Mailbox_fromuser {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {

        $UserAccount = $ComboBox_Mailbox.SelectedItem.ToString()
        $UserPrompt = new-object -comobject wscript.shell
        $Answer = $UserPrompt.popup("   Delete $UserAccount mailbox?", 0, "Remove Mailbox", 0x4 + 0x10)
    
            IF ($Answer -eq 6) {
                Clear-Output

                $Del_Mailbox = Get-MailBox $ComboBox_Mailbox.SelectedItem | Select-Object SamAccountName, UserPrincipalName  
                $User = $Del_Mailbox.SamAccountName.Tostring()
                $Mailbox = $Del_Mailbox.UserPrincipalName.Tostring()
        
                Disable-Mailbox $User -Confirm:$false -ErrorAction Stop 

                $ComboBox_Users.Text = $Null
                $Script:Exchange_Users += $User
                $Script:Exchange_Mailboxes -ne $Mailbox
                [void]$ComboBox_Mailbox.Items.remove($Mailbox)
                [void]$ComboBox_Mailbox.AutoCompleteCustomSource.remove($Mailbox) 
                $TextBox_Output.text = "Mailbox $Mailbox is now Deleted"
                Save-Exchangedata
            
            } ELSE { Write-Cancelled } 
        } CATCH  { Write-OutError }
    }
}

# Provides information about mailbox 
function Get-MailBox_info {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        Clear-Output
        $TextBox_Output.text = Get-Mailbox $ComboBox_Mailbox.SelectedItem -ErrorAction Stop | Format-List | Out-String -Width 2147483647 
        } CATCH  { Write-OutError }
    }
}

# Provides size statistics for mailbox 
function Get-MailBox_Size {    

    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        Clear-Output
        $TextBox_Output.text = Get-MailboxStatistics $ComboBox_Mailbox.SelectedItem -ErrorAction Stop | Format-List | Out-String -Width 2147483647                      
                    
        } CATCH  { Write-OutError }
    }
}

# Enables or disables active sync depending on active sync state 
function Set-Mailbox_ActiveSync {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        Clear-Output 
        $MailBox = [string]$ComboBox_Mailbox.SelectedItem
        $ActiveSync = (Get-CASMailbox -Identity $MailBox).ActiveSyncEnabled
        SWITCH ($ActiveSync) {
                true   { Set-CASMailbox $MailBox -ActiveSyncEnabled:$false ; $TextBox_Output.AppendText("ActiveSync is now disabled for $MailBox")  }
                false  { Set-CASMailbox $MailBox -ActiveSyncEnabled:$true  ; $TextBox_Output.AppendText("ActiveSync is now enabled for $MailBox")  }  
            }   
        } CATCH  { Write-OutError }
    }
}

# Enables or disabled access to OWA mailbox depending on state 
function Set-Mailbox_OWA {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        Clear-Output 
        $MailBox = [string]$ComboBox_Mailbox.SelectedItem
        $OWA = (Get-CASMailbox -Identity $MailBox).OWAEnabled
        SWITCH ($OWA) {
                true   { Set-CASMailbox $MailBox -OWAEnabled:$false ; $TextBox_Output.AppendText("OWA is now disabled for $MailBox")  }
                false  { Set-CASMailbox $MailBox -OWAEnabled:$true  ; $TextBox_Output.AppendText("OWA is now enabled for $MailBox")  }  
            }   
        } CATCH  { Write-OutError }
    }
}

# Set email forwarding address if none has been set or removes it if there is an active forwarding address 
function Set-Mailbox_ForwardingAddress {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        Clear-Output 
        $MailBox = [string]$ComboBox_Mailbox.SelectedItem
        $Forwarding = (Get-Mailbox -Identity $MailBox).ForwardingAddress
        IF( $Forwarding.Length -eq '0' ) {
        $Forwarding_mailbox = $Exchange_Mailboxes | Out-GridView -PassThru -Title "Select Mailbox"
            IF($Forwarding_mailbox.Length -eq '0'){ Write-OutInfo ; $TextBox_Output.text = "No mailbox selected"}
            ELSE {
                Set-Mailbox -Identity $MailBox -ForwardingAddress $Forwarding_mailbox
                $TextBox_Output.text = "$MailBox Emails are been forward to $Forwarding_mailbox"
                } 
            }
        ELSE {
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("  Remove Forwarding emails to $Forwarding from $MailBox mailbox?", 0, "Remove Mailbox", 0x4 + 0x10)
                IF ($Answer -eq 6) {
                    Clear-Output
                    Set-Mailbox -Identity $MailBox -ForwardingAddress $null
                    $TextBox_Output.text = "Removed Forwarding emails to $Forwarding from $MailBox mailbox"
                    } ELSE { Write-Cancelled }
              }   
        } CATCH  { Write-OutError }
    }
}

# Lists all mailboxes this with full access to mailbox  
function Get-MailBox_Permissions {    
     
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
        Clear-Output
        $results = Get-MailboxPermission $Mailbox -ErrorAction Stop | Where-Object { ($_.IsInherited -eq $False) -and ($_.AccessRights -like "*FullAccess*") -and -not ($_.User -like "NT AUTHORITY\SELF") }| Select-Object user, accessrights, IsInherited | Out-String -Width 2147483647 
        IF ($results.Length -eq '0')  { Write-OutInfo ; $TextBox_Output.text = "No User has permissons to $MailBox mailbox"}
        ELSE { $TextBox_Output.AppendText($results) }
            
        } CATCH  { Write-OutError }
    }
}


# Adds full access permissions to specified mailbox 
function Add-MailBox_FullAccessPermissions {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        Clear-Output
        $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
        $Member = $Exchange_Mailboxes | Out-GridView -PassThru -Title "Select Mailbox" 
        IF ($Member.Length -eq '0')  { Write-OutInfo ; $TextBox_Output.text = "No Mailbox Selected"}
        ELSE { 
            Add-MailboxPermission -Identity $Mailbox -User $Member -AccessRights FullAccess -InheritanceType All -Confirm:$false -ErrorAction Stop 
            $TextBox_Output.text = "$Member has been given full permissions to $Mailbox"
            }
        } CATCH  { Write-OutError }
    }
}

# Adds send as permissions to specified mailbox 
function Add-MailBox_SendasPermissions {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        Clear-Output
        $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
        $List = $Exchange_Mailboxes | Out-GridView -PassThru -Title "Select Mailbox"
        $Member = $List.SamAccountName.ToString()
        IF ($Member.Length -eq '0')  { Write-OutInfo ; $TextBox_Output.text = "No Mailbox Selected"}
            ELSE {
            Add-RecipientPermission -Identity $Mailbox -AccessRights SendAs -Trustee $Member -Confirm:$false -ErrorAction Stop
            $TextBox_Output.text = "$Member has been given Send as permissions to $Mailbox"
            }
        } CATCH {  Write-OutError }
    }
}
 
 # Add send on behalf permissions to specified mailbox 
function Add-MailBox_SendOnBehalfToPermissions {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        Clear-Output
        $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
        $List = $Exchange_Mailboxes | Out-GridView -PassThru -Title "Select Mailbox" 
        $Member = $List.SamAccountName.ToString()
        IF ($Member.Length -eq '0')  { Write-OutInfo ; $TextBox_Output.text = "No Mailbox Selected"}
        ELSE {
            Set-Mailbox -Identity $Mailbox -GrantSendOnBehalfTo @{add=$Member} -ErrorAction Stop
            $TextBox_Output.text = "$Member has been given Send On Behalf To permissions to $Mailbox"
            }
        } CATCH  { Write-OutError }
    }
}

# Set out of office message for specified mailbox 
# If specified mailbox has an out of office message will disable 
function Set-Mailbox_Outofoffice {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        Clear-Output
        $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
        IF ((Get-MailboxAutoReplyConfiguration -Identity $Mailbox).AutoReplyState -eq "Disabled") {
             [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
             $title = 'Set out of office message'
             $msg   = 'Enter message:'
             $Message = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
             Set-MailboxAutoReplyConfiguration -Identity $Mailbox -ExternalMessage $Message -InternalMessage $Message -AutoReplyState "Enabled"
             $TextBox_Output.text = "$Mailbox Message has been set to $Message"

        } ELSE { 
        
            Set-MailboxAutoReplyConfiguration -Identity $Mailbox -AutoReplyState "Disabled"
            $TextBox_Output.text = "$Mailbox Out of office Message has been removed"

            }              
        } CATCH  { Write-OutError }
    }
}


# Will change the mailbox type from: regular, shared, equipment or room
function Set-Mailbox_Type {
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
    Set-Output_MailBoxNull 
        } ELSE {
        TRY {
            Clear-Output
            $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
        
                $Type = @{
                'Regular'           = 'Regular mailboxes are the mailboxes that get assigned to every individual Exchange user'
                'Shared'            = 'Shared mailboxes are usually configured for multiple user access'
                'Equipment'         = 'These mailboxes are used for resources that are not location-specIFic like the portable system, microphones, projectors, or company cars.'
                'Room'              = 'This kind of mailbox gets assigned to dIFferent meeting locations, for example, auditoriums, conference and training rooms.'
            }
            
            $Result = $Type | Out-GridView -PassThru  -Title 'Make a  selection'
        
            SWITCH ($Result) {
                { $Result.Name -eq 'Regular'   }  { $Type = 'Regular'   }
                { $Result.Name -eq 'Shared'    }  { $Type = 'Shared'    }
                { $Result.Name -eq 'Equipment' }  { $Type = 'Equipment' }
                { $Result.Name -eq 'Room'      }  { $Type = 'Room'      }
            }   
            IF ($Member.Length -eq '0')  { Write-OutInfo ; $TextBox_Output.text = "No type Selected"}
            ELSE {
                Set-mailbox $Mailbox -type $Type -Confirm:$false
                $TextBox_Output.text = "Convering $Mailbox to $Type" 
            }
        } CATCH  { Write-OutError }
    }
}

# removes selected users send as and full mailbox permissions
function Remove-MailBox_FullAccessPermissions {
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } ELSE {
    TRY {
        $MailBox = $ComboBox_Mailbox.SelectedItem.ToString()
        Clear-Output
        $results = Get-MailboxPermission $MailBox -ErrorAction Stop | Where-Object { ($_.IsInherited -eq $False) -and ($_.AccessRights -like "*FullAccess*") -and -not ($_.User -like "NT AUTHORITY\SELF") } | Select-Object User, Accessrights | Out-GridView -Title "Select User(s) to remove Fullaccess from $MailBox" -PassThru
        IF( $results.Length -eq '0' )  { Write-OutInfo ; $TextBox_Output.text = "No User has Fullaccess permissons to $MailBox mailbox"}
        ELSE  { 
            Remove-MailboxPermission -Identity $MailBox -User $results.User -AccessRights fullaccess -Confirm:$false -ErrorAction Stop 
            $TextBox_Output.text = "Fullaccess permissons have been removed from $MailBox mailbox"
            }            
        } CATCH  { Write-OutError }
    }
}
  
# Removes all access to mailbox
function Remove-MailBox_AllFullAccessPermissions {
    TRY {
        $MailBox = $ComboBox_Mailbox.SelectedItem.ToString()
        Clear-Output
        $results = Get-MailboxPermission $MailBox -ErrorAction Stop | Where-Object { ($_.IsInherited -eq $False) -and ($_.AccessRights -like "*FullAccess*") -and -not ($_.User -like "NT AUTHORITY\SELF") } 
        IF($results.Length -eq '0') { Write-OutInfo ; $TextBox_Output.text = "No User has Fullaccess permissons to $MailBox mailbox"}
        ELSE  {
            FOREACH($User in $results.user) { Remove-MailboxPermission -Identity $MailBox -User $User -Confirm:$false -AccessRights fullaccess -ErrorAction Stop }
            $TextBox_Output.text = "All Fullaccess permissons have been removed from $MailBox mailbox"
        }           
    } CATCH  { Write-OutError }
}

# Sets HiddenFromAddressListsEnabled to true for each selected Mailbox(s) 
function Set-Mailbox_ToHidden{

  IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
    Set-Output_MailBoxNull 
        } ELSE {
        TRY {
            Clear-Output
            $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
            $Result  = (get-mailbox $Mailbox).HiddenFromAddressListsEnabled
            
            SWITCH ($Result) { 
            
            false { Set-Mailbox -Identity $Mailbox -HiddenFromAddressListsEnabled $true ; $TextBox_Output.text = "$Mailbox to is now hidden from global address list" }
            true { Set-Mailbox -Identity $Mailbox -HiddenFromAddressListsEnabled $false ; $TextBox_Output.text = "$Mailbox to is now visble in global address list"  }
            
            }
        } CATCH  { Write-OutError }
    }
}

#exports mail box to PST - must be full UNC path (will not with with mapped drives)
function Export-Mailbox {

  IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
    Set-Output_MailBoxNull 
        } ELSE {
        TRY {
            Clear-Output
            $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
            
                    $SaveFile = New-Object -TypeName System.Windows.Forms.SaveFileDialog
                    $SaveFile.Title = "Export PST"
                    $SaveFile.FileName = "$Mailbox Export"
                    $SaveFile.Filter = "Pst Files (*.pst)|*.pst"
                    $SaveFile.ShowDialog()

                    $Path = $SaveFile.FileName.ToString()

                    New-MailboxExportRequest -Mailbox $Mailbox -FilePath $Path -ErrorAction Stop
                    $TextBox_Output.text = "$Mailbox is now been exported to $Path `n `nNote: this will take some time Depending on the mailbox size "  

        } CATCH { Write-OutError }
    }
}

# Moves mailbox to requested database
function Move-Mailbox_DataBase {
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
    Set-Output_MailBoxNull 
        } ELSE {
        TRY {
            Clear-Output
            $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
            $DataBase = (get-mailboxdatabase | Out-GridView -Title "Select Database" -PassThru).name
            IF($DataBase.Length -eq '0') { Write-OutInfo ; $TextBox_Output.text = "No DataBase selected"}
            ELSE {            
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("Move $Mailbox to $DataBase datebase?", 0, "Gpupdate", 0x4 + 0x10)
                IF ($Answer -eq 6) {
                Clear-Output
                # check for account permissions before running command
                New-MoveRequest -Identity $Mailbox -TargetDatabase $DataBase -ErrorAction Stop 
                $TextBox_Output.text = "$Mailbox move requested to $DataBase datebase has started"
                } ELSE { Write-Cancelled }
            }
        } CATCH { Write-OutError }
    }
}


#================== Distribution Group Functions ==================

function New-DL {    
    
TRY {
    Clear-Output
    [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
    $title = 'New Distribution list'
    $msg   = 'Enter Distribution list name:'
    $Name = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
    IF($Name.Length -eq '0'){ Write-Cancelled } # ; $TextBox_Output.text = "`n`n Name cannot have 0 Characters"}
    ELSE { 
    
        New-DistributionGroup -Name $Name -ErrorAction Stop 
        Start-Sleep 0.2
        $Script:Exchange_DistributionGroups += $Name
        [void]$ComboBox_Distributionlist.Items.add($Name)
        [void]$ComboBox_Distributionlist.AutoCompleteCustomSource.add($Name) 
        $TextBox_Output.text = "$Name distribution has been created"
        Save-Exchangedata
                       
        }
    } CATCH { Write-OutError }
}



# Gets distribution list info 
function Get-DL_info {    
    
    IF ($ComboBox_Distributionlist.SelectedItem -eq $null) {
        Set-Output_DistributionlistNull
    } ELSE {
    TRY {
        Clear-Output
        $TextBox_Output.text = Get-DistributionGroup $ComboBox_Distributionlist.SelectedItem -ErrorAction Stop | Format-List | Out-String -Width 2147483647 
        } CATCH { Write-OutError }
    }
}

# Shows distribution list members
function Get-DL_Members {    
    
    IF ($ComboBox_Distributionlist.SelectedItem -eq $null) {
        Set-Output_DistributionlistNull
    } ELSE {
    TRY {
        Clear-Output
        $results = Get-DistributionGroupMember $ComboBox_Distributionlist.SelectedItem -ErrorAction Stop | Out-String -Width 2147483647 
        IF ($results.Length -eq '0')  { Write-OutInfo ; $TextBox_Output.text = "Disturbed group has no members"}
        ELSE { $TextBox_Output.AppendText($results) }
        } CATCH { Write-OutError }
    }
}

# Add members to distribution list
function Add-DL_Members {    
    
    IF ($ComboBox_Distributionlist.SelectedItem -eq $null) {
        Set-Output_DistributionlistNull
    } ELSE {
    TRY {
        $DL = $ComboBox_Distributionlist.Text.ToString()
        Clear-Output
        $Members = $Exchange_Mailboxes | Out-GridView  -Title "Select Member(s) to add to $DL" -PassThru 
        IF ($Members.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Members seleceted")}
        ELSE {
            FOREACH($Mailbox in $Members) {            
            Add-DistributionGroupMember -Identity $DL -Member $Mailbox -ErrorAction SilentlyContinue 
                }
            $TextBox_Output.AppendText("Members added to $DL Group")    
            }
        } CATCH { Write-OutError }
    }
}

# Copy members from distribution list
function Copy-DL_Members {    
    
    IF ($ComboBox_Distributionlist.SelectedItem -eq $null) {
        Set-Output_DistributionlistNull
    } ELSE {
    TRY {
        $DL = $ComboBox_Distributionlist.Text.ToString()
        Clear-Output
        $Copy_DL = $Exchange_DistributionGroups | Out-GridView  -Title "Select Distribution group to copy members from" -PassThru 
        IF ($Copy_DL.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Distribution group seleceted")}
        ELSE {
            $Members = (Get-DistributionGroupMember -Identity $Copy_DL).name
            FOREACH($Member in $Members) {
            Add-DistributionGroupMember -Identity $DL -Member $Member -ErrorAction SilentlyContinue 
                }
            $TextBox_Output.AppendText("Members added to $DL Group")
            }
        } CATCH  { Write-OutError }
    }
}

# Removes selceted distribution group members 
function Remove-DL_Members {    
    
    IF ($ComboBox_Distributionlist.SelectedItem -eq $null) {
        Set-Output_DistributionlistNull
    } ELSE {
    TRY {
        
        $DL = $ComboBox_Distributionlist.Text.ToString()
        Clear-Output
        $Members = (Get-DistributionGroupMember $DL | Out-GridView  -Title "Select Member(s) to remove from $DL" -PassThru).name 
        IF ($Members.Length -eq '0' ) {Write-OutInfo ; $TextBox_Output.AppendText("No Members seleceted")}
        ELSE {
            FOREACH($Member in $Members) {            
            Remove-DistributionGroupMember -Identity $DL -Member $Member -Confirm:$false -ErrorAction SilentlyContinue 
                }
            $TextBox_Output.AppendText("Members removed from $DL Group") 
            
            }
        } CATCH { Write-OutError } 
    }
}

# Removes all distribution group members 
function Remove-DL_Members_all {    
    
    IF ($ComboBox_Distributionlist.SelectedItem -eq $null) {
        Set-Output_DistributionlistNull
    } ELSE {
    TRY {
        $DL = $ComboBox_Distributionlist.Text.ToString()
        Clear-Output
        
        $UserPrompt = new-object -comobject wscript.shell
        $Answer = $UserPrompt.popup("   Remove All $DL Members?", 0, "Remove Members", 0x4 + 0x10)
        IF ($Answer -eq 6) {
            $Members = (Get-DistributionGroupMember $DL ).name 
                            FOREACH($Member in $Members) {            
            Remove-DistributionGroupMember -Identity $DL -Member $Member -Confirm:$false -ErrorAction SilentlyContinue 
                }
            $TextBox_Output.AppendText("All Members removed from $DL Group") 
            
            } ELSE { Write-Cancelled } 
 
        } CATCH { Write-OutError }
    }
}

# Sets managed by for distribution group 
# See details see https://docs.microsoft.com/en-us/powershell/module/exchange/set-distributiongroup?view=exchange-ps
function Set_DL_Manger {    
    
    IF ($ComboBox_Distributionlist.SelectedItem -eq $null) {
        Set-Output_DistributionlistNull
    } ELSE {

    $DL = $ComboBox_Distributionlist.SelectedItem.ToString()
    TRY {
            Clear-Output  
            $Manage = $Exchange_Mailboxes | Out-GridView  -Title "Select Member to Manage $DL" -PassThru 
            Set-DistributionGroup -Identity $DL -ManagedBy $Manage -ErrorAction stop
            $TextBox_Output.AppendText("$Manage can now Modify $DL Group") 
      
        } CATCH { Write-OutError }
    }
}

# Sets distribution list to hidden from global address list or makes invisible if hidden
function Set-Dl_ToHidden {    
    
    IF ($ComboBox_Distributionlist.SelectedItem -eq $null) {
        Set-Output_DistributionlistNull
    } ELSE {
    TRY {
        Clear-Output
        $DL = $ComboBox_Distributionlist.SelectedItem.ToString()
        $Result  = (Get-DistributionGroup $DL).HiddenFromAddressListsEnabled
            
        SWITCH ($Result) { 
            
        false { Set-DistributionGroup -Identity $DL -HiddenFromAddressListsEnabled $true ; $TextBox_Output.text = "$DL to is now hidden from global address list" }
        true { Set-DistributionGroup -Identity $DL -HiddenFromAddressListsEnabled $false ; $TextBox_Output.text = "$DL to is now visble in global address list"  }
            
            }

        } CATCH { Write-OutError }
    }
} 

#Removes distribution group 
function Remove_DL {    
    
    IF ($ComboBox_Distributionlist.SelectedItem -eq $null) {
        Set-Output_DistributionlistNull
    } ELSE {
        $DL = $ComboBox_Distributionlist.SelectedItem.ToString()
        TRY {
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("   Delete $DL Distribution list?", 0, "Remove Distribution list", 0x4 + 0x10)
    
            IF ($Answer -eq 6) {
                Clear-Output
                
                Remove-DistributionGroup -Identity $DL -Confirm:$false -ErrorAction Stop 

                $ComboBox_Distributionlist.Text = $Null
                $Script:Exchange_DistributionGroups -ne $DL
                [void]$ComboBox_Mailbox.Items.remove($DL)
                [void]$ComboBox_Mailbox.AutoCompleteCustomSource.remove($DL) 
                $TextBox_Output.text = "Distribution list $DL is now Deleted"
                Save-Exchangedata
            
            } ELSE { Write-Cancelled } 
                    
        } CATCH { Write-OutError }
    }
}


#===================== Menu Functions ======================

# Exports alist of each mailbox that has full access permissions to it and Each object that has full permissions 
function Export-FullAccessListToCSV {

    $StatusBarLabel.text = "  Export Mailbox FullAccess List to CSV..."
    $List = @()

    $SaveFile = New-Object -TypeName System.Windows.Forms.SaveFileDialog -Property @{
        Title = "Export User Accounts"
        FileName = "Mailbox FullAccess Export"
        Filter = "CSV Files (*.csv)|*.csv"
    }

    $Answer = $SaveFile.ShowDialog(); $Answer
                
        IF ( $Answer -eq "OK") {
                                                              
            Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission | Where-Object {($_.IsInherited -eq $False) -and ($_.AccessRights -like "*FullAccess*") -and -not ($_.User -like "NT AUTHORITY\SELF")} |`
            Select-Object Identity, User | Export-Csv $SaveFile.FileName -NoTypeInformation
            
            $SaveOut = $SaveFile.FileName.ToString()
            Clear-Output
            Set-StatusBarReady
            $TextBox_Output.AppendText("Exported to $SaveOut")
        } 

       ELSE {
            Clear-Output
            Set-StatusBarReady
            Write-OutInfo
            $OutputTB.AppendText("Exported canceled")
    }
    
}

# Show size of each database 
# Note that this is not 100% accurate unless the databases are dismounted and compacted 
function Get-MailboxDatabase_size {

    Get-MailboxDatabase -Status | Select Name, DatabaseSize, AvailableNewMailboxSpace | Sort-Object -Descending AvailableNewMailboxSpace

}


#region BaseFrom
#=========================================================================#
#                             Base From                                   # 
#=========================================================================#

# Base From & Shortcuts
#===========================================================

$Form = New-Object system.Windows.Forms.Form -Property @{
    ClientSize             = '1170,720'
    Text                   = "Ultimate Administrator Console"
    MinimumSize            = '1170,780'
    TopMost                = $false
    Icon                   = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command WMIC.exe).Path) 
    KeyPreview             = $true
    Opacity                = 0.99
}

# Shortcuts
<#F1#>  $Form.add_KeyDown({IF($_.keycode -eq "F1"){ Start-Process PowerShell.exe }})
<#F2#>  $Form.add_KeyDown({IF($_.keycode -eq "F2"){ Clear-Output }})
<#F3#>  $Form.add_KeyDown({IF($_.keycode -eq "F3"){ Copy-Outbox  }})
<#F4#>  $Form.add_KeyDown({IF($_.keycode -eq "F4"){ Copy-Notepad }})
<#F5#>  $Form.add_KeyDown({IF($_.keycode -eq "F5"){ Enable-ActiveDirectory }})
<#F6#>  $Form.add_KeyDown({IF($_.keycode -eq "F6"){ Enable-Exchange }})
<#F7#>  $Form.add_KeyDown({IF($_.keycode -eq "F7"){  }})
<#F8#>  $Form.add_KeyDown({IF($_.keycode -eq "F8"){  }})
<#F9#>  $Form.add_KeyDown({IF($_.keycode -eq "F9"){  }})
<#F10#> $Form.add_KeyDown({IF($_.keycode -eq "F10"){  }})
<#F11#> $Form.add_KeyDown({IF($_.keycode -eq "F11"){  }})
<#F12#> $Form.add_KeyDown({IF($_.keycode -eq "F12"){  }})


#====================== Menu Items =========================

## Objects ## 
$Menu                                    = New-Object System.Windows.Forms.MenuStrip
$Menu_File                               = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Restart                            = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_ShutDown                           = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_File_Space                         = New-Object System.Windows.Forms.ToolStripSeparator
$Menu_Exit                               = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Shell                              = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Shell_CMD                          = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Shell_PowerShell                   = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Shell_PowerShell_ISE               = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_AD                                 = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_AD_Space                           = New-Object System.Windows.Forms.ToolStripSeparator
$Menu_AD_ExportUsers                     = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_AD_ExportComputers                 = New-Object System.Windows.Forms.ToolStripMenuItem 
$Menu_AD_ExportGroups                    = New-Object System.Windows.Forms.ToolStripMenuItem 
$Menu_Exchange                           = New-Object System.Windows.Forms.ToolStripMenuItem 
$Menu_Exchange_ExportFullAccess          = New-Object System.Windows.Forms.ToolStripMenuItem 
$Menu_Help                               = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Help_Reset_PC                      = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Help_Reset_Network                 = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Help_Space                         = New-Object System.Windows.Forms.ToolStripSeparator
$Menu_Help_ShowErrors                    = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_About                              = New-Object System.Windows.Forms.ToolStripMenuItem

## text ##
$Menu_File.Text                          = "File"
$Menu_Restart.text                       = "Restart"
$Menu_ShutDown.text                      = "ShutDown"
$Menu_Exit.Text                          = "Exit"
$Menu_Shell.Text                         = "Shell"
$Menu_Shell_CMD.Text                     = "Command Prompt"
$Menu_Shell_PowerShell.Text              = "PowerShell"
$Menu_Shell_PowerShell_ISE.Text          = "ISE"
$Menu_AD.Text                            = "Active Directory"
$Menu_AD_ExportUsers.Text                = "Export Users to CSV"
$Menu_AD_ExportComputers.Text            = "Export Computers to CSV" 
$Menu_AD_ExportGroups.Text               = "Export Groups to CSV"
$Menu_Exchange.Text                      = "Exchange"
$Menu_Exchange_ExportFullAccess.text     = "Export FullAccess Permissons to CSV"
$Menu_Help.Text                          = "Help"
$Menu_Help_Reset_PC.text                 = "Reset PC"
$Menu_Help_Reset_Network.Text            = "Reset Network"
$Menu_Help_ShowErrors.text               = "Show Errors"
$Menu_About.Text                         = "About"

## Functions ##
$Menu_Restart.Add_Click({ Restart-PC })
$Menu_ShutDown.Add_Click({ Stop_PC })
$Menu_Exit.Add_Click({ $Form.close() })
$Menu_Shell_CMD.Add_click({ Start-Process CMD.exe })
$Menu_Shell_PowerShell.Add_click({ Start-Process PowerShell.exe }) 
$Menu_Shell_PowerShell_ISE.Add_click({ ISE })
$Menu_AD_ExportUsers.Add_Click({ CSVAdUserExport })
$Menu_AD_ExportComputers.Add_Click({ CSVComputerExport })
$Menu_AD_ExportGroups.Add_Click({ CSVGroupsExport })
$Menu_Exchange_ExportFullAccess.Add_Click({ Export-FullAccessListToCSV })
$Menu_Help_Reset_PC.Add_Click({ Start-Process systemreset -ArgumentList "--factoryreset" })
$Menu_Help_Reset_Network.Add_Click({ Reset-Networksettings })
$Menu_Help_ShowErrors.Add_Click({ Write-OutErrorFull })
$Menu_About.Add_Click({ Show-About })

## Disabled ## 
$Menu_AD.Enabled             = $false
$Menu_Exchange.Enabled       = $false

## Controls ##

# file
[void]$Menu_File.DropDownItems.AddRange(@(
    $Menu_Restart
    $Menu_ShutDown
    $Menu_File_Space 
    $Menu_Exit
))

# Shell
[void]$Menu_Shell.DropDownItems.AddRange(@(
    $Menu_Shell_CMD
    $Menu_Shell_PowerShell
    $Menu_Shell_PowerShell_ISE
))

# AD 
$Menu_AD.DropDownItems.AddRange(@(
    $Menu_AD_Space
    $Menu_AD_ExportUsers
    $Menu_AD_ExportComputers
    $Menu_AD_ExportGroups
))

# Exchange
$Menu_Exchange.DropDownItems.AddRange(@(
    $Menu_Exchange_ExportFullAccess

))

# Help
[void]$Menu_Help.DropDownItems.AddRange(@(
    $Menu_Help_Reset_PC
    $Menu_Help_Reset_Network 
    $Menu_Help_Space
    $Menu_Help_ShowErrors
    $Menu_About
))

#Icons
$Menu_Restart.Image                  = [System.IconExtractor]::Extract("imageres.dll", 230, $true) 
$Menu_ShutDown.Image                 = [System.IconExtractor]::Extract("Shell32.dll", 27, $true)
$Menu_Exit.Image                     = [System.IconExtractor]::Extract("imageres.dll", 84, $true)
$Menu_Shell_CMD.Image                = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command CMD.exe).Path)
$Menu_Shell_PowerShell.Image         = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command PowerShell).Path)
$Menu_Shell_PowerShell_ISE.Image     = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command PowerShell_ISE.exe).Path)
$Menu_Help_Reset_PC.Image            = [System.IconExtractor]::Extract("imageres.dll", 269, $true)
$Menu_Help_Reset_Network.Image       = [System.IconExtractor]::Extract("imageres.dll", 307, $true)
$Menu_Help_ShowErrors.Image          = [System.IconExtractor]::Extract("imageres.dll", 100, $true)
$Menu_About.Image                    = [System.IconExtractor]::Extract("Shell32.dll", 277, $true)

# Menu Range
[void]$Menu.Items.AddRange(@(
    $Menu_File
    $Menu_Shell
    $Menu_AD
    $Menu_Exchange
    $Menu_Help
))


#========================== Tabs ============================

$Tab_Control = New-object System.Windows.Forms.TabControl -Property @{
    Location = "10,40"
    Size = "430, 650"
    Appearance = 0
}

## Objects ##

$TabPage_WindowsTools    = New-Object System.Windows.Forms.TabPage
$TabPage_ControlPanel    = New-Object System.Windows.Forms.TabPage
$TabPage_AD              = New-Object System.Windows.Forms.TabPage
$TabPage_Exchange        = New-Object System.Windows.Forms.TabPage
$TabPage_365             = New-Object System.Windows.Forms.TabPage
$TabPage_Settings        = New-Object System.Windows.Forms.TabPage

## Text ## 

$TabPage_WindowsTools.Text     = "Windows"
$TabPage_ControlPanel.Text     = "Control/Net"
$TabPage_AD.Text               = "  AD"
$TabPage_Exchange.Text         = "Exchange"
$TabPage_365.Text              = "  365"
$TabPage_Settings.Text         = "Settings"

## Controls ##

$Tab_Control.Controls.AddRange(@(
    $TabPage_WindowsTools
    $TabPage_ControlPanel
    $TabPage_AD
    $TabPage_Exchange
   #$TabPage_365
    $TabPage_Settings
))


#endregion BaseFrom

#region 

#=========================================================================#
#                          Windows Tools UI                               # 
#=========================================================================#

# Windows Tools - GroupBox
#===========================================================

$GroupBox_Windows = New-Object System.Windows.Forms.GroupBox -Property @{
    Location            = "5,10"
    Size                = "409, 300"
    Text                = "Windows Tools"
}

$ListBox_Windows = New-Object System.Windows.Forms.ListBox -Property @{
    name                = "ListBox_windows"
    Location            = "7, 14"
    Size                = "394,240"
    BorderStyle         = 0
    HorizontalScrollbar = 1
}

$ListBox_Windows.Items.AddRange(@(
    "Backup Credentials"
    "Clean Disk Manager"
    "DirectX Diagnostic Tool"
    "Disk Manager"
    "Device Management"
    "Default Apps"
    "Event Viewer"
    "Enable Ultimate Performance"
    "Firewall"
    "Internet Properties"
    "Invoke Group policy update"
    "Network Properties"
    "Optional Features"
    "RegisTRY Editor"
    "Reliability Monitor"
    "Remote Desktop"
    "Services"
    "Start Windows Defender Offline Scan"
    "System Information" 
    "System Configuration Utility"
    "System Properties"
    "Task Manager"
    "Task Scheduler"
    "Windows Version"
    "Windows Update"
))

# Buttions
$Button_GetComputerinfo = New-Object System.Windows.Forms.Button -Property @{
    Location        = "5,255"
    Size            = "50,37"
    #Text            = "Computer info"
    FlatStyle       = "Flat"
}

$Button_GetSysteminfo = New-Object System.Windows.Forms.Button -Property @{
    Location        = "55,255"
    Size            = "50,37"
    #Text            = "System info"
    FlatStyle       = "Flat"
}

$Button_Ipconfiginfo = New-Object System.Windows.Forms.Button -Property @{
    Location        = "105,255"
    Size            = "50,37"
    #Text            = "Ipconfig info"
    FlatStyle       = "Flat"
}

$Button_Get_wIFiPassword = New-Object System.Windows.Forms.Button -Property @{
    Location        = "155,255"
    Size            = "50,37"
    #Text            = "Get_wIFiPassword"
    FlatStyle       = "Flat"
}

$Button_TextToWave = New-Object System.Windows.Forms.Button -Property @{
    Location        = "205,255"
    Size            = "50,37"
    #Text            = "TextToWave"
    FlatStyle       = "Flat"
}

$Button_Get_FolderACL = New-Object System.Windows.Forms.Button -Property @{
    Location        = "255,255"
    Size            = "50,37"
    #Text            = "Get_FolderACL"
    FlatStyle       = "Flat"
}

$Button_WindowsAction = New-Object System.Windows.Forms.Button -Property @{
    Location         = "350,255"
    Size             = "50,37"
    FlatStyle        = "Flat"
}

# Button Icons & Appearance
$Button_GetComputerinfo.FlatAppearance.BorderSize = 0
$Button_GetSysteminfo.FlatAppearance.BorderSize = 0
$Button_Ipconfiginfo.FlatAppearance.BorderSize = 0
$Button_Get_wIFiPassword.FlatAppearance.BorderSize = 0
$Button_TextToWave.FlatAppearance.BorderSize = 0
$Button_Get_FolderACL.FlatAppearance.BorderSize = 0
$Button_WindowsAction.FlatAppearance.BorderSize = 0
$Button_GetComputerinfo.Image = [System.IconExtractor]::Extract("Imageres.dll", 70, $true)
$Button_GetSysteminfo.Image = [System.IconExtractor]::Extract("Imageres.dll", 143, $true)
$Button_Ipconfiginfo.Image = [System.IconExtractor]::Extract("Shell32.dll", 18, $true)
$Button_Get_wIFiPassword.Image = [System.IconExtractor]::Extract("Imageres.dll", 330, $true)
$Button_TextToWave.Image = [System.IconExtractor]::Extract("Shell32.dll", 172, $true)
$Button_Get_FolderACL.Image = [System.IconExtractor]::Extract("Shell32.dll", 158, $true)
$Button_WindowsAction.Image = $Icon_OK

# ToolTips
$Tooltip_GetComputerinfo              = New-Object System.Windows.Forms.ToolTip
$Tooltip_GetSysteminfo                = New-Object System.Windows.Forms.ToolTip
$tooltip_Ipconfiginfo                 = New-Object System.Windows.Forms.ToolTip
$tooltip_Get_wIFiPassword             = New-Object System.Windows.Forms.ToolTip 
$Tooltip_TextToWave                   = New-Object System.Windows.Forms.ToolTip
$Tooltip_Get_FolderACL                = New-Object System.Windows.Forms.ToolTip
$Tooltip_WindowsAction                = New-Object System.Windows.Forms.ToolTip

$Tooltip_GetComputerinfo.SetToolTip($Button_GetComputerinfo, "Show Computer info")
$Tooltip_GetSysteminfo.SetToolTip($Button_GetSysteminfo, "Show System info")
$Tooltip_Ipconfiginfo.SetToolTip($Button_Ipconfiginfo, "Show IP config")
$tooltip_Get_wIFiPassword.SetToolTip($Button_Get_wIFiPassword, "Show WIFi Passwords")
$Tooltip_TextToWave.SetToolTip($Button_TextToWave, "Open TextToWave")
$Tooltip_Get_FolderACL.SetToolTip($Button_Get_FolderACL, "Open GetFolderACL")
$Tooltip_WindowsAction.SetToolTip($Button_WindowsAction, "Run/Start selected option")

# Controls
$ListBox_windows.add_MouseDoubleClick({ Start-WindowsApp })
$ListBox_windows.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-WindowsApp }})
$ListBox_windows.add_KeyDown({IF($_.keycode -eq "Space"){ Start-WindowsApp }})
$Button_GetSysteminfo.add_Click({ Get-SystemInfo_Output })
$Button_GetComputerinfo.add_Click({ Get-ComputerInfo_Output })
$Button_Ipconfiginfo.add_Click({ Get-IpconfigInfo_Output })
$Button_Get_wIFiPassword.add_Click({ Get-WIFiPassword })
$Button_TextToWave.add_Click({ Start-TexttoWave })
$Button_Get_FolderACL.add_Click({ Start-GetFolderACL })
$Button_WindowsAction.add_Click({ Start-WindowsApp })

$GroupBox_Windows.Controls.AddRange(@(
    $ListBox_windows
    $Button_GetComputerinfo 
    $Button_GetSysteminfo
    $Button_Get_wIFiPassword
    $Button_Ipconfiginfo
    $Button_TextToWave
    $Button_Get_FolderACL
    $Button_WindowsAction
)) 


# Windows Server Tools - GroupBox
#===========================================================

$GroupBox_WindowServer = New-Object System.Windows.Forms.GroupBox -Property @{
    Location               = "5,325"
    Size                   = "409, 290"
    Text                   = "Windows Server Tools"
}

$ListBox_WindowServer = New-Object System.Windows.Forms.ListBox -Property @{
    Location                = "7, 14"
    Size                    = "394,230"
    BorderStyle             = 0
    HorizontalScrollbar     = 1   
    #Enabled                 = $false 
}

# Add Items to listbox
FOREACH($Tool in $Admin_Tools.BaseName){[void]$ListBox_WindowServer.Items.Add($Tool)}


$Button_InstallRsat = New-Object System.Windows.Forms.Button -Property @{
    Location            = "5,245"
    Size                = "50,37"
    #Text               = "Install RSAT"
    FlatStyle           = "Flat"
}

$Button_WindowServerAction = New-Object System.Windows.Forms.Button -Property @{
    Location            = "350,245"
    Size                = "50,37"
    FlatStyle           = "Flat"
    #Enabled             =  $false
}

# Button Icons & Appearance
$Button_WindowServerAction.FlatAppearance.BorderSize = 0
$Button_InstallRsat.FlatAppearance.BorderSize = 0
$Button_WindowServerAction.Image = $Icon_OK
$Button_InstallRsat.Image = [System.IconExtractor]::Extract("Shell32.dll", 71, $true)

# ToolTips
$Tooltip_InstallRsat                = New-Object System.Windows.Forms.ToolTip
$Tooltip_WindowServerAction         = New-Object System.Windows.Forms.ToolTip

$Tooltip_InstallRsat.SetToolTip($Button_InstallRsat , "Install RSAT")
$Tooltip_WindowServerAction.SetToolTip($Button_WindowServerAction, "Run/Start selected option")

# Controls
$Button_InstallRsat.add_Click({ Add-AllRsatTools })
$ListBox_WindowServer.add_MouseDoubleClick({ start_windowAdminapp })
$ListBox_WindowServer.add_KeyDown({IF($_.keycode -eq "Enter"){ start_windowAdminapp }})
$ListBox_WindowServer.add_KeyDown({IF($_.keycode -eq "Space"){ start_windowAdminapp }})
$Button_WindowServerAction.add_Click({ start_windowAdminapp })

$GroupBox_WindowServer.Controls.AddRange(@(
    $ListBox_WindowServer
    $Button_InstallRsat
    $Button_WindowServerAction
))

#TabPage Windows Tools - Control AddRange
#===========================================================


$TabPage_WindowsTools.Controls.AddRange(@(
    $GroupBox_Windows
    $GroupBox_WindowServer
    $GroupBox_FolderPermissions
))

#=========================================================================#
#                          Control Panel UI                               # 
#=========================================================================#


# Control Panel - GroupBox
#===========================================================

$GroupBox_ControlPanel = New-Object System.Windows.Forms.GroupBox -Property @{
    Location           = "5,10"
    Size               = "409, 500"
    Text               = "Control Panel items"
}

$ListBox_ControlPanel = New-Object System.Windows.Forms.ListBox -Property @{
    name                = "ListBox_windows"
    Location            = "7, 14"
    Size                = "394,440"
    BorderStyle         = 0
    HorizontalScrollbar = 1
}

$ControlPanelItem = (Get-ControlPanelItem).Name | Sort-Object
FOREACH($Item in $ControlPanelItem) {$ListBox_ControlPanel.Items.AddRange($Item)} 

$Button_Godmode = New-Object System.Windows.Forms.Button -Property @{
    Location       = "5,450"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_Re_startService = New-Object System.Windows.Forms.Button -Property @{
    Location       = "55,450"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_StopService = New-Object System.Windows.Forms.Button -Property @{
    Location       = "105,450"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_StopProcess = New-Object System.Windows.Forms.Button -Property @{
    Location       = "155,450"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_ControlPanel = New-Object System.Windows.Forms.Button -Property @{
    Location        = "350,450"
    Size            = "50,37"
    FlatStyle       = "Flat"
}

# Button Icons & Appearance
$Button_Godmode.FlatAppearance.BorderSize = 0
$Button_Re_startService.FlatAppearance.BorderSize = 0
$Button_StopService.FlatAppearance.BorderSize = 0
$Button_StopProcess.FlatAppearance.BorderSize = 0
$Button_ControlPanel.FlatAppearance.BorderSize = 0
$Button_Godmode.Image = [System.IconExtractor]::Extract("Shell32.dll", 21, $true)
$Button_Re_startService.Image = [System.IconExtractor]::Extract("imageres.dll", 279, $true)
$Button_StopService.Image = [System.IconExtractor]::Extract("Shell32.dll", 152, $true)
$Button_StopProcess.Image = [System.IconExtractor]::Extract("imageres.dll", 322, $true)
$Button_ControlPanel.Image = $Icon_OK

# ToolTips
$Tooltip_Godmode                = New-Object System.Windows.Forms.ToolTip
$Tooltip_Re_startService        = New-Object System.Windows.Forms.ToolTip
$tooltip_StopService            = New-Object System.Windows.Forms.ToolTip
$tooltip_StopProcess            = New-Object System.Windows.Forms.ToolTip 
$Tooltip_ControlPanel           = New-Object System.Windows.Forms.ToolTip

$Tooltip_Godmode.SetToolTip($Button_Godmode, "Show Godmode settings")
$Tooltip_Re_startService.SetToolTip($Button_Re_startService, "(Re)start Service")
$tooltip_StopService.SetToolTip($Button_StopService, "Stop Service")
$tooltip_StopProcess.SetToolTip($Button_StopProcess, "Stop Process")
$Tooltip_ControlPanel.SetToolTip($Button_ControlPanel, "Run/Start selected option")

# Controls
$ListBox_ControlPanel.add_MouseDoubleClick({ Start-ControlPanelItem })
$ListBox_ControlPanel.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-ControlPanelItem }})
$ListBox_ControlPanel.add_KeyDown({IF($_.keycode -eq "Space"){ Start-ControlPanelItem }})
$Button_Godmode.add_Click({ Godmode })
$Button_Re_startService.add_Click({ Restart-LocalService })
$Button_StopService.add_Click({ Stop-LocalService })
$Button_StopProcess.add_Click({ Stop-LocalProcess })
$Button_ControlPanel.add_Click({ Start-ControlPanelItem })

$GroupBox_ControlPanel.Controls.AddRange(@(
    $ListBox_ControlPanel
    $Button_Godmode 
    $Button_Re_startService
    $Button_StopService 
    $Button_StopProcess
    $Button_ControlPanel
)) 

$TabPage_ControlPanel.Controls.AddRange(@(
    $GroupBox_ControlPanel
))


#endregion Windows

#region Network tools
#=========================================================================#
#                          Network Tools UI                               # 
#=========================================================================#

$GroupBox_Net = New-Object System.Windows.Forms.GroupBox -Property @{
    Location           = "5,525"
    Size               = "409, 90"
    Text               = "Network tools - enter IP/URI"
}

$Textbox_Nettools = New-Object System.Windows.Forms.TextBox -Property @{
    Location        = "7, 15"
    Width           = 390
}


# Buttions
$Button_NetPing = New-Object System.Windows.Forms.Button -Property @{
    Location        = "5,40"
    Size            = "50,37"
    FlatStyle       = "Flat"
}

$Button_NetTraceRoute = New-Object System.Windows.Forms.Button -Property @{
    Location        = "55,40"
    Size            = "50,37"
    FlatStyle       = "Flat"
}

$Button_NetNSlookup = New-Object System.Windows.Forms.Button -Property @{
    Location        = "105,40"
    Size            = "50,37"
    FlatStyle       = "Flat"
}

# Button Icons & Appearance
$Button_NetPing.FlatAppearance.BorderSize = 0
$Button_NetTraceRoute.FlatAppearance.BorderSize = 0
$Button_NetNSlookup.FlatAppearance.BorderSize = 0

$Button_NetPing.Image = [System.IconExtractor]::Extract("Shell32.dll", 164, $true)
$Button_NetTraceRoute.Image = [System.IconExtractor]::Extract("Shell32.dll", 167, $true)
$Button_NetNSlookup.Image = [System.IconExtractor]::Extract("Shell32.dll", 135, $true)

# ToolTips
$Tooltip_NetPing               = New-Object System.Windows.Forms.ToolTip
$Tooltip_NetTraceRoute         = New-Object System.Windows.Forms.ToolTip
$tooltip_NetNSlookup           = New-Object System.Windows.Forms.ToolTip

$Tooltip_NetPing.SetToolTip($Button_NetPing, "Test connection")
$Tooltip_NetTraceRoute.SetToolTip($Button_NetTraceRoute, "Start TraceRoute")
$Tooltip_NetNSlookup.SetToolTip($Button_NetNSlookup, "Resolve DNS")

# Controls
$Button_NetPing.add_Click({ Start-Ping })
$Button_NetTraceRoute.add_Click({ Start-TraceRoute })
$Button_NetNSlookup.add_Click({ Get-nslookup })

$GroupBox_Net.Controls.AddRange(@(
    $Textbox_Nettools
    $Button_NetPing 
    $Button_NetTraceRoute
    $Button_NetNSlookup
))

$TabPage_ControlPanel.Controls.AddRange(@(
    $GroupBox_Net
))

#endregion Network tools

#region Active Directory

#=========================================================================#
#                          Active Directory UI                            # 
#=========================================================================#

## TabPage AD ##
##===================================================================================================##

$Panel_ActiveDirectory = New-Object System.Windows.Forms.Panel -Property @{
    Location           = "0,0"
    Size               = "430, 580"
    Enabled            = $false
}

# User accounts GroupBox 
#===========================================================

$GroupBox_Users = New-Object System.Windows.Forms.GroupBox -Property @{
    Location            = "5,10"
    Size                = "409, 212"
    Text                = "Select Account"
}

$ComboBox_Users = New-Object System.Windows.Forms.ComboBox -Property @{
    Location            = "7, 14"
    DropDownStyle       = "DropDown"
    Width               = 394
    FlatStyle           = 'flat'
}

$ListBox_Users = New-Object System.Windows.Forms.ListBox -Property @{
    Name                = "ListBox_Users"
    Location            = "7, 38"
    Size                = "394,130"
    BorderStyle         = 0
    HorizontalScrollbar = 1    
}

$ListBox_Users.Items.AddRange(@(

    "Account info"
    "List all groups"
    "Set password to never expire"
    "Set password to cannot be change"
    "Add to Group"
    "Copy all Groups from another Account"
    "Remove Groups" 
    "Remove All Groups" 
    "Move OU"
    "Remove Account"
))

# Buttons
$Button_NewUser = New-Object System.Windows.Forms.Button -Property @{
    Location       = "5,170"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_Unlock = New-Object System.Windows.Forms.Button -Property @{
    Location       = "55,170"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_Resetpassword = New-Object System.Windows.Forms.Button -Property @{
    Location       = "105,170"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_DisableUser = New-Object System.Windows.Forms.Button -Property @{
    Location       = "155,170"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_UserAction = New-Object System.Windows.Forms.Button -Property @{
    Location        = "350,170"
    Size            = "45,37"
    FlatStyle       = "Flat"
}

# Button Icons & Appearance
$Button_NewUser.FlatAppearance.BorderSize = 0
$Button_Unlock.FlatAppearance.BorderSize = 0
$Button_Resetpassword.FlatAppearance.BorderSize = 0
$Button_DisableUser.FlatAppearance.BorderSize = 0
$Button_UserAction.FlatAppearance.BorderSize = 0
$Button_NewUser.Image = [System.IconExtractor]::Extract("imageres.dll", 295, $true)
$Button_Unlock.Image = [System.IconExtractor]::Extract("imageres.dll", 54, $true)
$Button_Resetpassword.Image = [System.IconExtractor]::Extract("imageres.dll", 299, $true)
$Button_DisableUser.Image = [System.IconExtractor]::Extract("imageres.dll", 308, $true)
$Button_UserAction.Image = $Icon_OK

# ToolTips
$Tooltip_NewUser             = New-Object System.Windows.Forms.ToolTip
$Tooltip_Unlock              = New-Object System.Windows.Forms.ToolTip
$Tooltip_Resetpassword       = New-Object System.Windows.Forms.ToolTip
$Tooltip_DisableUser         = New-Object System.Windows.Forms.ToolTip
$Tooltip_UserAction          = New-Object System.Windows.Forms.ToolTip

$Tooltip_NewUser.SetToolTip($Button_NewUser, "New User")
$Tooltip_Unlock.SetToolTip($Button_Unlock, "Unlock/Lock account")
$Tooltip_Resetpassword.SetToolTip($Button_Resetpassword, "Reset Password")      
$Tooltip_DisableUser.SetToolTip($Button_DisableUser, "Disable/Enable account")
$Tooltip_UserAction.SetToolTip($Button_UserAction, "Run/Start selected option")

# Controls
$ComboBox_Users.add_TextChanged({ Get-AD_UserFullInfo })
$ListBox_Users.add_MouseDoubleClick({ Start-AD_UserFunction })
$ListBox_Users.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-AD_UserFunction }})
$ListBox_Users.add_KeyDown({IF($_.keycode -eq "Space"){ Start-AD_UserFunction }})
$Button_NewUser.add_Click({ New-UserUI })
$Button_Unlock.add_Click({ Set-AD_UserUnlockAccount })
$Button_Resetpassword.add_Click({ Set-AD_UserPasswordReset })
$Button_DisableUser.add_Click({ Set-AD_UserDisableOrEnable })
$Button_UserAction.add_Click({ Start-AD_UserFunction })

$GroupBox_Users.Controls.AddRange(@( 
    $ComboBox_Users
    $ListBox_Users
    $Button_NewUser
    $Button_Unlock
    $Button_Resetpassword 
    $Button_DisableUser
    $Button_UserAction
))

# CPU GroupBox
#===========================================================

$GroupBox_Computers = New-Object System.Windows.Forms.GroupBox -Property @{
    Location            = "5,230"
    Size                = "409, 202"
    Text                = "Select Computer"
}

$ComboBox_Computers = New-Object System.Windows.Forms.ComboBox -Property @{
    Location            = "7, 14"
    Width               = 394
    DropDownStyle       = "DropDown"
    FlatStyle           = 'flat'
}

$ListBox_Computers = New-Object System.Windows.Forms.ListBox -Property @{
    Name                = "ListBox_Computers"
    Location            = "7, 38"
    Size                = "394,120"
    BorderStyle         = 0
    HorizontalScrollbar = 1    
}

$ListBox_Computers.Items.AddRange(@(

    "Computer info"          
    "List all Groups"
    "Remote Desktop"
    "Event Viewer"
    "Computer Management" 
    "Add to Group"        
    "Copy all Groups from another Account" 
    "Remove Group"                         
    "Remove All Groups"                    
    "Move OU"                              
    "Remove Account"                       
    "Update Group policy"                  
    "Restart PC"                           
))

# Buttons
$Button_ADSysteminfo = New-Object System.Windows.Forms.Button -Property @{
    Location       = "5,160"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_ADping = New-Object System.Windows.Forms.Button -Property @{
    Location       = "55,160"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_ADTraceRoute = New-Object System.Windows.Forms.Button -Property @{
    Location        = "105,160"
    Size            = "50,37"
    FlatStyle       = "Flat"
}

$Button_ADNSlookup = New-Object System.Windows.Forms.Button -Property @{
    Location        = "155,160"
    Size            = "50,37"
    FlatStyle       = "Flat"
}

$Button_ADRestartService = New-Object System.Windows.Forms.Button -Property @{
    Location       = "205,160"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_ADStopService = New-Object System.Windows.Forms.Button -Property @{
    Location       = "255,160"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_ADStopProcess = New-Object System.Windows.Forms.Button -Property @{
    Location       = "305,160"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_ComputerAction =  New-Object System.Windows.Forms.Button -Property @{
    Location    = "350,160"
    Size        = "50,37"
    FlatStyle   = "Flat"
}

# Button Icons & Appearance
$Button_ADSysteminfo.FlatAppearance.BorderSize = 0 
$Button_ADping.FlatAppearance.BorderSize = 0 
$Button_ADTraceRoute.FlatAppearance.BorderSize = 0
$Button_ADNSlookup.FlatAppearance.BorderSize = 0
$Button_ADRestartService.FlatAppearance.BorderSize = 0
$Button_ADStopService.FlatAppearance.BorderSize = 0 
$Button_ADStopProcess.FlatAppearance.BorderSize = 0
$Button_ComputerAction.FlatAppearance.BorderSize = 0
$Button_ADSysteminfo.Image = [System.IconExtractor]::Extract("Imageres.dll", 143, $true)
$Button_ADping.Image = [System.IconExtractor]::Extract("Shell32.dll", 164, $true)
$Button_ADTraceRoute.Image = [System.IconExtractor]::Extract("Shell32.dll", 167, $true)
$Button_ADNSlookup.Image = [System.IconExtractor]::Extract("Shell32.dll", 135, $true)
$Button_ADRestartService.Image = [System.IconExtractor]::Extract("imageres.dll", 279, $true)
$Button_ADStopService.Image = [System.IconExtractor]::Extract("Shell32.dll", 152, $true)
$Button_ADStopProcess.Image = [System.IconExtractor]::Extract("imageres.dll", 322, $true)
$Button_ComputerAction.Image = $Icon_OK

# ToolTips
$Tooltip_ADSysteminfo          = New-Object System.Windows.Forms.ToolTip
$Tooltip_ADping                = New-Object System.Windows.Forms.ToolTip 
$Tooltip_ADTraceRoute          = New-Object System.Windows.Forms.ToolTip
$Tooltip_ADNSlookup            = New-Object System.Windows.Forms.ToolTip
$Tooltip_ADRestartService      = New-Object System.Windows.Forms.ToolTip
$Tooltip_ADStopService         = New-Object System.Windows.Forms.ToolTip
$Tooltip_ADStopProcess         = New-Object System.Windows.Forms.ToolTip
$Tooltip_ComputerAction        = New-Object System.Windows.Forms.ToolTip

$Tooltip_ADSysteminfo.SetToolTip($Button_ADSysteminfo, "System info")
$Tooltip_ADping.SetToolTip($Button_ADping, "Ping computer")
$Tooltip_ADTraceRoute.SetToolTip($Button_ADTraceRoute, "Trace Route")
$Tooltip_ADNSlookup.SetToolTip($Button_ADNSlookup, "NSlookup")
$Tooltip_ADRestartService.SetToolTip($Button_ADRestartService, "(Re)start Service")
$Tooltip_ADStopService.SetToolTip($Button_ADStopService, "Stop Service")
$Tooltip_ADStopProcess.SetToolTip($Button_ADStopProcess, "Stop Process")
$Tooltip_ComputerAction.SetToolTip($Button_ComputerAction, "Run/Start selected option")

# controls
$Button_ADSysteminfo.add_Click({ Get-AD_systemInfo }) 
$Button_ADping.add_Click({ Start-AD_ComputerPing })
$Button_ADTraceRoute.add_Click({ Start-AD_TraceRoute })
$Button_ADNSlookup.add_Click({ Get-AD_nslookup })
$Button_ADRestartService.add_Click({ Restart-AD_Service })
$Button_ADStopService.add_Click({ Stop_AD_Service })
$Button_ADStopProcess.add_Click({ Stop_AD_Process })
$ComboBox_Computers.add_TextChanged({ Get-AD_ComputerFullInfo })
$ListBox_Computers.add_MouseDoubleClick({ Start-AD_ComputerFunction })
$ListBox_Computers.add_KeyDown({IF($_.keycode -eq "Enter"){  Start-AD_ComputerFunction }})
$ListBox_Computers.add_KeyDown({IF($_.keycode -eq "Space"){  Start-AD_ComputerFunction }})
$Button_ComputerAction.add_Click({ Start-AD_ComputerFunction })


$GroupBox_Computers.Controls.AddRange(@(
    $ComboBox_Computers
    $ListBox_Computers  
    $Button_ADSysteminfo 
    $Button_ADping 
    $Button_ADTraceRoute
    $Button_ADNSlookup
    $Button_ADRestartService
    $Button_ADStopService 
    $Button_ADStopProcess
    $Button_ComputerAction
))


# Group GroupBox
#===========================================================


$GroupBox_Groups = New-Object System.Windows.Forms.GroupBox -Property @{
    Location           = "5,435"
    Size               = "409, 145"
    Text               = "Select a Group"
}

$ComboBox_Groups = New-Object System.Windows.Forms.ComboBox -Property @{
    location           = "7, 14"
    Width              = 394
    DropDownStyle      = "DropDown"
    FlatStyle          = 'flat'
}

$ListBox_Groups = New-Object System.Windows.Forms.ListBox -Property @{
    Name                = "ListBox_Groups"
    Location            = "7, 38"
    Size                = "394,72"
    BorderStyle         = 0
    HorizontalScrollbar = 1    
}

$ListBox_Groups.Items.AddRange(@(
    "Group info"
    "List Members"
    "Add User"
    "Add Computer"
    "Add Group"
    "Remove Members"
    "Move OU" 
    "Remove Group"
))

# Buttons
$Button_NewGroup = New-Object System.Windows.Forms.Button -Property @{
    Location    = "5,100"
    Size        = "50,37"
    FlatStyle   = "Flat"
}

$Button_GroupAction = New-Object System.Windows.Forms.Button -Property @{
    Location    = "350,100"
    Size        = "50,37"
    FlatStyle   = "Flat"
}

# Button Icons & Appearance
$Button_NewGroup.FlatAppearance.BorderSize = 0
$Button_GroupAction.FlatAppearance.BorderSize = 0
$Button_NewGroup.Image = [System.IconExtractor]::Extract("imageres.dll", 295, $true)
$Button_GroupAction.Image = $Icon_OK

# ToolTips
$Tooltip_NewGroup         = New-Object System.Windows.Forms.ToolTip
$Tooltip_GroupAction      = New-Object System.Windows.Forms.ToolTip 

$Tooltip_NewGroup.SetToolTip($Button_NewGroup, "New Group")
$Tooltip_GroupAction.SetToolTip($Button_GroupAction, "Run/Start selected option")

# controls
$ComboBox_Groups.add_TextChanged({ GroupInfo })
$ListBox_Groups.add_MouseDoubleClick({ Start-AD_GroupFunction })
$ListBox_Groups.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-AD_GroupFunction }})
$ListBox_Groups.add_KeyDown({IF($_.keycode -eq "Space"){ Start-AD_GroupFunction }})
$Button_NewGroup.add_Click({ New-GroupUI })
$Button_GroupAction.add_Click({ Start-AD_GroupFunction })

$GroupBox_Groups.Controls.AddRange(@(
    $ListBox_Groups  
    $ComboBox_Groups 
    $Button_NewGroup
    $Button_GroupAction
))


# TabPage AD - Control AddRange
#===========================================================

$Button_ActiveDirectory_StartButtion = New-Object System.Windows.Forms.Button -Property @{
    Name        = "Button_ActiveDirectory_StartButtion"
    Location    = "5, 585"
    Size        = "410,30"
    Text        = "Enable Active Directory"
}

$Button_ActiveDirectory_StartButtion.add_Click({ Enable-ActiveDirectory })

$TabPage_AD.Controls.AddRange(@(
    $Panel_ActiveDirectory
    $Button_ActiveDirectory_StartButtion
))


$Panel_ActiveDirectory.Controls.AddRange(@(
    $GroupBox_Users
    $GroupBox_Computers
    $GroupBox_Groups
))

#endregion Active Directory


#region Exchange
#=========================================================================#
#                            Exchange                                     # 
#=========================================================================#

$Panel_Exchange = New-Object System.Windows.Forms.Panel -Property @{
    Location            = "0,0"
    Size                = "430, 530"
    Enabled             = $false
}

# Mailbox GroupBox
#===========================================================

$GroupBox_Mailbox = New-Object System.Windows.Forms.GroupBox -Property @{
    Location            = "5,10"
    Size                = "409, 302"
    Text                = "Select Mailbox"
}

$ComboBox_Mailbox = New-Object System.Windows.Forms.ComboBox -Property @{
    Location            = "7, 14"
    DropDownStyle       = "DropDown"
    Width               = 394
    FlatStyle           = 'flat'
}

$ListBox_Mailbox = New-Object System.Windows.Forms.ListBox -Property @{
    Location            = "7, 42"
    Size                = "394,215"
    BorderStyle         = 0
    HorizontalScrollbar = 1    
}


$ListBox_Mailbox.Items.AddRange(@(
    "Mailbox info"              
    "Get Mailbox size"                                                         
    "List all permissions"                              
    "Add full access permissions to mailbox"            
    "Add send as permissions"                           
    "Add send on behalf of permissions"                 
    "Remove full access permissions"                                
    "Remove all full access permissions"
    "Enable/Disable Activesync"
    "Enable/Disable OWA access"
    "Set out of office message"                         
    "Set mail forwarding"                               
    "Convert to ..."                                    
    "Hide/un-hide form global address list"             
    "Move to Database"                                  
    "Export to .PST"              
    "Remove mailbox"                                    
))

# Buttons
$Button_EnableMailBox = New-Object System.Windows.Forms.Button -Property @{
    Location       = "5,260"
    Size           = "50,37"
    FlatStyle      = "Flat"
}

$Button_MailboxAction = New-Object System.Windows.Forms.Button -Property @{
    Location    = "350,260"
    Size        = "50,37"
    FlatStyle   = "Flat"
}

# Button Icons & Appearance
$Button_EnableMailBox.FlatAppearance.BorderSize = 0
$Button_MailboxAction.FlatAppearance.BorderSize = 0
$Button_EnableMailBox.Image = [System.IconExtractor]::Extract("Shell32.dll", 156, $true)
$Button_MailboxAction.Image = $Icon_OK

# ToolTips
$Tooltip_EnableMailBox    = New-Object System.Windows.Forms.ToolTip
$Tooltip_MailboxAction    = New-Object System.Windows.Forms.ToolTip 

$Tooltip_EnableMailBox.SetToolTip($Button_EnableMailBox, "Enable Mailbox")
$Tooltip_MailboxAction.SetToolTip($Button_MailboxAction, "Run/Start selected option")

# controls
$ComboBox_Mailbox.add_TextChanged({ Get-MailBox_info })
$ListBox_Mailbox.add_MouseDoubleClick({ Start-Mailbox_Action })
$ListBox_Mailbox.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-Mailbox_Action  }})
$ListBox_Mailbox.add_KeyDown({IF($_.keycode -eq "Space"){ Start-Mailbox_Action  }})
$Button_EnableMailBox.add_Click({ Enable-Mailbox_foruser })
$Button_MailboxAction.add_Click({ Start-Mailbox_Action })

$GroupBox_Mailbox.Controls.AddRange(@(
    
    $ComboBox_Mailbox
    $ListBox_Mailbox
    $Button_EnableMailBox
    $Button_MailboxAction

))

# Distribution list GroupBox
#===========================================================

$GroupBox_Distributionlist = New-Object System.Windows.Forms.GroupBox -Property @{
    Location        = "5,320"
    Size            = "409, 192"
    Text            = "Select Distribution list"
}

$ComboBox_Distributionlist = New-Object System.Windows.Forms.ComboBox -Property @{
    Location         = "7, 14"
    DropDownStyle    = "DropDown"
    Width            = 394
    FlatStyle        = 'flat'
}

$ListBox_Distributionlist = New-Object System.Windows.Forms.ListBox -Property @{
    Location            = "7, 42"
    Size                = "394,105"
    BorderStyle         = 0
    HorizontalScrollbar = 1    
}


$ListBox_Distributionlist.Items.AddRange(@(

    "Distribution Group info"
    "List all members"
    "Add members"
    "Copy members"
    "Remove members"
    "Remove all members"
    "Set Owner"
    "Hide/un-hide form global address list"
    "Remove Distribution Group"     

))

# Buttons
$Button_NewDistributionlist = New-Object System.Windows.Forms.Button -Property @{
    Location       = "5,150"
    Size           = "50,37"
    FlatStyle      = "Flat"
}


$Button_DistributionlistAction = New-Object System.Windows.Forms.Button -Property @{
    Location  = "350,150"
    Size      = "50,37"
    FlatStyle = "Flat"
}


# Button Icons & Appearance
$Button_NewDistributionlist.FlatAppearance.BorderSize = 0
$Button_NewDistributionlist.Image = [System.IconExtractor]::Extract("Shell32.dll", 264, $true)


$Button_DistributionlistAction.FlatAppearance.BorderSize = 0
$Button_DistributionlistAction.Image = $Icon_OK

# ToolTips
$Tooltip_NewDistributionlist       = New-Object System.Windows.Forms.ToolTip
$Tooltip_DistributionlistAction    = New-Object System.Windows.Forms.ToolTip 

$Tooltip_EnableMailBox.SetToolTip($Button_NewDistributionlist, "New Distribution list")
$Tooltip_MailboxAction.SetToolTip($Button_DistributionlistAction, "Run/Start selected option")

# controls
$ComboBox_Distributionlist.add_TextChanged({ Get-DL_info  })
$ListBox_Distributionlist.add_MouseDoubleClick({ Start-Distributionlist_Action  })
$ListBox_Distributionlist.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-Distributionlist_Action }})
$ListBox_Distributionlist.add_KeyDown({IF($_.keycode -eq "Space"){ Start-Distributionlist_Action }})
$Button_NewDistributionlist.add_Click({ New-DL })
$Button_DistributionlistAction.add_Click({ Start-Distributionlist_Action })


$GroupBox_Distributionlist.Controls.AddRange(@(
    
    $Button_NewDistributionlist    
    $ComboBox_Distributionlist
    $ListBox_Distributionlist
    $Button_DistributionlistAction

))


# Connect to Exchange GroupBox
#===========================================================

$GroupBox_ConnectToExchange = New-Object System.Windows.Forms.GroupBox -Property @{
    Location        = "5,535"
    Size            = "409, 80"
    Text            = "Enter Exchange server name"
}


$Textbox_Exchange = New-Object System.Windows.Forms.TextBox -Property @{
    Location        = "7, 15"
    Width           = 390
}
$Textbox_Exchange.Text = $Exchangeserver.server 


$Button_Exchange_StartButtion = New-Object System.Windows.Forms.Button -Property @{
    Location        = "7, 40"
    Size            = "390,30"
    Text            = "Connect to Exchange server"
}

$Button_Exchange_StartButtion.add_Click({ Enable-Exchange })

$GroupBox_ConnectToExchange.Controls.AddRange(@(
    
    $Textbox_Exchange
    $Button_Exchange_StartButtion

))


$Textbox_Exchange.add_KeyDown({IF($_.keycode -eq "Enter"){ Enable-Exchange }})   

# TabPage Exchange - Control AddRange
#===========================================================


$Panel_Exchange.Controls.AddRange(@(
    $GroupBox_Mailbox
    $GroupBox_Distributionlist
))


$TabPage_Exchange.Controls.AddRange(@(
    $Panel_Exchange
    $GroupBox_ConnectToExchange 
))

#endregion Exchange


#=========================================================================#
#                            Settings                                     # 
#=========================================================================#


#============== GroupBox Opacity Settings ==================

$GroupBox_Opacity = New-Object System.Windows.Forms.GroupBox -Property @{
    Location                        = "5,10"
    Size                            = "409, 83"
    Text                            = "Opacity"
}

$TrackBar_Opacity = New-Object System.Windows.Forms.TrackBar
$TrackBar_Opacity.Orientation          = "Horizontal"
$TrackBar_Opacity.Location             = "15,35"
$TrackBar_Opacity.Size                 = "380,30"
$TrackBar_Opacity.TickStyle            = "TopLeft"
$TrackBar_Opacity.TickFrequency        = 20
$TrackBar_Opacity.SetRange(20, 99)
$TrackBar_Opacity.Value                = 99

$TrackBar_Opacity.add_ValueChanged{( Set-Opacity )}


$GroupBox_Opacity.Controls.AddRange(@(
    $TrackBar_Opacity
))


#================ GroupBox TextColour =================
$GroupBox_TextColour = New-Object System.Windows.Forms.GroupBox -Property @{
    Location                        = "5,100"
    Size                            = "409, 170"
    Text                            = "TextColour"
}

# $TrackBars
$TrackBar_TextColourRed = New-Object System.Windows.Forms.TrackBar
$TrackBar_TextColourRed.Orientation          = "Horizontal"
$TrackBar_TextColourRed.Location             = "15,35"
$TrackBar_TextColourRed.Size                 = "350,30"
$TrackBar_TextColourRed.TickStyle            = "TopLeft"
$TrackBar_TextColourRed.TickFrequency        = 51
$TrackBar_TextColourRed.SetRange(1, 255)

$TrackBar_TextColourGreen = New-Object System.Windows.Forms.TrackBar
$TrackBar_TextColourGreen.Orientation          = "Horizontal"
$TrackBar_TextColourGreen.Location             = "15,75"
$TrackBar_TextColourGreen.Size                 = "350,30"
$TrackBar_TextColourGreen.TickStyle            = "TopLeft"
$TrackBar_TextColourGreen.TickFrequency        = 51
$TrackBar_TextColourGreen.SetRange(1, 255)

$TrackBar_TextColourBlue = New-Object System.Windows.Forms.TrackBar
$TrackBar_TextColourBlue.Orientation          = "Horizontal"
$TrackBar_TextColourBlue.Location             = "15,115"
$TrackBar_TextColourBlue.Size                 = "350,30"
$TrackBar_TextColourBlue.TickStyle            = "TopLeft"
$TrackBar_TextColourBlue.TickFrequency        = 51
$TrackBar_TextColourBlue.SetRange(1, 255)


# Labels
$Label_TextColourRed = New-Object System.Windows.Forms.Label -Property @{
    Location                      = "365,40"
    Size                          = "25,25"
    Text                          = "R"
    ForeColor                     = "Red"
    Font                          = "Calibri Light,20"
}

$Label_TextColourGreen = New-Object System.Windows.Forms.Label -Property @{
    Location                      = "365,80"
    Size                          = "25,25"
    Text                          = "G"
    ForeColor                     = "Lime"
    Font                          = "Calibri Light,20"
}

$Label_TextColourBule = New-Object System.Windows.Forms.Label -Property @{
    Location                      = "365,120"
    Size                          = "25,25"
    Text                          = "B"
    Forecolor                     = "RoyalBlue"
    Font                          = "Calibri Light,20"
}

# Events 
$TrackBar_TextColourRed.add_ValueChanged{( Set-ForeColor )}
$TrackBar_TextColourGreen.add_ValueChanged{( Set-ForeColor )}
$TrackBar_TextColourBlue.add_ValueChanged{( Set-ForeColor )} 

$GroupBox_TextColour.Controls.AddRange(@(
    $TrackBar_TextColourRed
    $TrackBar_TextColourGreen 
    $TrackBar_TextColourBlue 
    $Label_TextColourRed
    $Label_TextColourGreen
    $Label_TextColourBule 
))  

#================ GroupBox BackColour =================
$GroupBox_BackColour = New-Object System.Windows.Forms.GroupBox -Property @{
    Location                        = "5,280"
    Size                            = "409, 170"
    Text                            = "BackColour"
}

# $TrackBars
$TrackBar_BackColourRed = New-Object System.Windows.Forms.TrackBar
$TrackBar_BackColourRed.Orientation          = "Horizontal"
$TrackBar_BackColourRed.Location             = "15,35"
$TrackBar_BackColourRed.Size                 = "350,30"
$TrackBar_BackColourRed.TickStyle            = "TopLeft"
$TrackBar_BackColourRed.TickFrequency        = 51
$TrackBar_BackColourRed.SetRange(1, 255)

$TrackBar_BackColourGreen = New-Object System.Windows.Forms.TrackBar
$TrackBar_BackColourGreen.Orientation          = "Horizontal"
$TrackBar_BackColourGreen.Location             = "15,75"
$TrackBar_BackColourGreen.Size                 = "350,30"
$TrackBar_BackColourGreen.TickStyle            = "TopLeft"
$TrackBar_BackColourGreen.TickFrequency        = 51
$TrackBar_BackColourGreen.SetRange(1, 255)

$TrackBar_BackColourBlue = New-Object System.Windows.Forms.TrackBar
$TrackBar_BackColourBlue.Orientation          = "Horizontal"
$TrackBar_BackColourBlue.Location             = "15,115"
$TrackBar_BackColourBlue.Size                 = "350,30"
$TrackBar_BackColourBlue.TickStyle            = "TopLeft"
$TrackBar_BackColourBlue.TickFrequency        = 51
$TrackBar_BackColourBlue.SetRange(1, 255)


# Labels
$Label_BackColourRed = New-Object System.Windows.Forms.Label -Property @{
    Location                      = "365,40"
    Size                          = "25,25"
    Text                          = "R"
    ForeColor                     = "Red"
    Font                          = "Calibri Light,20"
}

$Label_BackColourGreen = New-Object System.Windows.Forms.Label -Property @{
    Location                      = "365,80"
    Size                          = "25,25"
    Text                          = "G"
    ForeColor                     = "Lime"
    Font                          = "Calibri Light,20"
}

$Label_BackColourBule = New-Object System.Windows.Forms.Label -Property @{
    Location                      = "365,120"
    Size                          = "25,25"
    Text                          = "B"
    Forecolor                     = "RoyalBlue"
    Font                          = "Calibri Light,20"
}

# Events 
$TrackBar_BackColourRed.add_ValueChanged{( Set-BackColor  )}
$TrackBar_BackColourGreen.add_ValueChanged{( Set-BackColor  )}
$TrackBar_BackColourBlue.add_ValueChanged{( Set-BackColor )} 

$GroupBox_BackColour.Controls.AddRange(@(
    $TrackBar_BackColourRed
    $TrackBar_BackColourGreen 
    $TrackBar_BackColourBlue 
    $Label_BackColourRed
    $Label_BackColourGreen
    $Label_BackColourBule 
))  

#Button
$Button_SaveSettings = New-Object System.Windows.Forms.Button -Property @{ 
    Location                      = "5, 580"
    Size                          = "410,30"
    Text                          = "Save Settings"
    FlatStyle                     = "Flat"
}
$Button_SaveSettings.FlatAppearance.BorderSize = 0

$Button_SaveSettings.add_Click({ Save-settings })


#================ GroupBox Output Settings =================

$TabPage_Settings.Controls.AddRange(@(
    $GroupBox_Opacity
    $GroupBox_TextColour
    $GroupBox_BackColour   
    $Button_SaveSettings
))


#===================== Output GroupBox =====================

$GroupBox_Output = New-Object System.Windows.Forms.GroupBox -Property @{
    Location                        = "445,30"
    Size                            = "714, 615"
    Text                            = "Output"
    Anchor                          = "Top, Bottom, Left, Right"
    Backcolor                      = "transparent"
}

$TextBox_Output = New-Object System.Windows.Forms.RichTextBox -Property @{
    Name                            = "TextBox_Output"
    Location                        = "7, 14"
    Size                            = "700, 593"
    ScrollBars                      = "both"
    Multiline                       = $true
    WordWrap                        = $false
    Anchor                          = "Top, Bottom, Left, Right"
    Font                            = "lucida console,9"
    RightToLeft                     = "No"
    Cursor                          = "IBeam"
    BorderStyle                     = 0
    DetectUrls                      = $true
}


#=========================== Body =========================

# Buttons
$Button_OSK = New-Object System.Windows.Forms.Button -Property @{
    Name                            = "OSK"
    Location                        = "450,655"
    Size                            = "50,37"
    Anchor                          = "Bottom, Left"
    FlatStyle                       = "Flat"
    Backcolor                      = "transparent"
}

$Button_Brightness_Less = New-Object System.Windows.Forms.Button -Property @{
    Name                            = "Brightness_Less"
    Location                        = "500,655"
    Size                            = "50,37"
    Anchor                          = "Bottom, Left"
    FlatStyle                       = "Flat"
    Backcolor                      = "transparent"
}

$Button_Brightness_More = New-Object System.Windows.Forms.Button -Property @{
    Name                            = "Brightness_More"
    Location                        = "550,655"
    Size                            = "50,37"
    Anchor                          = "Bottom, Left"
    FlatStyle                       = "Flat"
    Backcolor                      = "transparent"
}

$Button_Clear = New-Object System.Windows.Forms.Button -Property @{
    Location                        = "940,655"
    Size                            = "50,37"
    Anchor                          = "Bottom, Right"
    FlatStyle                       = "Flat"
    Backcolor                      = "transparent"
}

$Button_Copy = New-Object System.Windows.Forms.Button -Property @{
    Location                       = "990,655"
    Size                           = "50,37"
    Anchor                         = "Bottom, Right"
    FlatStyle                      = "Flat"
    Backcolor                      = "transparent"
}

$Button_Cut = New-Object System.Windows.Forms.Button -Property @{
    Location                       = "1040,655"
    Size                           = "50,37"
    Anchor                         = "Bottom, Right"
    FlatStyle                      = "Flat"
    Backcolor                      = "transparent"
}

$Button_Notepad = New-Object System.Windows.Forms.Button -Property @{
    Location                       = "1090,655"
    Size                           = "50,37"
    Anchor                         = "Bottom, Right"
    FlatStyle                      = "Flat"
    Backcolor                      = "transparent"
} 

# Button Icons & Appearance
$Button_OSK.FlatAppearance.BorderSize = 0
$Button_Brightness_Less.FlatAppearance.BorderSize = 0
$Button_Brightness_More.FlatAppearance.BorderSize = 0
$Button_Clear.FlatAppearance.BorderSize = 0
$Button_Copy.FlatAppearance.BorderSize = 0
$Button_Cut.FlatAppearance.BorderSize = 0
$Button_Notepad.FlatAppearance.BorderSize = 0
$Button_Brightness_Less.Image = [System.IconExtractor]::Extract("imageres.dll", 332, $true)
$Button_Brightness_More.Image = [System.IconExtractor]::Extract("imageres.dll", 331, $true)
$Button_OSK.Image = [System.IconExtractor]::Extract("Shell32.dll", 173, $true)
$Button_Clear.Image = [System.IconExtractor]::Extract("imageres.dll", 254, $true)
$Button_Copy.Image = [System.IconExtractor]::Extract("Shell32.dll", 54, $true)
$Button_CUt.Image = [System.IconExtractor]::Extract("Shell32.dll", 259, $true)
$Button_Notepad.Image = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command notepad.exe).Path)

# ToolTips
$Tooltip_OSK                          = New-Object System.Windows.Forms.ToolTip
$Tooltip_Brightness_Less              = New-Object System.Windows.Forms.ToolTip
$Tooltip_Brightness_More              = New-Object System.Windows.Forms.ToolTip
$Tooltip_Clear                        = New-Object System.Windows.Forms.ToolTip
$Tooltip_Copy                         = New-Object System.Windows.Forms.ToolTip
$Tooltip_Cut                          = New-Object System.Windows.Forms.ToolTip
$Tooltip_Notepad                      = New-Object System.Windows.Forms.ToolTip

$Tooltip_OSK.SetToolTip($Button_OSK, "On Screen Keybroad")
$Tooltip_Brightness_Less.SetToolTip($Button_Brightness_Less, "Decrease brightness")
$Tooltip_Brightness_More.SetToolTip($Button_Brightness_More, "Increase brightness")
$Tooltip_Clear.SetToolTip($Button_Clear, "Clear output text")
$Tooltip_Copy.SetToolTip($Button_Copy, "Copy output text")
$Tooltip_Cut.SetToolTip($Button_Cut, "Cut output text")
$Tooltip_Notepad.SetToolTip($Button_Notepad, "Copy output text to Notepad")

#===================== StatusStrip =========================

$StatusBar = New-Object System.Windows.Forms.StatusStrip 
$StatusBarLabel  = New-Object System.Windows.Forms.ToolStripLabel -Property @{
    Width                         = 50
    Text                          = "  Ready"
    Visible                       = $true
}

$StatusBar.Items.AddRange([System.Windows.Forms.ToolStripItem[]]@($StatusBarLabel))

#======================= Buttons ===========================
# Button Controls
$Button_OSK.add_Click({ OSK })
$Button_Brightness_Less.add_Click({ Set-Brightness_Less })
$Button_Brightness_More.add_Click({ Set-Brightness_More })
$Button_Clear.add_Click({ Clear-Output })
$Button_Copy.add_Click({ Copy-Outbox })
$Button_Cut.add_Click({ Cut_Outbox })
$Button_Notepad.add_Click({ Copy-Notepad })
$TextBox_Output.add_LinkClicked({ Start-Process -FilePath $_.LinkText })
$TextBox_Output.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-OutPutCommand }})

# Add Controls
$GroupBox_Output.Controls.Add( $TextBox_Output )

#========================== Colors =========================

### Fore color

IF (test-path "$env:PUBLIC\Ultimate Administrator Console\Settings.xml") {


    $Script:Settings = Import-Clixml 'C:\users\Public\Ultimate Administrator Console\Settings.xml' -ErrorAction SilentlyContinue 

         ### Forecolor

    $TrackBar_TextColourRed.Value     = $Settings.TextColourRed 
    $TrackBar_TextColourGreen.Value   = $Settings.TextColourGreen  
    $TrackBar_TextColourBlue.Value    = $Settings.TextColourBlue 

    $Red = $TrackBar_TextColourRed.Value    
    $Green = $TrackBar_TextColourGreen.Value
    $Blue = $TrackBar_TextColourBlue.Value

    $ListBox_windows.ForeColor                    = "$Red,$Green,$Blue" 
    $ListBox_WindowServer.ForeColor               = "$Red,$Green,$Blue"
    $ListBox_ControlPanel.ForeColor               = "$Red,$Green,$Blue"
    $TextBox_Output.ForeColor                     = "$Red,$Green,$Blue"
    $ComboBox_Users.ForeColor                     = "$Red,$Green,$Blue"
    $ListBox_Users.ForeColor                      = "$Red,$Green,$Blue"
    $ListBox_Computers.ForeColor                  = "$Red,$Green,$Blue"
    $ComboBox_Computers.ForeColor                 = "$Red,$Green,$Blue"
    $ListBox_Computers.ForeColor                  = "$Red,$Green,$Blue"
    $ComboBox_Groups.ForeColor                    = "$Red,$Green,$Blue"
    $ListBox_Groups.ForeColor                     = "$Red,$Green,$Blue"
    $ComboBox_Mailbox.ForeColor                   = "$Red,$Green,$Blue"
    $ListBox_Mailbox.ForeColor                    = "$Red,$Green,$Blue"
    $ComboBox_Distributionlist.ForeColor          = "$Red,$Green,$Blue"
    $ListBox_Distributionlist.ForeColor           = "$Red,$Green,$Blue"
    $StatusBarLabel.ForeColor                     = "$Red,$Green,$Blue"

        ### Backcolor

    $TrackBar_BackColourRed.Value     = $Settings.BackColourRed   
    $TrackBar_BackColourGreen.Value   = $Settings.BackColourGreen 
    $TrackBar_BackColourBlue.Value    = $Settings.BackColourBlue    

    $Red = $TrackBar_BackColourRed.Value
    $Green = $TrackBar_BackColourGreen.Value
    $Blue = $TrackBar_BackColourBlue.Value

    $ListBox_windows.BackColor                    = "$Red,$Green,$Blue" 
    $ListBox_WindowServer.BackColor               = "$Red,$Green,$Blue" 
    $ListBox_ControlPanel.BackColor               = "$Red,$Green,$Blue" 
    $TextBox_Output.BackColor                     = "$Red,$Green,$Blue" 
    $ComboBox_Users.BackColor                     = "$Red,$Green,$Blue" 
    $ListBox_Users.BackColor                      = "$Red,$Green,$Blue" 
    $ComboBox_Computers.BackColor                 = "$Red,$Green,$Blue" 
    $ListBox_Computers.BackColor                  = "$Red,$Green,$Blue" 
    $ComboBox_Groups.BackColor                    = "$Red,$Green,$Blue" 
    $ListBox_Groups.BackColor                     = "$Red,$Green,$Blue" 
    $ComboBox_Mailbox.BackColor                   = "$Red,$Green,$Blue" 
    $ListBox_Mailbox.BackColor                    = "$Red,$Green,$Blue" 
    $ComboBox_Distributionlist.BackColor          = "$Red,$Green,$Blue" 
    $ListBox_Distributionlist.BackColor           = "$Red,$Green,$Blue" 
    $StatusBar.BackColor                          = "$Red,$Green,$Blue" 


} ELSE {

### Forecolor
    $TrackBar_TextColourRed.Value     = 255
    $TrackBar_TextColourGreen.Value   = 255
    $TrackBar_TextColourBlue.Value    = 255

    $Red = $TrackBar_TextColourRed.Value    
    $Green = $TrackBar_TextColourGreen.Value
    $Blue = $TrackBar_TextColourBlue.Value
  

    $ListBox_windows.ForeColor                    = "$Red,$Green,$Blue" 
    $ListBox_WindowServer.ForeColor               = "$Red,$Green,$Blue"
    $ListBox_ControlPanel.ForeColor               = "$Red,$Green,$Blue"
    $TextBox_Output.ForeColor                     = "$Red,$Green,$Blue"
    $ComboBox_Users.ForeColor                     = "$Red,$Green,$Blue"
    $ListBox_Users.ForeColor                      = "$Red,$Green,$Blue"
    $ListBox_Computers.ForeColor                  = "$Red,$Green,$Blue"
    $ComboBox_Computers.ForeColor                 = "$Red,$Green,$Blue"
    $ListBox_Computers.ForeColor                  = "$Red,$Green,$Blue"
    $ComboBox_Groups.ForeColor                    = "$Red,$Green,$Blue"
    $ListBox_Groups.ForeColor                     = "$Red,$Green,$Blue"
    $ComboBox_Mailbox.ForeColor                   = "$Red,$Green,$Blue"
    $ListBox_Mailbox.ForeColor                    = "$Red,$Green,$Blue"
    $ComboBox_Distributionlist.ForeColor          = "$Red,$Green,$Blue"
    $ListBox_Distributionlist.ForeColor           = "$Red,$Green,$Blue"
    $StatusBarLabel.ForeColor                     = "$Red,$Green,$Blue"

### Backcolor

    $TrackBar_BackColourRed.Value     = 1 
    $TrackBar_BackColourGreen.Value   = 1
    $TrackBar_BackColourBlue.Value    = 1

    $Red = $TrackBar_BackColourRed.Value
    $Green = $TrackBar_BackColourGreen.Value
    $Blue = $TrackBar_BackColourBlue.Value

    $ListBox_windows.BackColor                    = "$Red,$Green,$Blue" 
    $ListBox_WindowServer.BackColor               = "$Red,$Green,$Blue" 
    $ListBox_ControlPanel.BackColor               = "$Red,$Green,$Blue" 
    $TextBox_Output.BackColor                     = "$Red,$Green,$Blue" 
    $ComboBox_Users.BackColor                     = "$Red,$Green,$Blue" 
    $ListBox_Users.BackColor                      = "$Red,$Green,$Blue" 
    $ComboBox_Computers.BackColor                 = "$Red,$Green,$Blue" 
    $ListBox_Computers.BackColor                  = "$Red,$Green,$Blue" 
    $ComboBox_Groups.BackColor                    = "$Red,$Green,$Blue" 
    $ListBox_Groups.BackColor                     = "$Red,$Green,$Blue" 
    $ComboBox_Mailbox.BackColor                   = "$Red,$Green,$Blue" 
    $ListBox_Mailbox.BackColor                    = "$Red,$Green,$Blue" 
    $ComboBox_Distributionlist.BackColor          = "$Red,$Green,$Blue" 
    $ListBox_Distributionlist.BackColor           = "$Red,$Green,$Blue" 
    $StatusBar.BackColor                          = "$Red,$Green,$Blue" 

    }


#=========================== END ==========================

# Add Controls to from
$Form.controls.AddRange(@(
    $Menu
    $Tab_Control
    $GroupBox_Output
    $Button_OSK
    $Button_Brightness_Less
    $Button_Brightness_More
    $Button_Clear
    $Button_Copy
    $Button_Cut
    $Button_Notepad
    $StatusBar 
))


# Show Form
[void]$Form.ShowDialog()

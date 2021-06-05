
<#

Ultimate Administrator Console

.SYNOPSIS

.DESCRIPTION

.NOTES

Author Theo bird (Bedlem55)
  
#>

# Create Dir for Ultimate Administrator Console and Import settings 
$Settings = $null
IF (-not(test-path "$env:PUBLIC\Ultimate Administrator Console")) { New-Item "$env:PUBLIC\Ultimate Administrator Console" -ItemType Directory -ErrorAction SilentlyContinue -Force | Out-Null }
IF (test-path "$env:PUBLIC\Ultimate Administrator Console\Settings.xml") { $Script:Settings = Import-Clixml 'C:\users\Public\Ultimate Administrator Console\Settings.xml' -ErrorAction SilentlyContinue }

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

$Exchangeserver = If (test-path "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml") { Import-Clixml "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml" }

# Icons
$Icon_OK = [System.IconExtractor]::Extract("Shell32.dll", 302, $true)

# About
$About =  @"

    Author:      Theo Bird (Bedlem55)
    Github:      https://github.com/Bedlem55/Ultimate-Administrator-Console
    YouTube:     

"@


# AD 
$AD_Forst       = $null
$AD_Domain      = $null
$AD_Users       = $null
$AD_Computers   = $null
$AD_Groups      = $null
$AD_OUs         = $null

# exchange
$Exchange_Users                  = $null
$Exchange_Mailboxes              = $null
$Exchange_DistributionGroups     = $null
$script:Exchange_Contacts        = $null

$Colors = @(

 'AliceBlue'
 'AntiqueWhite'
 'Aqua'
 'Aquamarine'
 'Azure'
 'Beige'
 'Bisque'
 'Black'
 'BlanchedAlmond'
 'Blue'
 'BlueViolet'
 'Brown'
 'BurlyWood'
 'CadetBlue'
 'Chartreuse'
 'Chocolate'
 'Coral'
 'CornflowerBlue'
 'Cornsilk'
 'Crimson'
 'Cyan'
 'DarkBlue'
 'DarkCyan'
 'DarkGoldenrod'
 'DarkGray'
 'DarkGreen'
 'DarkKhaki'
 'DarkOliveGreen'
 'DarkOrange'
 'DarkOrchid'
 'DarkRed'
 'DarkSalmon'
 'DarkSeaGreen'
 'DarkSlateBlue'
 'DarkSlateGray'
 'DarkTurquoise'
 'DarkViolet'
 'DeepPink'
 'DeepSkyBlue'
 'DimGray'
 'DodgerBlue'
 'Firebrick'
 'FloralWhite'
 'ForestGreen'
 'Gainsboro'
 'GhostWhite'
 'Gold'
 'Goldenrod'
 'Gray'
 'Green'
 'GreenYellow'
 'Honeydew'
 'HotPink'
 'IndianRed'
 'Indigo'
 'Ivory'
 'Khaki'
 'Lavender'
 'LavenderBlush'
 'LawnGreen'
 'LemonChiffon'
 'LightBlue'
 'LightCoral'
 'LightCyan'
 'LightGoldenrodYellow'
 'LightGreen'
 'LightGray'
 'LightPink'
 'LightSalmon'
 'LightSeaGreen'
 'LightSkyBlue'
 'LightSlateGray'
 'LightSteelBlue'
 'LightYellow'
 'Lime'
 'LimeGreen'
 'Linen'
 'Magenta'
 'Maroon'
 'MediumAquamarine'
 'MediumBlue'
 'MediumOrchid'
 'MediumPurple'
 'MediumSeaGreen'
 'MediumSlateBlue'
 'MediumSpringGreen'
 'MediumTurquoise'
 'MediumVioletRed'
 'MidnightBlue'
 'MintCream'
 'MistyRose'
 'Moccasin'
 'NavajoWhite'
 'Navy'
 'OldLace'
 'Olive'
 'OliveDrab'
 'Orange'
 'OrangeRed'
 'Orchid'
 'PaleGoldenrod'
 'PaleGreen'
 'PaleTurquoise'
 'PaleVioletRed'
 'PapayaWhip'
 'PeachPuff'
 'Peru'
 'Pink'
 'Plum'
 'PowderBlue'
 'Purple'
 'Red'
 'RosyBrown'
 'RoyalBlue'
 'SaddleBrown'
 'Salmon'
 'SandyBrown'
 'SeaGreen'
 'Seashell'
 'Sienna'
 'Silver'
 'SkyBlue'
 'SlateBlue'
 'SlateGray'
 'Snow'
 'SpringGreen'
 'SteelBlue'
 'Tan'
 'Teal'
 'Thistle'
 'Tomato'
 'Turquoise'
 'Violet'
 'Wheat'
 'White'
 'WhiteSmoke'
 'Yellow'
 'YellowGreen'
 )
 
#=========================================================================#
#                           Base Functions                                # 
#=========================================================================#

# set ForeColor
Function Set-ForeColor {

    $ListBox_windows.ForeColor                    = $ComboBox_Output_ForeColor.text.ToString() 
    $ListBox_WindowServer.ForeColor               = $ComboBox_Output_ForeColor.text.ToString()
    $ListBox_ControlPanel.ForeColor               = $ComboBox_Output_ForeColor.text.ToString()
    $TextBox_Output.ForeColor                     = $ComboBox_Output_ForeColor.text.ToString()
    $ComboBox_Users.ForeColor                     = $ComboBox_Output_ForeColor.text.ToString()
    $ListBox_Users.ForeColor                      = $ComboBox_Output_ForeColor.text.ToString()
    $ComboBox_Computers.ForeColor                 = $ComboBox_Output_ForeColor.text.ToString()
    $ListBox_Computers.ForeColor                  = $ComboBox_Output_ForeColor.text.ToString()
    $ComboBox_Groups.ForeColor                    = $ComboBox_Output_ForeColor.text.ToString()
    $ListBox_Groups.ForeColor                     = $ComboBox_Output_ForeColor.text.ToString()
    $ComboBox_Mailbox.ForeColor                   = $ComboBox_Output_ForeColor.text.ToString()
    $ListBox_Mailbox.ForeColor                    = $ComboBox_Output_ForeColor.text.ToString()
    $ComboBox_Distributionlist.ForeColor          = $ComboBox_Output_ForeColor.text.ToString()
    $ListBox_Distributionlist.ForeColor           = $ComboBox_Output_ForeColor.text.ToString()
    $ComboBox_Contacts.ForeColor                  = $ComboBox_Output_ForeColor.text.ToString()
    $ListBox_Contacts.ForeColor                   = $ComboBox_Output_ForeColor.text.ToString()
    $StatusBarLabel.ForeColor                     = $ComboBox_Output_ForeColor.text.ToString()

}

# set BackColor
Function Set-BackColor {

    $ListBox_windows.BackColor                    = $ComboBox_Output_BackColor.text.ToString()
    $ListBox_WindowServer.BackColor               = $ComboBox_Output_BackColor.text.ToString()
    $ListBox_ControlPanel.BackColor               = $ComboBox_Output_BackColor.text.ToString()
    $TextBox_Output.BackColor                     = $ComboBox_Output_BackColor.text.ToString()
    $ComboBox_Users.BackColor                     = $ComboBox_Output_BackColor.text.ToString()
    $ListBox_Users.BackColor                      = $ComboBox_Output_BackColor.text.ToString()
    $ComboBox_Computers.BackColor                 = $ComboBox_Output_BackColor.text.ToString()
    $ListBox_Computers.BackColor                  = $ComboBox_Output_BackColor.text.ToString()
    $ComboBox_Groups.BackColor                    = $ComboBox_Output_BackColor.text.ToString()
    $ListBox_Groups.BackColor                     = $ComboBox_Output_BackColor.text.ToString()
    $ComboBox_Mailbox.BackColor                   = $ComboBox_Output_BackColor.text.ToString()
    $ListBox_Mailbox.BackColor                    = $ComboBox_Output_BackColor.text.ToString()
    $ComboBox_Distributionlist.BackColor          = $ComboBox_Output_BackColor.text.ToString()
    $ListBox_Distributionlist.BackColor           = $ComboBox_Output_BackColor.text.ToString()
    $ComboBox_Contacts.BackColor                  = $ComboBox_Output_BackColor.text.ToString()
    $ListBox_Contacts.BackColor                   = $ComboBox_Output_BackColor.text.ToString()
    $StatusBar.BackColor                          = $ComboBox_Output_BackColor.text.ToString()
    
}

Function Set-Opacity {

    $Form.Opacity = "0." + $TrackBar_Opacity.Value
}

Function Save-settings {

   Try {
        
        New-Object PSObject -Property @{

          ForeColor = $ComboBox_Output_ForeColor.Text
          BackColor = $ComboBox_Output_BackColor.Text 
        
        } | Export-Clixml "$env:PUBLIC\Ultimate Administrator Console\Settings.xml"
    } Catch { Write-OutError }
}


Function New-Admin_ShortCut {


    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut(“$env:USERPROFILE\Desktop\HIPS.lnk”)
    $Shortcut.TargetPath = $ScriptPath
    $Shortcut.IconLocation = "C:\WINDOWS\system32\imageres.dll, 204"
    $Shortcut.Arguments = “/s /t 0”
    $Shortcut.Save()

}


# Clear output 
Function Clear-Output {
    $TextBox_Output.ForeColor = $ComboBox_Output_ForeColor.text.ToString()
    $TextBox_Output.Clear()
}

# Error
Function Write-OutError {
    Clear-Output
    $TextBox_Output.ForeColor = [Drawing.Color]::Red
    $Err = $Error[0]
    $TextBox_Output.AppendText("Error: $Err")
}

# About
Function Show-About {
   Clear-Output
   $TextBox_Output.AppendText($About)    
} 

# Copys outbox text 
Function Copy_Outbox {
    $TextBox_Output.SelectAll()
    $TextBox_Output.Copy()
} 

# Copys outbox text to notepad
Function Copy_Notepad { 
    $filename = [System.IO.Path]::GetTempFileName() 
    Add-Content -Value $TextBox_Output.text -Path $filename
    notepad $filename
}

# Runs Commands typed into the TextBox_Output
Function Start-OutPutCommand {
    $Command = $TextBox_Output.text
        try {
        Clear-Output
        $TextBox_Output.Text = Invoke-Expression $Command -ErrorAction Stop | Out-String
    } Catch { Write-OutError } 
}

Function Get-ComputerInfo_Output {
    Clear-Output
    $TextBox_Output.Text = Invoke-Expression "Get-computerinfo" -ErrorAction Stop | Out-String
    
}

Function Set-StatusBarReady {
    $StatusBarLabel.text = "  Ready"
}


#=========================================================================#
#                          Windows Functions                              # 
#=========================================================================#

#================= Windows Tools Functions =================

# Start windows App
Function start_windowapp {

    IF ($ListBox_windows.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    Else { 
      try { 
        switch ($ListBox_windows.SelectedItem) {

            'ACL folder info'                       { Get_ACL }
            'Clean Disk Manager'                    { cleanmgr.exe }
            'DirectX Diagnostic Tool'               { Start-Process dxdiag.exe -ErrorAction Stop }
            'Disk Manager'                          { Start-Process diskmgmt.msc -ErrorAction Stop }
            'Device Management'                     { Start-Process devmgmt.msc -ErrorAction Stop }
            'Enable Ultimate Performance'           { Enable-Ultimate_Performance }
            'Event Viewer'                          { Start-Process eventvwr.msc -ErrorAction Stop }
            'Firewall'                              { Start-Process firewall.cpl -ErrorAction Stop }
            'Internet Properties'                   { Start-Process inetcpl.cpl -ErrorAction Stop }
            'Invoke Group policy update'            { Start-Gpupdate }
            'Network Properties'                    { Start-Process control -ArgumentList netconnections -ErrorAction Stop}
            'Optional Features'                     { Start-Process OptionalFeatures.exe -ErrorAction Stop }
            'Registry Editor'                       { Start-Process regedit -ErrorAction Stop }
            'Reliability Monitor'                   { Start-Process perfmon /rel -ErrorAction Stop}
            'Remote Desktop'                        { Start-Process mstsc.exe -ErrorAction Stop}
            'Services'                              { Start-Process services.msc -ErrorAction Stop }
            'Show Wifi Passwords'                   { Get-WifiPassword }
            'Start Windows Defender Offline Scan'   { Start-WindowsDefenderOfflineScan } 
            'System Information'                    { Start-Process msinfo32.exe -ErrorAction Stop } 
            'System Configuration Utility'          { Start-Process msconfig.exe -ErrorAction Stop }
            'System Properties'                     { Start-Process sysdm.cpl -ErrorAction Stop }
            'Task Scheduler'                        { Start-Process taskschd.msc -ErrorAction Stop }
            'Task Manager'                          { Start-Process taskmgr.exe -ErrorAction Stop }
            'Text to Wave'                          { Start-TexttoWave }
            'Windows Version'                       { Start-Process winver.exe -ErrorAction Stop }
            'Windows Update'                        { Start-Process control -ArgumentList update -ErrorAction Stop }

            } 
        } Catch { Write-OutError }
    }
}

# Start Server app
Function start_windowAdminapp {

    IF ($ListBox_WindowServer.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    Else { 
      try { 
        switch ($ListBox_WindowServer.SelectedItem) {
            
            'Active Directory Administrative Center'              { Start-Process dsac.exe -ErrorAction Stop }
            'Active Directory Domains and Trusts'                 { Start-Process domain.msc -ErrorAction Stop }
            'Active Directory Sites and Services'                 { Start-Process dssite.msc -ErrorAction Stop }
            'Active Directory Users and Computers'                { Start-Process dsa.msc -ErrorAction Stop }
            'ADSI Edit'                                           { Start-Process adsiedit.msc -ErrorAction Stop }
            'Computer Management'                                 { Start-Process compmgmt.msc -ArgumentList /s -ErrorAction Stop }
            'DFS Management'                                      { Start-Process dfsmgmt.msc }
            'DHCP'                                                { Start-Process dhcpmgmt.msc -ErrorAction Stop }
            'DNS'                                                 { Start-Process dnsmgmt.msc -ErrorAction Stop }
            'File Server Resource Manager'                        { Start-Process fsrm.msc -ErrorAction Stop }
            'Group Policy Management'                             { Start-Process gpmc.msc -ErrorAction Stop }
            'Print Management'                                    { Start-Process printmanagement.msc -ErrorAction Stop }
            'Server Manager'                                      { Start-Process ServerManager.exe -ErrorAction Stop }
            'Volume Activation Tools'                             { Start-Process vmw.exe -ErrorAction Stop }
            'Windows Defender Firewall with Advanced Security'    { Start-Process WF.msc -ErrorAction Stop }
            'Windows Server Update Services'                      { Start-Process wsus.msc -ErrorAction Stop }  
                        
            } 
        } Catch { Write-OutError }
    }
}

Function Add-AllRsatTools {
    
    Try {
    $StatusBarLabel.text = "  Installing RSAT"

    Add-WindowsCapability -Online -Name Rsat.FileServices.Tools -ErrorAction Stop  
    Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools
    Add-WindowsCapability -Online -Name Rsat.IPAM.Client.Tools
    Add-WindowsCapability -Online -Name Rsat.LLDP.Tools
    Add-WindowsCapability -Online -Name Rsat.NetworkController.Tools
    Add-WindowsCapability -Online -Name Rsat.NetworkLoadBalancing.Tools
    Add-WindowsCapability -Online -Name Rsat.BitLocker.Recovery.Tools
    Add-WindowsCapability -Online -Name Rsat.CertificateServices.Tools
    Add-WindowsCapability -Online -Name Rsat.DHCP.Tools
    Add-WindowsCapability -Online -Name Rsat.FailoverCluster.Management.Tools
    Add-WindowsCapability -Online -Name Rsat.RemoteAccess.Management.Tools
    Add-WindowsCapability -Online -Name Rsat.RemoteDesktop.Services.Tools
    Add-WindowsCapability -Online -Name Rsat.ServerManager.Tools
    Add-WindowsCapability -Online -Name Rsat.Shielded.VM.Tools
    Add-WindowsCapability -Online -Name Rsat.StorageMigrationService.Management.Tools
    Add-WindowsCapability -Online -Name Rsat.StorageReplica.Tools
    Add-WindowsCapability -Online -Name Rsat.SystemInsights.Management.Tools
    Add-WindowsCapability -Online -Name Rsat.VolumeActivation.Tools
    Add-WindowsCapability -Online -Name Rsat.WSUS.Tools

    Set-StatusBarReady

    } Catch {
        Set-StatusBarReady
        Write-OutError
    }
}

Function Start-WindowsDefenderOfflineScan { 
    
    try {
        $UserPrompt = new-object -comobject wscript.shell
        $Answer = $UserPrompt.popup("Start offline Windows Defender scan? `n`n Note: this will restart your PC", 0, "Start Scan", 0x4 + 0x30)
            IF ($Answer -eq 6) {
                Clear-Output
                Start-MpWDOScan -ErrorAction Stop | Out-Null
                $TextBox_Output.AppendText("Starting Scan")
            
            } Else {
                Clear-Output
                $TextBox_Output.AppendText("Scan canceled")
            }
        } Catch { Write-OutError }
}


Function Start-Gpupdate {

    try {
        $UserPrompt = new-object -comobject wscript.shell
        $Answer = $UserPrompt.popup("Invoke Gpupdate? `n`n Note: this will restart your PC", 0, "Invoke Gpupdate", 0x4 + 0x30)
            IF ($Answer -eq 6) {
                Start-Process gpupdate -ArgumentList "/force /boot" -ErrorAction Stop  -Wait | Out-Null
            } Else {
                Clear-Output
                $TextBox_Output.AppendText("Gpupdate canceled")
            }
        } Catch { Write-OutError }
}



Function Godmode {
    $path = "$env:PUBLIC\Ultimate Administrator Console.{ED7BA470-8E54-465E-825C-99712043E01C}"
    IF ((Test-path $path) -ne $true) { New-item -Path $path -ItemType Directory }
    Invoke-Item $path 
} 


Function Start-ControlPanelItem {
    IF ($ListBox_ControlPanel.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No control panel item selected") } 
    Else {  
        Try{
            Show-ControlPanelItem -Name $ListBox_ControlPanel.SelectedItem -ErrorAction Stop
        } Catch { Write-OutError }
    }
} 

Function Get_ACL {
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
    
    } Else {

        $Path = $TextBox_GetFolder.text.tostring()
        IF(Test-Path $Path) {

        $SaveFile = New-Object -TypeName System.Windows.Forms.SaveFileDialog
        $SaveFile.Title = "Export ACL Permissions"
        $SaveFile.FileName = "Folder Permissions Export"
        $SaveFile.Filter = "CSV Files (*.csv)|*.csv"
        $SaveFile.ShowDialog()

        Get-ChildItem -Path $Path -Recurse | Where-Object{$_.psiscontainer}|
        Get-Acl | foreach {
        $path = $_.Path
        $_.Access | ForEach-Object {
            New-Object PSObject -Property @{
                Folder = $path.Replace("Microsoft.PowerShell.Core\FileSystem::","")
                Access = $_.FileSystemRights
                Control = $_.AccessControlType
                User = $_.IdentityReference
                Inheritance = $_.IsInherited
                    }
                }
            } | select-object -Property Folder,User,Access,Control,Inheritance | export-csv $SaveFile.FileName.tostring() -NoTypeInformation -force
        } Else { [System.Windows.Forms.MessageBox]::Show("No folder selected", "Warning:",0,48) }
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
Windows Registry Editor Version 5.00

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
Windows Registry Editor Version 5.00

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

Warning: this will modify the system registry.
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

  if ($null -eq $SelectVoiceCB.SelectedItem) {
    [System.Windows.Forms.MessageBox]::Show("No voice selected", "Warning:",0,48) 
  }
  Else {
    $Speak.SetOutputToDefaultAudioDevice() ; 
    $Speak.Rate = ($speed.Value)
    $Speak.Volume = $Volume.Value 
    $Speak.SelectVoice($SelectVoiceCB.Text) 
    $Speak.Speak($SpeakTextBox.Text)
  } 
}

Function SaveSound {
  if ($null -eq $SelectVoiceCB.SelectedItem) {
    [System.Windows.Forms.MessageBox]::Show("No voice selected", "Warning:",0,48) 
  }
  else {
    $SaveChooser = New-Object -TypeName System.Windows.Forms.SaveFileDialog
    $SaveChooser.Title = "Save text to Wav file"
    $SaveChooser.FileName = "SpeechSynthesizer"
    $SaveChooser.Filter = 'Wave file (.wav) | *.wav'
    $Answer = $SaveChooser.ShowDialog(); $Answer

    if ( $Answer -eq "OK" ) {
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

  if (-not(Get-WmiObject -Class win32_operatingsystem).version.remove(2) -eq 10 ) { 
    [System.Windows.Forms.MessageBox]::Show("$OS","Warning:",0,48) 
  }

  else {
    if ($Admin -eq $true) {

    $UserPrompt = new-object -comobject wscript.shell
    $Answer = $UserPrompt.popup($Message, 0, "Enable system Voices", 4)

      If ($Answer -eq 6) {
        New-Item -Value $eva -Path $env:SystemDrive\Eva.reg
        New-Item -Value $Mark -Path $env:SystemDrive\Mark.reg
        Start-Process regedit.exe -ArgumentList  /s, $env:SystemDrive\Eva.reg -Wait  
        Start-Process regedit.exe -ArgumentList  /s, $env:SystemDrive\Mark.reg -Wait
        Remove-Item $env:SystemDrive\Mark.reg -Force
        Remove-Item $env:SystemDrive\Eva.reg  -Force

        $UserPrompt = new-object -comobject wscript.shell
        $Answer = $UserPrompt.popup($Restart, 0, "Restart prompt", 4)
          If ($Answer -eq 6) { Restart-Computer -Force }

      } 
    }   Else { [System.Windows.Forms.MessageBox]::Show("$AdminMeg","Warning:",0,48) } 
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
$SpeakButtion.Font = 'Microsoft Sans Serif,10'
$SpeakButtion.add_Click( { PlaySound })

$SaveButtion = New-Object system.Windows.Forms.Button
$SaveButtion.location = "660, 456"
$SaveButtion.Size = "127, 55"
$SaveButtion.Anchor = "Bottom"
$SaveButtion.text = "Save"
$SaveButtion.Font = 'Microsoft Sans Serif,10'
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
$SpeakTextBox.Font = 'Microsoft Sans Serif,10'
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

$SelectVoiceCB.Font = 'Microsoft Sans Serif,10'
$Voices = ($speak.GetInstalledVoices() | ForEach-Object { $_.voiceinfo }).Name
foreach ($Voice in $Voices) {
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

# Get All wifi passwords
# Credit to https://itfordummies.net/2018/11/05/get-known-wifi-networks-passwords-powershell/
Function Get-WifiPassword {

    Clear-Output

    netsh wlan show profile | Select-Object -Skip 3| Where-Object -FilterScript {($_ -like '*:*')} | ForEach-Object -Process {
        $NetworkName = $_.Split(':')[-1].trim()
        $PasswordDetection = $(netsh wlan show profile name =$NetworkName key=clear) | Where-Object -FilterScript {($_ -like '*contenu de la clé*') -or ($_ -like '*key content*')}

       $Wifi = New-Object -TypeName PSObject -Property @{
            NetworkName = $NetworkName
            Password = if($PasswordDetection){$PasswordDetection.Split(':')[-1].Trim()}else{'Unknown'}
        } -ErrorAction SilentlyContinue | Select NetworkName, Password | Out-String
        $TextBox_Output.AppendText($Wifi)  
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

Function Import-ADxml {

 $AD_XML = Import-Clixml "$env:PUBLIC\Ultimate Administrator Console\AD.xml"
            
    $script:AD_Forst       = (Get-ADDomain).Forest
    $script:AD_Domain      = (Get-ADForest).UPNSuffixes
    $script:AD_Users       = $AD_XML.Users | Sort-Object
    $script:AD_Computers   = $AD_XML.Computers | Sort-Object
    $script:AD_Groups      = $AD_XML.Groups | Sort-Object
    $script:AD_OUs         = $AD_XML.OUs | Sort-Object
     
}

Function Import-ADdata {

    $script:AD_Forst       = (Get-ADDomain).Forest
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
    try { 
        Import-Module activedirectory -ErrorAction Stop -WarningAction SilentlyContinue 
                
        If (test-path "$env:PUBLIC\Ultimate Administrator Console\AD.xml") {
            $LastWriteTime = (Get-ItemProperty "$env:PUBLIC\Ultimate Administrator Console\AD.xml").LastWriteTime
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("Load Active Directory data from local cache? `n`nCache was Last updated on $LastWriteTime", 0, " Load from cache", 0x4 + 0x20)
    
         switch ($Answer) {

            6           { Import-ADxml }
            Default     { Import-ADdata }  
             
            }
                    
        } Else { Import-ADdata }     
        
        ForEach ($User in $AD_Users) { [void]$ComboBox_Users.Items.Add($user) }
        $ComboBox_Users.AutoCompleteSource = "CustomSource" 
        $ComboBox_Users.AutoCompleteMode = "SuggestAppend"
        $AD_Users | ForEach-Object { [void]$ComboBox_Users.AutoCompleteCustomSource.Add($_) }

        ForEach ($CPU in $AD_Computers) { [void]$ComboBox_Computers.Items.Add($CPU) }
        $ComboBox_Computers.AutoCompleteSource = "CustomSource" 
        $ComboBox_Computers.AutoCompleteMode = "SuggestAppend"
        $AD_Computers | ForEach-Object { [void]$ComboBox_Computers.AutoCompleteCustomSource.Add($_) }
        
        ForEach ($Group in $AD_Groups) { [void]$ComboBox_Groups.Items.Add($Group) }
        $ComboBox_Groups.AutoCompleteSource = "CustomSource" 
        $ComboBox_Groups.AutoCompleteMode = "SuggestAppend"
        $AD_Groups | ForEach-Object { [void]$ComboBox_Groups.AutoCompleteCustomSource.Add($_) }
            
        $Panel_ActiveDirectory.Enabled = $true
        $Menu_AD.Enabled = $true
       
        Save-ADdata
        Set-StatusBarReady
        $TextBox_Output.AppendText("*** Active Directory object have been loaded ***")    
        
        
    } catch {
    Write-OutError
    Set-StatusBarReady
    $Button_ActiveDirectory_StartButtion.Enabled = $true
    } 
}

# Save AD data to cache
Function Save-ADdata {
        
    Try {
        
        New-Object PSObject -Property @{

            Users      = $AD_users
            Computers  = $AD_Computers
            Groups     = $AD_Groups
            OUs        = $AD_OUs  
        
        } | Export-Clixml "$env:PUBLIC\Ultimate Administrator Console\AD.xml"
    } Catch { Write-OutError }
}

# starts selected action
Function Start-AD_UserFunction {

    IF ($ListBox_users.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    Else { 
      try { 
        switch ($ListBox_users.SelectedItem) {

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
            "Remove All Groups"                      { Remove-AD_UserfromGroup }
            "Move OU"                                { Move-AD_User }
            "Remove Account"                         { Remove-AD_User }

            } 
        } Catch { Write-OutError }
    }
}

# starts selected action
Function Start-AD_ComputerFunction {

    IF ($ListBox_Computers.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    Else { 
      try { 
        switch ($ListBox_computers.SelectedItem) {
        
        "Computer info"                                { Get-AD_ComputerFullInfo }
        "List all Groups"                              { Get-AD_ComputerMembers }
        "Test Connectivity"                            { Test-AD_ComputerConnection}
        "Remote Desktop"                               { Connect-AD_Computer }
        "Event Viewer"                                 { Start-AD_ComputerEventViewer }
        "Computer Management"                          { Start-AD_ComputerManagement }
        "Add to Group"                                 { Add-AD_ComputerToGroup }
        "Copy all Groups from another Account"         { Copy-AD_ComputerMembers }
        "Remove Group"                                 { Remove-AD_ComputerFromGroup }
        "Remove All Groups"                            { Remove-AD_ComputerFromGroup }
        "Move OU"                                      { Move-AD_Computer }
        "Remove Account"                               { Remove-AD_Computer }
        "Update Group policy"                          { Invoke-AD_ComputerPolicyUpdate }
        "Restart PC"                                   { Restart-AD_Computer } 

            } 
        } Catch { Write-OutError }
    }
}

# starts selected action
Function Start-AD_GroupFunction {

    IF ($ListBox_Groups.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    Else { 
      try { 
        switch ($ListBox_Groups.SelectedItem) {
        
        "Group info"               { GroupInfo }
        "List Members"             { GroupMembers }
        "Add User"                 { Add-UserMember }
        "Add Computer"             { Add-ComputerMember }
        "Add Group"                { Add-GroupMember }
        "Remove Members"           { Remove-Member }
        "Move OU"                  { Move-AD_Group} 
        "Remove Group"             { Remove-AD_Group }
 

            } 
        } Catch { Write-OutError }
    }
}

# Set output message for Null SelectedItem
Function Set-Output_ADuserNull {
    Clear-Output
    $TextBox_Output.AppendText("No User Selected")
}

Function Set-Output_ADComputerNull {
    Clear-Output
    $TextBox_Output.AppendText("No Computer Selected")
}

Function Set-Output_ADGroupNull {
    Clear-Output
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

$GroupBox_UPN.Controls.AddRange(@(
    $TextBox_UPN
    $ComboBox_UPN
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
$Button_NewUser_Cancel.FlatAppearance.BorderSize = 0

$Button_NewUser_OK = New-Object System.Windows.Forms.Button -Property @{
    Location = "275, 225"
    Size = "128,35"
    Text = "Ok"
    FlatStyle = "Flat"
}
$Button_NewUser_OK.FlatAppearance.BorderSize = 0

# Controls
$Button_NewUser_Cancel.add_Click( { $NewUserFrom.Close(); $NewUserFrom.Dispose() })
$Button_NewUser_OK.add_Click( { New-AD_User })

# Populate ComboBoxes
ForEach ($Domain in $AD_Domain) { [void]$ComboBox_UPN.Items.Add("@$Domain") }
$ComboBox_UPN.AutoCompleteSource = "CustomSource" 
$ComboBox_UPN.AutoCompleteMode = "SuggestAppend"
$Domain_UPN | ForEach-Object { [void]$ComboBox_UPN.AutoCompleteCustomSource.Add($_) }
$GroupBox_CopyUser.Controls.Add($ComboBox_CopyUser)

ForEach ($user in $AD_Users.SamAccountName) { [void]$ComboBox_CopyUser.Items.Add($user) }
$ComboBox_CopyUser.AutoCompleteSource = "CustomSource" 
$ComboBox_CopyUser.AutoCompleteMode = "SuggestAppend"
$AD_users.SamAccountName | ForEach-Object { [void]$ComboBox_CopyUser.AutoCompleteCustomSource.Add($_) }
$GroupBox_CopyUser.Controls.Add($ComboBox_CopyUser)

ForEach ($OU in $AD_OUs.CanonicalName) { [void]$ComboBox_OU.Items.Add($OU) }
$ComboBox_OU.AutoCompleteSource = "CustomSource" 
$ComboBox_OU.AutoCompleteMode = "SuggestAppend"
$AD_OUs.CanonicalName | ForEach-Object { [void]$ComboBox_OU.AutoCompleteCustomSource.Add($_) }
$GroupBox_OU.Controls.Add($ComboBox_OU)

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
    $obj[0].split(".") | ForEach-Object { $DN += ",DC=" + $_}
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

    Try { 
        
    $StatusBarLabel.text = "  Creating new user account for $UserName"
    New-ADUser @NewUser -ErrorAction Stop

        IF($ComboBox_CopyUser.SelectedItem -ne $null) {

            Start-Sleep -Milliseconds 0.2
            $CopyUser = $ComboBox_CopyUser.SelectedItem.ToString()
            $CopyFromUser = Get-ADUser $CopyUser -Properties MemberOf
            $CopyToUser = Get-ADUser $UserName -Properties MemberOf
            $CopyFromUser.MemberOf | Where{$UserName.MemberOf -notcontains $_} |  Add-ADGroupMember -Members $UserName
               
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

    } catch { Write-OutError }
}


# display full user account info to output 
Function Get-AD_UserFullInfo {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
    } Else {
        Try {
            Clear-Output
            $UserAccount = $ComboBox_Users.Text.ToString()
            $TextBox_Output.text = get-aduser $UserAccount -Properties * | Format-List | Out-String -Width 2147483647
            
        } Catch { Write-OutError }
    }
}

# list all groups user account is member of to output
Function Get-AD_UserMembers {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
    } Else {
        Try {
            Clear-Output
            $UserAccount = $ComboBox_Users.Text.ToString()
            $TextBox_Output.text = get-aduser $UserAccount -Properties * | ForEach-Object {($_.memberof | Get-ADGroup | Select-Object -ExpandProperty Name)} | Sort-Object | Format-List | Out-String -Width 2147483647
            
        } Catch { Write-OutError }
    }
}

# resets password to random one - password must be changed at next login
Function Set-AD_UserPasswordReset {        

    IF ($ComboBox_Users.SelectedItem -eq $null) {
      Set-Output_ADuserNull
    } Else {
        Try {
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
            } Else { 
                Clear-Output
                $TextBox_Output.AppendText("Reset Password action canceled")
            }
        } Catch { Write-OutError }
    }
}

# Unlocks account 
Function Set-AD_UserUnlockAccount {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
    } Else {
        Try {
            $UserAccount = $ComboBox_Users.Text.ToString()                
            Clear-Output
            Unlock-ADAccount -Identity $ComboBox_Users.Text -ErrorAction Stop
            $TextBox_Output.AppendText("$UserAccount's account is now unlocked")
        } Catch { Write-OutError }
    }
}
                        
# disables or enables user account 
Function Set-AD_UserDisableOrEnable {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
       Set-Output_ADuserNull
    } Else {
        IF ((Get-ADUser -Identity $ComboBox_Users.SelectedItem).Enabled -eq $true) { 
            Try {
    
                $UserAccount = $ComboBox_Users.Text.ToString()
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Disable $UserAccount`?", 0, "Disable Account Prompt", 0x4 + 0x30)
    
                IF ($Answer -eq 6) {
                    Clear-Output
                    Disable-ADAccount -Identity $ComboBox_Users.SelectedItem -ErrorAction Stop
                    $TextBox_Output.AppendText("$UserAccount account is now disabled")
                } Else {
                    Clear-Output
                    $TextBox_Output.AppendText("Account disabled action canceled") 
                }

            } Catch { Write-OutError }
        } Else { 
            Try {
    
                $UserAccount = $ComboBox_Users.Text.ToString()
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        $UserAccount is disabled, Enable this account`?", 0, "Enable Account Prompt", 0x4 + 0x30)
    
                IF ($Answer -eq 6) {
                    Clear-Output
                    Enable-ADAccount -Identity $ComboBox_Users.SelectedItem -ErrorAction Stop
                    $TextBox_Output.AppendText("$UserAccount account is now Enabled")
                } Else {
                    Clear-Output
                    $TextBox_Output.AppendText("Account Enable action canceled") 
                }
            } Catch { Write-OutError }
        }
    }
}

# sets password to never expire 
Function Set-PasswordToNeverExpire {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
    } Else {
        IF ((Get-ADUser $ComboBox_Users.SelectedItem -Properties *).PasswordNeverExpires -eq $false ) {

            Try {
                Clear-Output
                $UserAccount = $ComboBox_Users.Text.ToString()
                set-aduser $ComboBox_Users.SelectedItem -PasswordNeverExpires:$true 
                $TextBox_Output.AppendText("$UserAccount``s account is set to 'Password Never Expires'")
        
            } Catch { Write-OutError }
        } Else {
            Try {
                Clear-Output
                $UserAccount = $ComboBox_Users.Text.ToString()
                set-aduser $ComboBox_Users.SelectedItem -PasswordNeverExpires:$false 
                $TextBox_Output.AppendText("$UserAccount's Password is now expired and must be changed")
            } Catch { Write-OutError }
        }
    }
}

# set password to cannot be changed
Function Set-PasswordToCannotBeChanged {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
    } Else {
            IF ((Get-ADUser $ComboBox_Users.SelectedItem -Properties *).CannotChangePassword -eq $false ) {

                Try {
                    Clear-Output
                    $UserAccount = $ComboBox_Users.Text.ToString()
                    set-aduser $ComboBox_Users.SelectedItem -CannotChangePassword:$true
                    $TextBox_Output.AppendText("$UserAccount's account is set to 'Cannot Change Password'")
        
                } Catch { Write-OutError }
            } Else {
                Try {
                    Clear-Output
                    $UserAccount = $ComboBox_Users.Text.ToString()
                    set-aduser $ComboBox_Users.SelectedItem -CannotChangePassword:$false 
                    $TextBox_Output.AppendText("$UserAccount's Password can now be changed by user")
            } Catch { Write-OutError }
        }
    }
}

# Added account to selected groups
Function Add-AD_UserToGroup {

     IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } Else {
        Try {
            Clear-Output
            $UserAccount = $ComboBox_Users.Text.ToString()
            $List = $AD_Groups | Out-GridView -PassThru -Title "Select Group(s)"
            Foreach($Group in $List) { Add-ADGroupMember -Identity $Group -Members $UserAccount -Confirm:$false } 
            $TextBox_Output.AppendText("$UserAccount has now been added to selected Groups")
        } Catch { Write-OutError }
    }
} 

# Copies All selected users members
Function Copy-AD_UserMemberships {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } Else {
        Try {
            $UserAccount = $ComboBox_Users.Text.ToString()
            $CopyUser = $AD_Users | Sort-Object | Out-GridView -PassThru -Title "Select Account" 
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("        Copy all Groups form $CopyUser?", 0, "Copy",0x4 + 0x20)
            IF ($Answer -eq 6) {
                $StatusBar.text = "Copying All Groups from $UserAccount"
                Start-Sleep -Milliseconds 0.2
                $List = Get-ADUser $CopyUser -Properties * | ForEach-Object {($_.memberof | Get-ADGroup).SamAccountName } 
                Foreach($Group in $List) { Add-ADGroupMember -Identity $Group -Members $UserAccount -Confirm:$false -ErrorAction SilentlyContinue } 
                Clear-Output
                $TextBox_Output.AppendText("All groups from $CopyUser have been added to $UserAccount")
                Set-StatusBarReady
            } 
        } Catch { Write-OutError }
    }
}

# Rmmoves All selected users Group membership
Function Remove-AD_UserfromGroup {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } Else {
        Try {
            $UserAccount = $ComboBox_Users.Text.ToString()
            IF ($ListBox_users.SelectedItem -eq "Remove All Groups") {
                $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Remove all Groups from $UserAccount?", 0, "Remove", 0x4 + 0x30)
                IF ($Answer -eq 6) {
                    Clear-Output
                    $StatusBar.text = "Removing All Groups"
                    Start-Sleep -Milliseconds 0.2
                    $List = get-aduser $UserAccount -Properties * | ForEach-Object {($_.memberof | Get-ADGroup).SamAccountName}
                    Foreach($Group in $List) { Remove-ADGroupMember -Identity $Group -Members $UserAccount -Confirm:$false } 
                    $TextBox_Output.AppendText("Removed all groups form $UserAccount") }
                    Set-StatusBarReady 
            } Else {
                Clear-Output
                $UserAccount = $ComboBox_Users.Text.ToString()
                $List = get-aduser $UserAccount -Properties * | ForEach-Object {($_.memberof | Get-ADGroup).SamAccountname} | Sort-Object | Out-GridView -PassThru -Title "Select Groups"
                Foreach($Group in $List) { Remove-ADGroupMember -Identity $Group -Members $UserAccount -Confirm:$false } 
                $TextBox_Output.AppendText("All selected groups have been removed form $UserAccount")
            }
        } Catch { Write-OutError }
    }
}

# Moves Account OU
Function Move-AD_User {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } Else {
        Try {
            Clear-Output
            $ORG = $AD_OUs | Out-GridView -PassThru -Title "Select Organizational Unit"
            $User = $ComboBox_Users.SelectedItem.ToString() 
            $ORG_move = $ORG.CanonicalName
            $User_Move = Get-ADuser -Identity $ComboBox_Users.SelectedItem -Properties * | select DistinguishedName 
            Move-ADObject -Identity $User_Move.DistinguishedName -TargetPath $ORG.DistinguishedName
            $TextBox_Output.text = "Moved $User to $ORG_move"
        } Catch { Write-OutError }
    }
}

# Removes AD account
Function Remove-AD_User {

    IF ($ComboBox_Users.SelectedItem -eq $null) {
        Set-Output_ADuserNull
        } Else {
        Try {
            $UserAccount = $ComboBox_Users.SelectedItem.ToString()
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("   Remove $UserAccount from AD?", 0, "Remove User account", 0x4 + 0x10)
    
                IF ($Answer -eq 6) {
                
                Clear-Output
                $User = $ComboBox_Users.SelectedItem.ToString() 
                Remove-ADuser $User -Confirm:$false -ErrorAction Stop
                $TextBox_Output.text = "Removed $User from Active Directory"

                $script:AD_Users -ne $user
                [void]$ComboBox_Users.Items.remove($user)
                [void]$ComboBox_Users.AutoCompleteCustomSource.Remove($user) 
                Save-ADdata

            } Else { 
                Clear-Output
                $TextBox_Output.AppendText("Remove account canceled") 
            }
        } Catch { Write-OutError }
    }
}



# Computer Functions
#===========================================================

Function Get-AD_ComputerFullInfo {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
    } Else {
    Try {
        Clear-Output
        $TextBox_Output.text = Get-ADComputer $ComboBox_Computers.SelectedItem -Properties * | Format-List | Out-String -Width 2147483647 
        } Catch { Write-OutError }
    }
}

Function Test-AD_ComputerConnection{

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
    } Else {
    Try {
        $Computer = $ComboBox_Computers.SelectedItem.ToString()
        Clear-Output
        $Test = Test-Connection $ComboBox_Computers.SelectedItem -Count 1 -Quiet
        switch ($Test)
            {
            $true{ $TextBox_Output.text = "Connection to $Computer was successful"}
            $false{ $TextBox_Output.text = "Connection to $Computer Failed"}       
            }
        } Catch { Write-OutError }
    }
}


Function Connect-AD_Computer{

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } Else {
        Try {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            Clear-Output
            $TextBox_Output.text = "Connceting to $Computer"
            Start-Process mstsc.exe -ArgumentList "/v:$Computer"
        } Catch { Write-OutError }
    }
}


Function Start-AD_ComputerEventViewer {
    
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull 
        } Else {
        Try {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            Clear-Output
            $TextBox_Output.text = "Opening Event viewer to $Computer"
            Start-Process eventvwr.exe -ArgumentList "$Computer"
        } Catch { Write-OutError }
    }
}


Function Start-AD_ComputerManagement {
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } Else {
        Try {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            Clear-Output
            $TextBox_Output.text = "Opening Computer Management to $Computer"
            Start-Process compmgmt.msc -ArgumentList "/s /computer:\\$Computer"
        } Catch { Write-OutError }
    }
}


Function Get-AD_ComputerMembers {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } Else {
        Try {
            Clear-Output
            $Computer = $ComboBox_Computers.SelectedItem.ToString()
            $TextBox_Output.text = Get-ADComputer $Computer -Properties * | ForEach-Object {($_.memberof | Get-ADGroup | Select-Object -ExpandProperty Name)} | Format-List | Out-String -Width 2147483647
        } Catch { Write-OutError }
    }
}

Function Copy-AD_ComputerMembers {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } Else {
        Try {
            $ComputerAccount = $ComboBox_Computers.Text.ToString()
            $CopyComputer = $AD_Computers.name | Sort-Object | Out-GridView -PassThru -Title "Select Account" 
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("        Copy all Groups form $CopyComputer?", 0, "Copy", 0x4 + 0x20)
            IF ($Answer -eq 6) {
                $StatusBar.text = "Copying All Groups from $CopyComputer"
                $List = Get-ADComputer $CopyComputer -Properties * | ForEach-Object {($_.memberof | Get-ADGroup).SamAccountName } 
                Foreach($Group in $List) { Add-ADGroupMember -Identity $Group -Members "$ComputerAccount`$" -Confirm:$false -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 0.2 } 
                Clear-Output
                $TextBox_Output.AppendText("All groups from $CopyComputer have been added to $ComputerAccount")
                Set-StatusBarReady
            }
        } Catch { Write-OutError }
    }
}


Function Add-AD_ComputerToGroup {

     IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } Else {
        Try {
            Clear-Output
            $ComputerAccount = $ComboBox_Computers.Text.ToString()
            $List = $AD_Groups | Out-GridView -PassThru -Title "Select Group(s)"
            Foreach($Group in $List) { Add-ADGroupMember -Identity $Group -Members "$ComputerAccount$" -Confirm:$false } 
            $TextBox_Output.AppendText("$ComputerAccount has now been added to selected Groups")
        } Catch { Write-OutError }
    }
} 


Function Remove-AD_ComputerFromGroup {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } Else {
        Try {
            $ComputerAccount = $ComboBox_Computers.Text.ToString()      
            IF ($ListBox_Computers.SelectedItem -eq "Remove All Groups") {
             $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Remove all Groups from $ComputerAccount?", 0, "Remove", 0x4 + 0x30)
                IF ($Answer -eq 6) {
                    Clear-Output
                    $StatusBar.text = "Removing All Groups"
                    Start-Sleep -Milliseconds 0.2
                    $List = Get-ADComputer $ComputerAccount -Properties * | ForEach-Object {($_.memberof | Get-ADGroup).SamAccountName}
                    Foreach($Group in $List) { Remove-ADGroupMember -Identity $Group -Members "$ComputerAccount$" -Confirm:$false } 
                    $TextBox_Output.AppendText("Removed all groups form $ComputerAccount") }
                    Set-StatusBarReady 
            
            } Else {
                Clear-Output
                $List = Get-ADComputer $ComputerAccount -Properties * | ForEach-Object {($_.memberof | Get-ADGroup | Select-Object -ExpandProperty Name)} | Sort-Object | Out-GridView -PassThru -Title "Select Groups"
                Foreach($Group in $List) { Remove-ADGroupMember -Identity $Group -Members "$ComputerAccount$" -Confirm:$false } 
                $TextBox_Output.AppendText("All selected groups have been removed form $ComputerAccount")
            }
        } Catch { Write-OutError }
    }
}

# Moves Computers OU
Function Move-AD_Computer {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } Else {
        Try {
            Clear-Output
            $ORG = $AD_OUs | Out-GridView -PassThru -Title "Select Organizational Unit"
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            $ORG_move = $ORG.CanonicalName
            $Computer_Move = Get-ADComputer $ComboBox_Computers.SelectedItem -Properties * | select DistinguishedName 
            Move-ADObject -Identity $Computer_Move.DistinguishedName -TargetPath $ORG.DistinguishedName
            $TextBox_Output.text = "Moved $Computer to $ORG_move"
        } Catch { Write-OutError }
    }
}

# Removes AD Computer account
Function Remove-AD_Computer {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } Else {
        Try {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Remove $Computer from AD?", 0, "Remove", 0x4 + 0x10)
    
            IF ($Answer -eq 6) {
                Clear-Output
                Remove-ADComputer $Computer -Confirm:$false -ErrorAction Stop
                $TextBox_Output.text = "Removed $Computer from Active Directory"

                $AD_Computers -ne $Computer
                [void]$ComboBox_Computers.Items.remove($Computer)
                [void]$ComboBox_Computers.AutoCompleteCustomSource.Remove($Computer) 
                Save-ADdata

            } Else { 
                Clear-Output
                $TextBox_Output.AppendText("Remove account canceled") 
            }
        } Catch { Write-OutError }
    }
}

Function Invoke-AD_ComputerPolicyUpdate {
    
    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } Else {
        Try {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("Restart $Computer after group policy update?", 0, "Gpupdate", 0x4 + 0x10)
    
                IF ($Answer -eq 6) {
                Clear-Output
                Invoke-GPUpdate -Computer $Computer -Force -Boot -ErrorAction Stop
                $TextBox_Output.text = "Group policy update request sent to $Computer with restart"
            } Else { 
                Clear-Output
                Invoke-GPUpdate -Computer $Computer -Force -ErrorAction Stop
                $TextBox_Output.Text = "Group policy update request sent to $Computer"
            }
        } Catch { Write-OutError }
    }
}

Function Restart-AD_Computer {

    IF ($ComboBox_Computers.SelectedItem -eq $null) {
        Set-Output_ADComputerNull
        } Else {
        Try {
            $Computer = $ComboBox_Computers.SelectedItem.ToString() 
            $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("    Restart $Computer`?", 0, "Restart?", 0x4 + 0x10)
    
                IF ($Answer -eq 6) {
                
                Clear-Output
                
                Restart-Computer $Computer -Force -Confirm:$false -ErrorAction Stop
                $TextBox_Output.text = "Restart request sent to $Computer"
            } Else { 
                Clear-Output
                $TextBox_Output.AppendText("Restart Canceled") 
            }
        } Catch { Write-OutError }
    }
}

# Groups Functions
#===========================================================

Function GroupMembers {
    
        IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
        } Else {
            Try {
            Clear-Output
            $TextBox_Output.text = (Get-ADGroupMember -Identity $ComboBox_Groups.SelectedItem).Name  | Sort-Object | Out-String -Width 2147483647
        } Catch { Write-OutError }
    }
}


Function GroupInfo {
    
    IF ($ComboBox_Groups.SelectedItem -eq $null) {
    Set-Output_ADGroupNull
    } Else {
        Try {
        Clear-Output
        $TextBox_Output.text = Get-ADGroup $ComboBox_Groups.SelectedItem -Properties * | FL | Out-String -Width 2147483647
        } Catch { Write-OutError }
    }
}

  
Function Add-UserMember {

    IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
        } Else {
        Try {
            $GroupOBJ = $ComboBox_Groups.Text.ToString()
            Clear-Output
            $Members = $AD_Users | Out-GridView  -Title "Select Member(s) to add to $GroupOBJ" -PassThru 
            $Members = (Get-ADUser $Members -Properties *).SamAccountname 
            Add-ADGroupMember -Identity $ComboBox_Groups.text -Members $Members -ErrorAction Stop 
            $TextBox_Output.AppendText("Members added to $GroupOBJ Group")
        } Catch { Write-OutError }
    }
}


Function Add-ComputerMember {

   IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
    } Else {
        Try {
            $GroupOBJ = $ComboBox_Groups.Text.ToString()
            Clear-Output
            $Members = Get-ADComputer -Filter * | select Name, SamAccountname | Out-GridView  -Title "Select Member(s) to add to $GroupOBJ" -PassThru 
            Add-ADGroupMember -Identity $ComboBox_Groups.text -Members $Members.SamAccountName -ErrorAction Stop 
            $TextBox_Output.AppendText("Members added to $GroupOBJ Group")
        } Catch { Write-OutError }
    }
}


Function Add-GroupMember {

   IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
    } Else {
        Try {
            $GroupOBJ = $ComboBox_Groups.Text.ToString()
            Clear-Output
            $Members = Get-ADGroup -Filter * | select Name | Out-GridView  -Title "Select Member(s) to add to $GroupOBJ" -PassThru 
            Add-ADGroupMember -Identity $ComboBox_Groups.text -Members $Members.SamAccountName -ErrorAction Stop 
            $TextBox_Output.AppendText("Members added to $GroupOBJ Group")
        } Catch { Write-OutError }
    }
}


Function Remove-Member {

    IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull 
        } Else {
        Try {
            Clear-Output
            $GroupOBJ = $ComboBox_Groups.Text.ToString()
            $Members = Get-ADGroup $ComboBox_Groups.SelectedItem | Get-ADGroupMember | Select-Object Name,SamAccountName | Out-GridView -Title "Select Member(s) to remove from $GroupOBJ" -PassThru
            Get-ADGroup $ComboBox_Groups.SelectedItem | remove-adgroupmember -Members $members.SamAccountName -Confirm:$false -ErrorAction Stop
            $TextBox_Output.AppendText("Removed members from $GroupOBJ Group")
        } Catch { Write-OutError }
    }
}


Function Move-AD_Group {

    IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
        } Else {
        Try {
            Clear-Output
            $ORG = $AD_OUs | Out-GridView -PassThru -Title "Select Organizational Unit"
            $Group = $ComboBox_Groups.SelectedItem.ToString() 
            $ORG_move = $ORG.CanonicalName
            $Group_Move = Get-ADGroup $ComboBox_$Groups.SelectedItem -Properties * | select DistinguishedName 
            Move-ADObject -Identity $Computer_Move.DistinguishedName -TargetPath $ORG.DistinguishedName
            $TextBox_Output.text = "Moved $Group to $ORG_move"
        } Catch { Write-OutError }
    }
}

Function Remove-AD_Group {

    IF ($ComboBox_Groups.SelectedItem -eq $null) {
        Set-Output_ADGroupNull
        } Else {
        Try {
        $Group = $ComboBox_Groups.Text.ToString()
        $UserPrompt = new-object -comobject wscript.shell
                $Answer = $UserPrompt.popup("        Remove $Group from AD?", 0, "Remove", 0x4 + 0x10)
    
            IF ($Answer -eq 6) {
                Clear-Output
                Remove-ADGroup $Group -Confirm:$false -ErrorAction Stop
                $TextBox_Output.text = "Removed $Group from Active Directory"

                $AD_Groups -ne $Group
                [void]$ComboBox_Groups.Items.remove($Group)
                [void]$ComboBox_Groups.AutoCompleteCustomSource.Remove($Group) 
                Save-ADdata
            }
        } Catch { Write-OutError }
    }
}



#===================== Menu Functions ======================

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
        } 

       Else {
            Clear-Output
            Set-StatusBarReady
            $OutputTB.AppendText("Exported canceled")
    }
}


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
        }

        Else {
            Clear-Output
            Set-StatusBarReady
            $TextBox_Output.AppendText("Exported canceled")
    }
} 


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
            $List += Foreach($Group in $Groups) { New-Object PSObject -Property @{

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
        }
        
        Else {
            Clear-Output
            Set-StatusBarReady
            $TextBox_Output.AppendText("Exported canceled")
    }
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
    $script:Exchange_Contacts                    = $Exchange_XML.Contacts | Sort-Object
 
 }

Function Import-ExchangeData {

    $script:Exchange_Users                  = (Get-User -ResultSize Unlimited | Where-Object {$_.RecipientType -eq "user" -and $_.RecipientTypeDetails -ne "DisabledUser"}).SamAccountName | Sort-Object
    $script:Exchange_Mailboxes              = (Get-mailbox -ResultSize Unlimited -WarningAction SilentlyContinue).SamAccountName | Sort-Object
    $script:Exchange_DistributionGroups     = (Get-DistributionGroup -ResultSize Unlimited).SamAccountName | Sort-Object
    $script:Exchange_Contacts               = (Get-Contact).Name | Sort-Object

}

# Imports All Exchange objects 
Function Enable-Exchange {
    
    Clear-Output
    $GroupBox_ConnectToExchange.Enabled = $false    
    $StatusBarLabel.text = "  Loading Exchange Objects"

    #Connect to Exchange
    try { 

        $ConnectionUri = $Textbox_Exchange.text
        $UserCredential = Get-Credential 
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ConnectionUri/PowerShell/" -Authentication Kerberos -Credential $UserCredential -ErrorAction Stop
        Import-PSSession $Session -DisableNameChecking -ErrorAction Stop

        IF (test-path "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml") {
        
            $LastWriteTime = (Get-ItemProperty "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml").LastWriteTime
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("Load Exchange data from local cache? `n`nCache was Last updated on $LastWriteTime", 0, " Load from cache", 0x4 + 0x20)

            switch ($Answer) {

            6           { Import-ExchangeXML }
            Default     { Import-ExchangeData }  
            
            }
        
        } Else { Import-ExchangeData }
         
        ForEach ($Mailbox in $Exchange_Mailboxes) { [void]$ComboBox_Mailbox.Items.Add($Mailbox) }
        $ComboBox_Mailbox.AutoCompleteSource = "CustomSource" 
        $ComboBox_Mailbox.AutoCompleteMode = "SuggestAppend"
        $Exchange_Mailboxes | ForEach-Object { [void]$ComboBox_Mailbox.AutoCompleteCustomSource.Add($_) }

        ForEach ($DistributionGroup in $Exchange_DistributionGroups) { [void]$ComboBox_Distributionlist.Items.Add($DistributionGroup) }
        $ComboBox_Distributionlist.AutoCompleteSource = "CustomSource" 
        $ComboBox_Distributionlist.AutoCompleteMode = "SuggestAppend"
        $Exchange_DistributionGroups | ForEach-Object { [void]$ComboBox_Distributionlist.AutoCompleteCustomSource.Add($_) }

        ForEach ($Contact in $Exchange_Contacts) { [void]$ComboBox_Contacts.Items.Add($Contact) }
        $ComboBox_Contacts.AutoCompleteSource = "CustomSource" 
        $ComboBox_Contacts.AutoCompleteMode = "SuggestAppend"
        $Exchange_Contacts | ForEach-Object { [void]$ComboBox_Contacts.AutoCompleteCustomSource.Add($_) }
        
        $Panel_Exchange.Enabled = $true
        $Menu_Exchange.Enabled = $true
       
        Save-Exchangedata
        Set-StatusBarReady
        $TextBox_Output.AppendText("*** Exchange objects have been loaded ***")  
                                
        
    } catch {
    Write-OutError
    Set-StatusBarReady
    $GroupBox_ConnectToExchange.Enabled = $true
    } 

}


# Save Exchange data to cache
Function Save-Exchangedata {
        
    Try {
        
        New-Object PSObject -Property @{

            Server          = $Textbox_Exchange.text.toString()
            Users           = $Exchange_Users  
            Mailboxs        = $Exchange_Mailboxes  
            Groups          = $Exchange_DistributionGroups  
            Contacts        = $Exchange_Contacts 
        
        } | Export-Clixml "$env:PUBLIC\Ultimate Administrator Console\Exchange.xml"
    } Catch { Write-OutError }
}

# Start Mailbox Action
Function Start-Mailbox_Action {


    IF ($ListBox_Mailbox.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    Else { 
      try { 
        switch ($ListBox_Mailbox.SelectedItem) {
        
            "Mailbox info"                                      { Get-MailBox_info }
            "List all permissions"                              { Get-MailBox_Permissions }
            "Add full access permissions to mailbox"            { Add-MailBox_FullAccessPermissions }
            "Add send as permissions"                           { Add-MailBox_SendasPermissions }
            "Add send on behalf of permissions"                 { Add-MailBox_SendOnBehalfToPermissions  }
            "Remove permissions"                                { }
            "Set out of office message"                         { }
            "Set mail forwarding"                               { }
            "Convert to ..."                                    { Set-Mailbox_Type }
            "Hide/un-hide form global address list"             { Set-Mailbox_ToHidden-UnHidden }
            "Move to Database"                                  { Move-Mailbox_DataBase }
            "Export to .PST ( on-premises only )"               { }
            "Remove mailbox"                                    { Remove-Mailbox_fromuser }

            } 
        } Catch { Write-OutError }
    }
}

# Start Distributionlist Action
Function Start-Distributionlist_Action {


    IF ($ListBox_Distributionlist.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    Else { 
      try { 
        switch ($ListBox_Mailbox.SelectedItem) {
        
            "Distribution Group info"                           {}
            "List all members"                                  {}
            "Add members"                                       {}
            "Remove members"                                    {}
            "Set Owner"                                         {}
            "Hide/un-hide form global address list"             {}
            "Remove Distribution Group"                         {}
    
            } 
        } Catch { Write-OutError }
    }
}

# Start Contact Action
Function Start-Contacts_Action {


    IF ($ListBox_Contacts.SelectedItem -eq $null) {
        Clear-Output
        $TextBox_Output.AppendText("No App Selected") 
    }

    Else { 
      try { 
        switch ($ListBox_Contacts.SelectedItem) {
        
            "Contacts info"                                    {}
            "Hide/un-hide form global address list"            {}
            "Remove Contacts"                                  {}
    
            } 
        } Catch { Write-OutError }
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

Function Set-Output_ContactsNull {
    Clear-Output
    $TextBox_Output.AppendText("No Contact Selected")
}

#===================== Mailbox Functions ======================

function Enable-Mailbox_foruser {
   
    Try{

        $list = $Exchange_Users | Out-GridView -PassThru -Title "Select User"
        $User = $list.ToString()
        Enable-Mailbox $User -ErrorAction Stop    
        $StatusBarLabel.text = "  Creating Mailbox for $User"
        Start-Sleep 5
        $Mailbox = (Get-mailbox $User).UserPrincipalName
       
        $ComboBox_Users.Text = $Null
        $Exchange_Users -ne $User
        $Exchange_Mailboxes += $Mailbox
        [void]$ComboBox_Mailbox.Items.add($Mailbox)
        [void]$ComboBox_Mailbox.AutoCompleteCustomSource.add($Mailbox) 
        $TextBox_Output.text = "$User mailbox $Mailbox is now enabled"
        Save-Exchangedata
        Set-StatusBarReady

    } Catch { Write-OutError }
}

function Get-MailBox_info {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } Else {
    Try {
        Clear-Output
        $TextBox_Output.text = Get-Mailbox $ComboBox_Mailbox.SelectedItem -ErrorAction Stop | Format-List | Out-String -Width 2147483647 
        } Catch { Write-OutError }
    }
}


function Get-MailBox_Permissions {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } Else {
    Try {
        Clear-Output
        $TextBox_Output.text = Get-MailboxPermission $ComboBox_Mailbox.SelectedItem -ErrorAction Stop | select user, accessrights, IsInherited, Deny | Out-String -Width 2147483647 
        } Catch { Write-OutError }
    }
}

function Add-MailBox_FullAccessPermissions {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } Else {
    Try {
        Clear-Output
        $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
        $List = $Exchange_Mailboxes | Out-GridView -PassThru -Title "Select Mailbox" 
        $Member = $List.SamAccountName.ToString()
        Add-MailboxPermission -Identity $Mailbox -User $Member -AccessRights FullAccess -InheritanceType All -Confirm:$false -ErrorAction Stop 
        $TextBox_Output.text = "$Member has been given full permissions to $Mailbox"
        } Catch { Write-OutError }
    }
}

function Add-MailBox_SendasPermissions {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } Else {
    Try {
        Clear-Output
        $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
        $List = $Exchange_Mailboxes | Out-GridView -PassThru -Title "Select Mailbox" 
        $Member = $List.SamAccountName.ToString()
        Add-RecipientPermission -Identity $Mailbox -AccessRights SendAs -Trustee $Member -Confirm:$false -ErrorAction Stop
        $TextBox_Output.text = "$Member has been given Send as permissions to $Mailbox"
        } Catch { Write-OutError }
    }
}
 
function Add-MailBox_SendOnBehalfToPermissions {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } Else {
    Try {
        Clear-Output
        $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
        $List = $Exchange_Mailboxes | Out-GridView -PassThru -Title "Select Mailbox" 
        $Member = $List.SamAccountName.ToString()
        Set-Mailbox -Identity $Mailbox -GrantSendOnBehalfTo @{add=$Member} -ErrorAction Stop
        $TextBox_Output.text = "$Member has been given Send On Behalf To permissions to $Mailbox"
        } Catch { Write-OutError }
    }
}



function Set-Mailbox_Type {
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
    Set-Output_MailBoxNull 
        } Else {
        Try {
            Clear-Output
            $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
        
                $Type = @{
                'Regular'           = 'Regular mailboxes are the mailboxes that get assigned to every individual Exchange user'
                'Shared'            = 'Shared mailboxes are usually configured for multiple user access'
                'Equipment'         = 'These mailboxes are used for resources that are not location-specific like the portable system, microphones, projectors, or company cars.'
                'Room'              = 'This kind of mailbox gets assigned to different meeting locations, for example, auditoriums, conference and training rooms.'
            }
            
            $Result = $Type | Out-GridView -PassThru  -Title 'Make a  selection'
        
            Switch ($Result) {
                { $Result.Name -eq 'Regular'   }  { $Type = 'Regular'   }
                { $Result.Name -eq 'Shared'    }  { $Type = 'Shared'    }
                { $Result.Name -eq 'Equipment' }  { $Type = 'Equipment' }
                { $Result.Name -eq 'Room'      }  { $Type = 'Room'      }
            }   
           
            Set-mailbox $Mailbox -type $Type -Confirm:$false
            $TextBox_Output.text = "Convering $Mailbox to $Type" 

        } Catch { Write-OutError }
    }
}

# Sets HiddenFromAddressListsEnabled to true for each selected Mailbox(s) (Not DirSynced)
function Set-Mailbox_ToHidden-UnHidden {

  IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
    Set-Output_MailBoxNull 
        } Else {
        Try {
            Clear-Output
            $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
            $Result  = (get-mailbox $Mailbox).HiddenFromAddressListsEnabled
            
            Switch ($Result) { 
            false { Set-Mailbox -Identity $Mailbox -HiddenFromAddressListsEnabled $true 
                    $TextBox_Output.text = "$Mailbox to is now hidden from global address list" 
                  }
            
            true  { Set-Mailbox -Identity $Mailbox -HiddenFromAddressListsEnabled $false
                    $TextBox_Output.text = "$Mailbox to is now visble in global address list"            
                 }
            }
        } Catch { Write-OutError }
    }
}


# Moves mailbox to requested database

function Move-Mailbox_DataBase {
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
    Set-Output_MailBoxNull 
        } Else {
        Try {
            Clear-Output
            $Mailbox = $ComboBox_Mailbox.SelectedItem.ToString()
            $UserPrompt = new-object -comobject wscript.shell
            $DataBase = (get-mailboxdatabase | ogv -PassThru).name
            $Answer = $UserPrompt.popup("Move $Mailbox to $DataBase datebase?", 0, "Gpupdate", 0x4 + 0x10)
    
                IF ($Answer -eq 6) {
                
                Clear-Output
                New-MoveRequest -Identity $Mailbox -TargetDatabase $DataBase
                $TextBox_Output.text = "$Mailbox move requested to $DataBase datebase has started"
            } Else { 
                Clear-Output
                $TextBox_Output.Text = "Move requested canceled"
            }
        } Catch { Write-OutError }
    }
}

function Remove-Mailbox_fromuser {    
    
    IF ($ComboBox_Mailbox.SelectedItem -eq $null) {
        Set-Output_MailBoxNull 
    } Else {
    Try {

        $UserAccount = $ComboBox_Mailbox.SelectedItem.ToString()
        $UserPrompt = new-object -comobject wscript.shell
        $Answer = $UserPrompt.popup("   Delete $UserAccount`?", 0, "Remove Mailbox", 0x4 + 0x10)
    
            IF ($Answer -eq 6) {
                Clear-Output

                $Del_Mailbox = Get-MailBox $ComboBox_Mailbox.SelectedItem | Select-Object SamAccountName, UserPrincipalName  
                $User = $Del_Mailbox.SamAccountName.Tostring()
                $Mailbox = $Del_Mailbox.UserPrincipalName.Tostring()
        
                Disable-Mailbox $User -Confirm:$false -ErrorAction Stop 

                $ComboBox_Users.Text = $Null
                $Exchange_Users += $User
                $Exchange_Mailboxes -ne $Mailbox
                [void]$ComboBox_Mailbox.Items.remove($Mailbox)
                [void]$ComboBox_Mailbox.AutoCompleteCustomSource.remove($Mailbox) 
                $TextBox_Output.text = "Mailbox $Mailbox is now Deleted"
                Save-Exchangedata
            
         } Else { 
            Clear-Output
            $TextBox_Output.AppendText("Remove account canceled") 
            } 
        } Catch { Write-OutError }
    }
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
    MinimumSize            = '1170,720'
    TopMost                = $false
    Icon                   = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command WMIC.exe).Path) #[System.IconExtractor]::Extract("imageres.dll", 311, $true)
    KeyPreview             = $true
    Opacity                = 0.99
}

# Shortcuts
<#F1#>  $Form.add_KeyDown({IF($_.keycode -eq "F1"){ Start-Process PowerShell.exe }})
<#F2#>  $Form.add_KeyDown({IF($_.keycode -eq "F2"){ Clear-Output }})
<#F3#>  $Form.add_KeyDown({IF($_.keycode -eq "F3"){ Copy_Outbox  }})
<#F4#>  $Form.add_KeyDown({IF($_.keycode -eq "F4"){ Copy_Notepad }})
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
$Menu_File_Space                         = New-Object System.Windows.Forms.ToolStripSeparator
$Menu_NewAdminProfile                    = New-Object System.Windows.Forms.ToolStripMenuItem
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
$Menu_Help                               = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_About                              = New-Object System.Windows.Forms.ToolStripMenuItem

## text ##
$Menu_File.Text                          = "File"
$Menu_NewAdminProfile.Text               = "New Admin Profile"
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
$Menu_Help.Text                          = "Help"
$Menu_About.Text                         = "About"

## Functions ##
$Menu_NewAdminProfile.Add_Click({  })
$Menu_Exit.Add_Click({ $Form.close() })
$Menu_Shell_CMD.Add_click({ Start-Process CMD.exe })
$Menu_Shell_PowerShell.Add_click({ Start-Process PowerShell.exe }) 
$Menu_Shell_PowerShell_ISE.Add_click({ ISE })
$Menu_About.Add_Click({ Show-About })
$Menu_AD_ExportUsers.Add_Click({ CSVAdUserExport })
$Menu_AD_ExportComputers.Add_Click({ CSVComputerExport })
$Menu_AD_ExportGroups.Add_Click({ CSVGroupsExport })

## Disabled ## 
$Menu_AD.Enabled             = $false
$Menu_Exchange.Enabled       = $false

## Controls ##

# file
[void]$Menu_File.DropDownItems.AddRange(@(
    $Menu_NewAdminProfile 
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

# Help
[void]$Menu_Help.DropDownItems.AddRange(@(
    $Menu_About
))

#Icons
$Menu_NewAdminProfile.Image          = [System.IconExtractor]::Extract("Shell32.dll", 47, $true)
$Menu_Exit.Image                     = [System.IconExtractor]::Extract("imageres.dll", 84, $true)
$Menu_Shell_CMD.Image                = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command CMD.exe).Path)
$Menu_Shell_PowerShell.Image         = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command PowerShell).Path)
$Menu_Shell_PowerShell_ISE.Image     = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command PowerShell_ISE.exe).Path)
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
    Appearance = 2
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
$TabPage_ControlPanel.Text     = "Control"
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
    $TabPage_365
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
    "ACL folder info"
    "Clean Disk Manager"
    "DirectX Diagnostic Tool"
    "Disk Manager"
    "Device Management"
    "Event Viewer"
    "Enable Ultimate Performance"
    "Firewall"
    "Internet Properties"
    "Invoke Group policy update"
    "Network Properties"
    "Optional Features"
    "Registry Editor"
    "Reliability Monitor"
    "Remote Desktop"
    "Services"
    "Show Wifi Passwords"
    "Start Windows Defender Offline Scan"
    "System Information" 
    "System Configuration Utility"
    "System Properties"
    "Task Manager"
    "Task Scheduler"
    "Text to Wave"
    "Windows Version"
    "Windows Update"
))


$Button_GetComputerinfo = New-Object System.Windows.Forms.Button -Property @{
    Location        = "5,255"
    Size            = "128,35"
    Text            = "Computer info"
    FlatStyle       = "Flat"
}
$Button_GetComputerinfo.FlatAppearance.BorderSize = 0


$Button_WindowsAction = New-Object System.Windows.Forms.Button -Property @{
    Location         = "273,255"
    Size             = "128,35"
    FlatStyle        = "Flat"
}
$Button_WindowsAction.FlatAppearance.BorderSize = 0
$Button_WindowsAction.Image = $Icon_OK

# Controls
$ListBox_windows.add_MouseDoubleClick({ start_windowapp })
$ListBox_windows.add_KeyDown({IF($_.keycode -eq "Enter"){ start_windowapp }})
$ListBox_windows.add_KeyDown({IF($_.keycode -eq "Space"){ start_windowapp }})
$Button_GetComputerinfo.add_Click({ Get-ComputerInfo_Output })
$Button_WindowsAction.add_Click({ start_windowapp })

$GroupBox_Windows.Controls.AddRange(@(
    $ListBox_windows
    $Button_GetComputerinfo 
    $Button_WindowsAction
)) 


# Windows Server Tools - GroupBox
#===========================================================

$GroupBox_WindowServer = New-Object System.Windows.Forms.GroupBox -Property @{
    Location               = "5,325"
    Size                   = "409, 250"
    Text                   = "Windows Server Tools"
}

$ListBox_WindowServer = New-Object System.Windows.Forms.ListBox -Property @{
    Location                = "7, 14"
    Size                    = "394,190"
    BorderStyle             = 0
    HorizontalScrollbar     = 1    
}

$ListBox_WindowServer.Items.AddRange(@(
    "Active Directory Administrative Center"
    "Active Directory Domains and Trusts"
    "Active Directory Sites and Services"
    "Active Directory Users and Computers"
    "ADSI Edit"
    "Computer Management"
    "File Server Resource Manager"
    "DHCP"
    "DNS"
    "File Server Resource Manager" 
    "Group Policy Management"
    "Print Management"
    "Server Manager"
    "Volume Activation Tools"
    "Windows Defender Firewall with Advanced Security"    
    "Windows Server Update Services"
))

$Button_InstallRsat = New-Object System.Windows.Forms.Button -Property @{
    Location            = "5,205"
    Size                = "128,35"
    Text                = "Install RSAT"
    FlatStyle           = "Flat"
}
$Button_InstallRsat.FlatAppearance.BorderSize = 0

$Button_WindowServerAction = New-Object System.Windows.Forms.Button -Property @{
    Location            = "273,205"
    Size                = "128,35"
    FlatStyle           = "Flat"
}
$Button_WindowServerAction.FlatAppearance.BorderSize = 0
$Button_WindowServerAction.Image = $Icon_OK

#Controls
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
    Size               = "409, 560"
    Text               = "Control Panel items"
}

$ListBox_ControlPanel = New-Object System.Windows.Forms.ListBox -Property @{
    name                = "ListBox_windows"
    Location            = "7, 14"
    Size                = "394,500"
    BorderStyle         = 0
    HorizontalScrollbar = 1
}

$ControlPanelItem = (Get-ControlPanelItem).Name
foreach($Item in $ControlPanelItem) {$ListBox_ControlPanel.Items.AddRange($Item)} 

$Button_Godmode = New-Object System.Windows.Forms.Button -Property @{
    Location       = "5,515"
    Size           = "128,35"
    Text           = "Godmode"
    FlatStyle      = "Flat"
}
$Button_Godmode.FlatAppearance.BorderSize = 0


$Button_ControlPanel = New-Object System.Windows.Forms.Button -Property @{
    Location        = "273,515"
    Size            = "128,35"
    FlatStyle       = "Flat"
}
$Button_ControlPanel.FlatAppearance.BorderSize = 0
$Button_ControlPanel.Image = $Icon_OK

# Controls
$ListBox_ControlPanel.add_MouseDoubleClick({ Start-ControlPanelItem })
$ListBox_ControlPanel.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-ControlPanelItem }})
$ListBox_ControlPanel.add_KeyDown({IF($_.keycode -eq "Space"){ Start-ControlPanelItem }})
$Button_Godmode.add_Click({ Godmode })
$Button_ControlPanel.add_Click({ Start-ControlPanelItem })

$GroupBox_ControlPanel.Controls.AddRange(@(
    $ListBox_ControlPanel
    $Button_Godmode 
    $Button_ControlPanel
)) 

$TabPage_ControlPanel.Controls.AddRange(@(
    
    $GroupBox_ControlPanel
))


#endregion Windows


#region Active Directory

#=========================================================================#
#                          Active Directory UI                            # 
#=========================================================================#

## TabPage AD ##
##===================================================================================================##

$Panel_ActiveDirectory = New-Object System.Windows.Forms.Panel -Property @{
    Location           = "0,0"
    Size               = "430, 560"
    Enabled            = $false
}

# User accounts GroupBox 
#===========================================================

$GroupBox_Users = New-Object System.Windows.Forms.GroupBox -Property @{
    Location            = "5,10"
    Size                = "409, 192"
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
    Location            = "7, 42"
    Size                = "394,105"
    BorderStyle         = 0
    HorizontalScrollbar = 1    
}


$ListBox_Users.Items.AddRange(@(
    "Account info"
    "List all groups"
    "Reset Password"
    "Unlock account"
    "Disable/Enable Account"
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
    Location       = "5,150"
    Size           = "128,35"
    Text           = "New User"
    FlatStyle      = "Flat"
}
$Button_NewUser.FlatAppearance.BorderSize = 0


$Button_UserAction = New-Object System.Windows.Forms.Button -Property @{
    Location        = "273,150"
    Size            = "128,35"
    FlatStyle       = "Flat"
}
$Button_UserAction.FlatAppearance.BorderSize = 0
$Button_UserAction.Image = $Icon_OK

# Controls
$ComboBox_Users.add_TextChanged({ Get-AD_UserFullInfo })
$ListBox_Users.add_MouseDoubleClick({ Start-AD_UserFunction })
$ListBox_Users.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-AD_UserFunction }})
$ListBox_Users.add_KeyDown({IF($_.keycode -eq "Space"){ Start-AD_UserFunction }})
$Button_NewUser.add_Click({ New-UserUI })
$Button_UserAction.add_Click({ Start-AD_UserFunction })

$GroupBox_Users.Controls.AddRange(@( 
    $ComboBox_Users
    $ListBox_Users
    $Button_NewUser
    $Button_UserAction
))

# CPU GroupBox
#===========================================================

$GroupBox_Computers = New-Object System.Windows.Forms.GroupBox -Property @{
    Location            = "5,210"
    Size                = "409, 192"
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
    Location            = "7, 42"
    Size                = "394,105"
    BorderStyle         = 0
    HorizontalScrollbar = 1    
}

$ListBox_Computers.Items.AddRange(@(
    "Computer info"
    "List all Groups"
    "Test Connectivity"
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
$Button_ComputerAction =  New-Object System.Windows.Forms.Button -Property @{
    Location    = "273,150"
    Size        = "128,35"
    FlatStyle   = "Flat"
}
$Button_ComputerAction.FlatAppearance.BorderSize = 0
$Button_ComputerAction.Image = $Icon_OK

# controls
$ComboBox_Computers.add_TextChanged({ Get-AD_ComputerFullInfo })
$ListBox_Computers.add_MouseDoubleClick({ Start-AD_ComputerFunction })
$ListBox_Computers.add_KeyDown({IF($_.keycode -eq "Enter"){  Start-AD_ComputerFunction }})
$ListBox_Computers.add_KeyDown({IF($_.keycode -eq "Space"){  Start-AD_ComputerFunction }})
$Button_ComputerAction.add_Click({ Start-AD_ComputerFunction })


$GroupBox_Computers.Controls.AddRange(@(
    $ComboBox_Computers
    $ListBox_Computers  
    $Button_ComputerAction
))


# Group GroupBox
#===========================================================


$GroupBox_Groups = New-Object System.Windows.Forms.GroupBox -Property @{
    Location           = "5,410"
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
    Location            = "7, 42"
    Size                = "394,52"
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
    Size        = "128,37"
    Text        = "New Group"
    FlatStyle   = "Flat"
}
$Button_NewGroup.FlatAppearance.BorderSize = 0

$Button_GroupAction = New-Object System.Windows.Forms.Button -Property @{
    Location    = "273,100"
    Size        = "128,37"
    FlatStyle   = "Flat"
}
$Button_GroupAction.FlatAppearance.BorderSize = 0
$Button_GroupAction.Image = $Icon_OK

# controls
$ComboBox_Groups.add_TextChanged({ GroupInfo })
$ListBox_Groups.add_MouseDoubleClick({ Start-AD_GroupFunction })
$ListBox_Groups.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-AD_GroupFunction }})
$ListBox_Groups.add_KeyDown({IF($_.keycode -eq "Space"){ Start-AD_GroupFunction }})
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
    Location    = "5, 560"
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
    Size                = "409, 192"
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
    Size                = "394,105"
    BorderStyle         = 0
    HorizontalScrollbar = 1    
}


$ListBox_Mailbox.Items.AddRange(@(
    "Mailbox info"                                     
    "List all permissions"                              
    "Add full access permissions to mailbox"            
    "Add send as permissions"                           
    "Add send on behalf of permissions"                 
    "Remove permissions"                                
         
    "Set out of office message"                         
    "Set mail forwarding"                               
    "Convert to ..."                                    
    "Hide/un-hide form global address list"             
    "Move to Database"                                  
    "Export to .PST ( on-premises only )"              
    "Remove mailbox"                                    
))

# Buttons
$Button_EnableMailBox = New-Object System.Windows.Forms.Button -Property @{
    Location       = "5,150"
    Size           = "128,35"
    Text           = "Enable MailBox"
    FlatStyle      = "Flat"
}
$Button_EnableMailBox.FlatAppearance.BorderSize = 0

$Button_MailboxAction = New-Object System.Windows.Forms.Button -Property @{
    Location      = "273,150"
    Size          = "128,37"
    FlatStyle     = "Flat"
}
$Button_MailboxAction.FlatAppearance.BorderSize = 0
$Button_MailboxAction.Image = $Icon_OK


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
    Location        = "5,210"
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
    "Remove members"                                   
    "Set Owner"                                     
    "Hide/un-hide form global address list"            
    "Remove Distribution Group"     
))

$Button_DistributionlistAction = New-Object System.Windows.Forms.Button -Property @{
    Location = "273,150"
    Size = "128,37"
    FlatStyle = "Flat"
}
$Button_DistributionlistAction.FlatAppearance.BorderSize = 0
$Button_DistributionlistAction.Image = $Icon_OK


# controls
$ComboBox_Distributionlist.add_TextChanged({  })
$ListBox_Distributionlist.add_MouseDoubleClick({  })
$ListBox_Distributionlist.add_KeyDown({IF($_.keycode -eq "Enter"){  }})
$ListBox_Distributionlist.add_KeyDown({IF($_.keycode -eq "Space"){  }})
$Button_DistributionlistAction.add_Click({ })


$GroupBox_Distributionlist.Controls.AddRange(@(
    
    $ComboBox_Distributionlist
    $ListBox_Distributionlist
    $Button_DistributionlistAction

))


# Contact GroupBox
#===========================================================

$GroupBox_Contacts = New-Object System.Windows.Forms.GroupBox -Property @{
    Location        = "5,410"
    Size            = "409, 120"
    Text            = "Select Contact"
}

$ComboBox_Contacts = New-Object System.Windows.Forms.ComboBox -Property @{
    Location         = "7, 14"
    DropDownStyle    = "DropDown"
    Width            = 394
    FlatStyle        = 'flat'
}

$ListBox_Contacts = New-Object System.Windows.Forms.ListBox -Property @{
    Location            = "7, 42"
    Size                = "394,30"
    BorderStyle         = 0
    HorizontalScrollbar = 1    
}


$ListBox_Contacts.Items.AddRange(@(
    "Contact info"
    "Remove contact"
))

$Button_Contacts = New-Object System.Windows.Forms.Button -Property @{
    Location = "273,75"
    Size = "128,37"
    FlatStyle = "Flat"
}
$Button_Contacts.FlatAppearance.BorderSize = 0
$Button_Contacts.Image = $Icon_OK


# controls
$ComboBox_Contacts.add_TextChanged({  })
$ListBox_Contacts.add_MouseDoubleClick({  })
$ListBox_Contacts.add_KeyDown({IF($_.keycode -eq "Enter"){  }})
$ListBox_Contacts.add_KeyDown({IF($_.keycode -eq "Space"){  }})
$Button_Contacts.add_Click({ })


$GroupBox_Contacts.Controls.AddRange(@(
    
    $ComboBox_Contacts
    $ListBox_Contacts
    $Button_Contacts

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
    $GroupBox_Contacts
    
))


$TabPage_Exchange.Controls.AddRange(@(
    $Panel_Exchange
    $GroupBox_ConnectToExchange 
))

#endregion Exchange

#region Office365

#=========================================================================#
#                            Office365                                    # 
#=========================================================================#

#endregion Office365

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

$GroupBox_Opacity.Controls.AddRange(@(
    $TrackBar_Opacity
))

#================= GroupBox Output Settings ================
 
$GroupBox_Output = New-Object System.Windows.Forms.GroupBox -Property @{
    Location                      = "5,97"
    Size                          = "409, 82"
    Text                          = "Output Settings"
} 

$Label_Output_ForeColor = New-Object System.Windows.Forms.Label -Property @{
    Location                      = "7,20"
    Width                         = 70
    Text                          = "Text Color:"
}


$Label_Output_BackColor = New-Object System.Windows.Forms.Label -Property @{
    Location                      = "7, 55"
    Width                         = 70
    Text                          = "Back Color:"
}

$ComboBox_Output_ForeColor = New-Object System.Windows.Forms.ComboBox -Property @{
    Name                          = "Output_ForeColor"
    Location                      = "87, 15"
    Width                         = 314
    FlatStyle                     = 'flat'
}

$ComboBox_Output_BackColor = New-Object System.Windows.Forms.ComboBox -Property @{
    Name                          = "ListBox_Users"
    Location                      = "87, 50"
    Width                         = 314
    FlatStyle                     = 'flat'
}

# Add colours to ComboBox(s)
ForEach ($Color in $Colors) { [void]$ComboBox_Output_ForeColor.Items.Add($Color) }
$ComboBox_Output_ForeColor.AutoCompleteSource = "CustomSource" 
$ComboBox_Output_ForeColor.AutoCompleteMode = "SuggestAppend"
$Colors | ForEach-Object { [void]$ComboBox_Output_ForeColor.AutoCompleteCustomSource.Add($_) }

ForEach ($Color in $Colors) { [void]$ComboBox_Output_BackColor.Items.Add($Color) }
$ComboBox_Output_BackColor.AutoCompleteSource = "CustomSource" 
$ComboBox_Output_BackColor.AutoCompleteMode = "SuggestAppend"
$Colors | ForEach-Object { [void]$ComboBox_Output_BackColor.AutoCompleteCustomSource.Add($_) }

#Button
$Button_SaveSettings = New-Object System.Windows.Forms.Button -Property @{ 
    Location                      = "5, 187"
    Size                          = "410,30"
    Text                          = "Save Settings"
    FlatStyle                     = "Flat"
}
$Button_SaveSettings.FlatAppearance.BorderSize = 0


# Events 
$TrackBar_Opacity.add_ValueChanged{( Set-Opacity )}
$ComboBox_Output_ForeColor.add_TextChanged({ Set-ForeColor })
$ComboBox_Output_BackColor.add_TextChanged({ Set-BackColor })
$Button_SaveSettings.add_Click({ Save-settings })

# Controls
$GroupBox_Output.Controls.AddRange(@(
    $Label_Output_ForeColor
    $Label_Output_BackColor
    $ComboBox_Output_ForeColor
    $ComboBox_Output_BackColor
))

#================ GroupBox Output Settings =================

$TabPage_Settings.Controls.AddRange(@(
    $GroupBox_Opacity
    $GroupBox_Output  
    $Button_SaveSettings  
))


#===================== Output GroupBox =====================

$GroupBox_Output = New-Object System.Windows.Forms.GroupBox -Property @{
    Location                        = "445,30"
    Size                            = "714, 615"
    Text                            = "Output"
    Anchor                          = "Top, Bottom, Left, Right"
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

$Button_Clear = New-Object System.Windows.Forms.Button -Property @{
    Location                        = "990,655"
    Size                            = "50,37"
    Anchor                          = "Bottom, Right"
    FlatStyle                       = "Flat"
}
$Button_Clear.FlatAppearance.BorderSize = 0
$Button_Clear.Image = [System.IconExtractor]::Extract("Shell32.dll", 219, $true)

$Button_Copy = New-Object System.Windows.Forms.Button -Property @{
    Location                       = "1040,655"
    Size                           = "50,37"
    Anchor                         = "Bottom, Right"
    FlatStyle                      = "Flat"
    Backcolor                      = "transparent"
}
$Button_Copy.FlatAppearance.BorderSize = 0
$Button_Copy.Image = [System.IconExtractor]::Extract("Shell32.dll", 54, $true)

$Button_Notepad = New-Object System.Windows.Forms.Button -Property @{
    Location                       = "1090,655"
    Size                           = "50,37"
    Anchor                         = "Bottom, Right"
    FlatStyle                      = "Flat"
} 
$Button_Notepad.FlatAppearance.BorderSize = 0
$Button_Notepad.Image = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command notepad.exe).Path)

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
$Button_Clear.add_Click({ Clear-Output })
$Button_Copy.add_Click({ Copy_Outbox })
$Button_Notepad.add_Click({ Copy_Notepad })
$TextBox_Output.add_LinkClicked({ Start-Process -FilePath $_.LinkText })
$TextBox_Output.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-OutPutCommand }})

# Add Controls
$GroupBox_Output.Controls.Add( $TextBox_Output )

#========================== Colors =========================

## Default (set these to change the rest of the from)
$ComboBox_Output_ForeColor.Text = $Settings.ForeColor
$ComboBox_Output_BackColor.Text = $Settings.BackColor

### Fore color
$ListBox_windows.ForeColor                    = $ComboBox_Output_ForeColor.text.ToString()
$ListBox_WindowServer.ForeColor               = $ComboBox_Output_ForeColor.text.ToString()
$ListBox_ControlPanel.ForeColor               = $ComboBox_Output_ForeColor.text.ToString()
$TextBox_Output.ForeColor                     = $ComboBox_Output_ForeColor.text.ToString()
$ComboBox_Users.ForeColor                     = $ComboBox_Output_ForeColor.text.ToString()
$ListBox_Users.ForeColor                      = $ComboBox_Output_ForeColor.text.ToString()
$ComboBox_Computers.ForeColor                 = $ComboBox_Output_ForeColor.text.ToString()
$ListBox_Computers.ForeColor                  = $ComboBox_Output_ForeColor.text.ToString()
$ComboBox_Groups.ForeColor                    = $ComboBox_Output_ForeColor.text.ToString()
$ListBox_Groups.ForeColor                     = $ComboBox_Output_ForeColor.text.ToString()
$ComboBox_Mailbox.ForeColor                   = $ComboBox_Output_ForeColor.text.ToString()
$ListBox_Mailbox.ForeColor                    = $ComboBox_Output_ForeColor.text.ToString()
$ComboBox_Distributionlist.ForeColor          = $ComboBox_Output_ForeColor.text.ToString()
$ListBox_Distributionlist.ForeColor           = $ComboBox_Output_ForeColor.text.ToString()
$ComboBox_Contacts.ForeColor                  = $ComboBox_Output_ForeColor.text.ToString()
$ListBox_Contacts.ForeColor                   = $ComboBox_Output_ForeColor.text.ToString()
$StatusBarLabel.ForeColor                     = $ComboBox_Output_ForeColor.text.ToString()

#### Back color
$ListBox_windows.BackColor                    = $ComboBox_Output_BackColor.text.ToString()
$ListBox_WindowServer.BackColor               = $ComboBox_Output_BackColor.text.ToString()
$ListBox_ControlPanel.BackColor               = $ComboBox_Output_BackColor.text.ToString()
$TextBox_Output.BackColor                     = $ComboBox_Output_BackColor.text.ToString()
$ComboBox_Users.BackColor                     = $ComboBox_Output_BackColor.text.ToString()
$ListBox_Users.BackColor                      = $ComboBox_Output_BackColor.text.ToString()
$ComboBox_Computers.BackColor                 = $ComboBox_Output_BackColor.text.ToString()
$ListBox_Computers.BackColor                  = $ComboBox_Output_BackColor.text.ToString()
$ComboBox_Groups.BackColor                    = $ComboBox_Output_BackColor.text.ToString()
$ListBox_Groups.BackColor                     = $ComboBox_Output_BackColor.text.ToString()
$ComboBox_Mailbox.BackColor                   = $ComboBox_Output_BackColor.text.ToString()
$ListBox_Mailbox.BackColor                    = $ComboBox_Output_BackColor.text.ToString()
$ComboBox_Distributionlist.BackColor          = $ComboBox_Output_BackColor.text.ToString()
$ListBox_Distributionlist.BackColor           = $ComboBox_Output_BackColor.text.ToString()
$ComboBox_Contacts.BackColor                  = $ComboBox_Output_BackColor.text.ToString()
$ListBox_Contacts.BackColor                   = $ComboBox_Output_BackColor.text.ToString()
$StatusBar.BackColor                          = $ComboBox_Output_BackColor.text.ToString()


#=========================== END ==========================

# Add Controls to from
$Form.controls.AddRange(@(
    $Menu
    $Tab_Control
    $GroupBox_Output
    $Button_Clear
    $Button_Copy
    $Button_Notepad
    $StatusBar 
))


# Show Form
[void]$Form.ShowDialog()



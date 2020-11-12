
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

# Assembly and Modules
#===========================================================
Add-Type -AssemblyName system.windows.forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# From Variables
#===========================================================
$About =  @"

    Author:      Theo Bird
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


#=========================================================================#
#                           Base Functions                                # 
#=========================================================================#

# Clear output 
Function Clear-Output {
    $TextBox_Output.Clear()
}

# Error
Function Write-OutError {
    Clear-Output
    $Err = $Error[0]
    $TextBox_Output.AppendText("$Err")
}

# About
Function Show-About {
   Clear-Output
   $TextBox_Output.AppendText($About)    
} 


Function Copy_Outbox {
    $TextBox_Output.SelectAll()
    $TextBox_Output.Copy()
} 


Function Copy_Notepad { 
    $filename = [System.IO.Path]::GetTempFileName() 
    Add-Content -Value $TextBox_Output.text -Path $filename
    notepad $filename
}


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
    $StatusBar.text = "  Ready"
}

Function Start-NewUAC {
  Powershell ($MyInvocation).ScriptName
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

            'ACL folder info'                  { Get_ACL }
            'DirectX Diagnostic Tool'          { Start-Process dxdiag.exe -ErrorAction Stop }
            'Disk Manager'                     { Start-Process diskmgmt.msc -ErrorAction Stop }
            'Device Management'                { Start-Process devmgmt.msc -ErrorAction Stop }
            'Event Viewer'                     { Start-Process eventvwr.msc -ErrorAction Stop }
            'Firewall'                         { Start-Process firewall.cpl -ErrorAction Stop }
            'Internet Properties'              { Start-Process inetcpl.cpl -ErrorAction Stop }
            'Network Properties'               { Start-Process control -ArgumentList netconnections -ErrorAction Stop}
            'Optional Features'                { Start-Process OptionalFeatures.exe -ErrorAction Stop }
            'Registry Editor'                  { Start-Process regedit -ErrorAction Stop }
            'Reliability Monitor'              { Start-Process perfmon /rel -ErrorAction Stop}
            'Remote Desktop'                   { Start-Process mstsc.exe -ErrorAction Stop}
            'Services'                         { Start-Process services.msc -ErrorAction Stop }
            'System Information'               { Start-Process msinfo32.exe -ErrorAction Stop } 
            'System Configuration Utility'     { Start-Process msconfig.exe -ErrorAction Stop }
            'System Properties'                { Start-Process sysdm.cpl -ErrorAction Stop }
            'Task Scheduler'                   { Start-Process taskschd.msc -ErrorAction Stop }
            'Task Manager'                     { Start-Process taskmgr.exe -ErrorAction Stop }
            'Windows Version'                  { Start-Process winver.exe -ErrorAction Stop }
            'Windows Update'                   { Start-Process control -ArgumentList update -ErrorAction Stop }

            } 
        } Catch {
        Write-OutError
        Set-StatusBarReady
        }
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
    $StatusBar.text = "Installing RSAT"

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

#=========================================================================#
#                    Active Directory Functions                           # 
#=========================================================================#

# Imports All AD objects 
Function Enable-ActiveDirectory {
        
    #Import AD Module
    try { 
        Import-Module activedirectory -ErrorAction Stop -WarningAction SilentlyContinue 
        $LastWriteTime = ($StatusBar.text = "  Loading Active Directory Objects").LastWriteTime
        
        If (test-path "$env:PUBLIC\Ultimate Administrator Console\AD.xml") {
            $LastWriteTime = (Get-ItemProperty "$env:PUBLIC\Ultimate Administrator Console\AD.xml").LastWriteTime
            $UserPrompt = new-object -comobject wscript.shell
            $Answer = $UserPrompt.popup("Load Active Directory data from local cache? `n`nCache was Last updated on $LastWriteTime", 0, " Load from cache", 0x4 + 0x20)
    
                IF ($Answer -eq 6) {
                    $AD_XML = Import-Clixml "$env:PUBLIC\Ultimate Administrator Console\AD.xml"
            
                    $script:AD_Forst       = (Get-ADDomain).Forest
                    $script:AD_Domain      = (Get-ADForest).UPNSuffixes
                    $script:AD_Users       = $AD_XML.Users
                    $script:AD_Computers   = $AD_XML.Computers
                    $script:AD_Groups      = $AD_XML.Groups
                    $script:AD_OUs         = $AD_XML.OUs
                                                                                        
        } Else {
        
        $script:AD_Forst       = (Get-ADDomain).Forest
        $script:AD_Domain      = (Get-ADForest).UPNSuffixes
        $script:AD_Users       = Get-ADUser -Filter * -Properties SamAccountName,Name,Mail,Enabled,whenCreated,LastLogonDate,DistinguishedName | Select-Object SamAccountName,Name,Mail,Enabled,whenCreated,LastLogonDate,DistinguishedName | Sort-Object 
        $script:AD_Computers   = Get-ADComputer -Filter * -Properties Name, Created, Enabled, OperatingSystem, OperatingSystemVersion, IPv4Address, LastLogonDate, logonCount, DistinguishedName | Select-Object Name, Created, Enabled, OperatingSystem, OperatingSystemVersion, IPv4Address, LastLogonDate, logonCount | Sort-Object
        $script:AD_Groups      = Get-ADGroup -Filter * -Properties SamAccountName, Name, Description, Created, DistinguishedName | Select-Object SamAccountName, Name, Description, Created, DistinguishedName | Sort-Object
        $script:AD_OUs         = Get-ADOrganizationalUnit -Filter * -Properties * | Sort-Object | Select-Object CanonicalName,DistinguishedName  
        
        }      
        
        ForEach ($User in $AD_Users.samaccountname) { [void]$ComboBox_Users.Items.Add($user) }
        $ComboBox_Users.AutoCompleteSource = "CustomSource" 
        $ComboBox_Users.AutoCompleteMode = "SuggestAppend"
        $AD_Users.SamAccountName | ForEach-Object { [void]$ComboBox_Users.AutoCompleteCustomSource.Add($_) }

        ForEach ($CPU in $AD_Computers.name) { [void]$ComboBox_Computers.Items.Add($CPU) }
        $ComboBox_Computers.AutoCompleteSource = "CustomSource" 
        $ComboBox_Computers.AutoCompleteMode = "SuggestAppend"
        $AD_Computers.name | ForEach-Object { [void]$ComboBox_Computers.AutoCompleteCustomSource.Add($_) }
        
        ForEach ($Group in $AD_Groups.SamAccountName) { [void]$ComboBox_Groups.Items.Add($Group) }
        $ComboBox_Groups.AutoCompleteSource = "CustomSource" 
        $ComboBox_Groups.AutoCompleteMode = "SuggestAppend"
        $AD_Groups.SamAccountName | ForEach-Object { [void]$ComboBox_Groups.AutoCompleteCustomSource.Add($_) }
            
        $Panel_ActiveDirectory.Enabled = $true
        $Menu_AD.Enabled = $true
        $Button_ActiveDirectory_StartButtion.Enabled = $false 

        Save-ADdata
        Set-StatusBarReady
        $TextBox_Output.AppendText("*** Active Directory object have been loaded ***")    
        }
        
    } catch {
    Write-OutError
    Set-StatusBarReady
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

    # taken from https://gist.github.com/joegasper/3fafa5750261d96d5e6edf112414ae18
    $obj = $ComboBox_OU.SelectedItem.Replace(',','\,').Split('/')
    [string]$DN = "OU=" + $obj[$obj.count - 1]
    for ($i = $obj.count - 2;$i -ge 1;$i--){$DN += ",OU=" + $obj[$i]}
    $obj[0].split(".") | ForEach-Object { $DN += ",DC=" + $_}

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
        
    $StatusBar.text = "  Creating new user account for $UserName"
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
        $AD_Users.add($UserName)
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

                $AD_Users.remove($User)
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
            $CopyComputer = $AD_Computers | Sort-Object | Out-GridView -PassThru -Title "Select Account" 
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

                $AD_Computers.remove($Computer)
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

                $AD_Groups.remove($Group)
                [void]$ComboBox_Groups.Items.remove($Group)
                [void]$ComboBox_Groups.AutoCompleteCustomSource.Remove($Group) 
                Save-ADdata
            }
        } Catch { Write-OutError }
    }
}



#===================== Menu Functions ======================

# List all user details 
Function show-AD_users {

    $AD_Users | Out-GridView -Title "Users"       

}

# List all Computer details 
Function show-AD_Computers {

    $AD_Computers | Out-GridView -Title "Computers" 
}

# List all Groups details
Function show-AD_Groups {

    $AD_Groups | Out-GridView -Title "Groups"
    
}

#List all Organizational Unit details
Function show-AD_OUs {

    $AD_OUs | Out-GridView -Title "Organizational Units"
    
}


Function CSVAdUserExport {

    $StatusBar.text = "  Export User Objects to CSV..."
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
    
    $StatusBar.text = "  Export Computer Objects to CSV..."
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

    $StatusBar.text = "  Export Group Objects to CSV..."
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
#                             Base From                                   # 
#=========================================================================#

# Base From & Shortcuts
#===========================================================

$Form = New-Object system.Windows.Forms.Form -Property @{
    ClientSize             = '1170,720'
    Text                   = "Ultimate Administrator Console"
    MinimumSize            = '1170,720'
    TopMost                = $false
    ShowIcon               = $false
    KeyPreview             = $true
}

# Shortcuts
<#F1#>  $Form.add_KeyDown({IF($_.keycode -eq "F1"){ Start-Process PowerShell.exe }})
<#F2#>  $Form.add_KeyDown({IF($_.keycode -eq "F2"){ Clear-Output }})
<#F3#>  $Form.add_KeyDown({IF($_.keycode -eq "F3"){ Copy_Outbox  }})
<#F4#>  $Form.add_KeyDown({IF($_.keycode -eq "F4"){ Copy_Notepad }})
<#F5#>  $Form.add_KeyDown({IF($_.keycode -eq "F5"){ Enable-ActiveDirectory }})
<#F6#>  $Form.add_KeyDown({IF($_.keycode -eq "F6"){  }})
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
$Menu_New                                = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Exit                               = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Shell                              = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Shell_CMD                          = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Shell_PowerShell                   = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_Shell_PowerShell_ISE               = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_AD                                 = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_AD_ViewUserAccounts                = New-Object System.Windows.Forms.ToolStripMenuItem 
$Menu_AD_ViewComptuerAccounts            = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_AD_ViewGroups                      = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_AD_ViewOUs                         = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_AD_Space                           = New-Object System.Windows.Forms.ToolStripSeparator
$Menu_AD_ExportUsers                     = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_AD_ExportComputers                 = New-Object System.Windows.Forms.ToolStripMenuItem 
$Menu_AD_ExportGroups                    = New-Object System.Windows.Forms.ToolStripMenuItem 
$Menu_Help                               = New-Object System.Windows.Forms.ToolStripMenuItem
$Menu_About                              = New-Object System.Windows.Forms.ToolStripMenuItem

## text ##
$Menu_File.Text                          = "File"
$Menu_New.Text                           = "New"
$Menu_Exit.Text                          = "Exit"
$Menu_Shell.Text                         = "Shell"
$Menu_Shell_CMD.Text                     = "Command Prompt"
$Menu_Shell_PowerShell.Text              = "PowerShell"
$Menu_Shell_PowerShell_ISE.Text          = "ISE"
$Menu_AD.Text                            = "Active Directory"
$Menu_AD_ViewUserAccounts.Text           = "View All User accounts" 
$Menu_AD_ViewComptuerAccounts.Text       = "View All Computer accounts"
$Menu_AD_ViewGroups.Text                 = "View All Groups"
$Menu_AD_ViewOUs.Text                    = "View All Organizational Units"
$Menu_AD_ExportUsers.Text                = "Export Users to CSV"
$Menu_AD_ExportComputers.Text            = "Export Computers to CSV" 
$Menu_AD_ExportGroups.Text               = "Export Gruops to CSV"
$Menu_Help.Text                          = "Help"
$Menu_About.Text                         = "About"

## Functions ##
$Menu_New.Add_Click({ Start-NewUAC })
$Menu_Exit.Add_Click({ $Form.close() })
$Menu_Shell_CMD.Add_click({ Start-Process CMD.exe })
$Menu_Shell_PowerShell.Add_click({ Start-Process PowerShell.exe }) 
$Menu_Shell_PowerShell_ISE.Add_click({ ISE })
$Menu_About.Add_Click({ Show-About })
$Menu_AD_ViewUserAccounts.Add_Click({ show-AD_users }) 
$Menu_AD_ViewComptuerAccounts.Add_Click({ show-AD_Computers })
$Menu_AD_ViewGroups.Add_Click({ show-AD_Groups }) 
$Menu_AD_ViewOUs.Add_Click({ show-AD_OUs })
$Menu_AD_ExportUsers.Add_Click({ CSVAdUserExport })
$Menu_AD_ExportComputers.Add_Click({ CSVComputerExport })
$Menu_AD_ExportGroups.Add_Click({ CSVGroupsExport })

## Disabled ## 
$Menu_AD.Enabled             = $false

## Controls ##

# file
[void]$Menu_File.DropDownItems.AddRange(@(
#    $Menu_New
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
    $Menu_AD_ViewUserAccounts
    $Menu_AD_ViewComptuerAccounts
    $Menu_AD_ViewGroups
    $Menu_AD_ViewOUs
    $Menu_AD_Space
    $Menu_AD_ExportUsers
    $Menu_AD_ExportComputers
    $Menu_AD_ExportGroups
))

# Help
[void]$Menu_Help.DropDownItems.AddRange(@(
    $Menu_About
))


# Menu Range
[void]$Menu.Items.AddRange(@(
    $Menu_File
    $Menu_Shell
    $Menu_AD
    $Menu_Help
))


#========================== Tabs ============================

$Tab_Control = New-object System.Windows.Forms.TabControl -Property @{
    Location = "10,40"
    Size = "430, 620"
    Appearance = 2
}

## Objects ##

$TabPage_WindowsTools    = New-Object System.Windows.Forms.TabPage
$TabPage_ControlPanel    = New-Object System.Windows.Forms.TabPage
$TabPage_AD              = New-Object System.Windows.Forms.TabPage

## Text ## 

$TabPage_WindowsTools.Text     = "Windows Tools"
$TabPage_ControlPanel.Text     = "Control Panel"
$TabPage_AD.Text               = "Active Directory"

## Controls ##

$Tab_Control.Controls.AddRange(@(
    $TabPage_WindowsTools
    $TabPage_ControlPanel
    $TabPage_AD
))

#=========================================================================#
#                          Windows Tools UI                               # 
#=========================================================================#

# Windows Tools - GroupBox
#===========================================================

$GroupBox_Windows = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "5,10"
    Size = "409, 300"
    Text = "Windows Tools"
}

$ListBox_Windows = New-Object System.Windows.Forms.ListBox -Property @{
    name = "ListBox_windows"
    Location = "7, 14"
    Size = "394,240"
    BorderStyle = 0
    HorizontalScrollbar = 1
}

$ListBox_Windows.Items.AddRange(@(
    "ACL folder info"
    "DirectX Diagnostic Tool"
    "Disk Manager"
    "Device Management"
    "Event Viewer"
    "Firewall"
    "Internet Properties"
    "Network Properties"
    "Optional Features"
    "Registry Editor"
    "Reliability Monitor"
    "Remote Desktop"
    "Services"
    "System Information" 
    "System Configuration Utility"
    "System Properties"
    "Task Manager"
    "Task Scheduler"
    "Windows Version"
    "Windows Update"
))


$Button_GetComputerinfo = New-Object System.Windows.Forms.Button -Property @{
    Location = "5,255"
    Size = "128,35"
    Text = "Computer info"
    FlatStyle = "Flat"
}
$Button_GetComputerinfo.FlatAppearance.BorderSize = 0


$Button_WindowsAction = New-Object System.Windows.Forms.Button -Property @{
    Location = "273,255"
    Size = "128,35"
    Text = "Run"
    FlatStyle = "Flat"
}
$Button_WindowsAction.FlatAppearance.BorderSize = 0

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
    Location = "5,325"
    Size = "409, 250"
    Text = "Windows Server Tools"
}

$ListBox_WindowServer = New-Object System.Windows.Forms.ListBox -Property @{
    Location = "7, 14"
    Size = "394,190"
    BorderStyle = 0
    HorizontalScrollbar = 1    
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
    Location = "5,205"
    Size = "128,35"
    Text = "Install RSAT"
    FlatStyle = "Flat"
}
$Button_InstallRsat.FlatAppearance.BorderSize = 0

$Button_WindowServerAction = New-Object System.Windows.Forms.Button -Property @{
    Location = "273,205"
    Size = "128,35"
    Text = "Run"
    FlatStyle = "Flat"
}
$Button_WindowServerAction.FlatAppearance.BorderSize = 0

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
    Location = "5,10"
    Size = "409, 560"
    Text = "Control Panel items"
}

$ListBox_ControlPanel = New-Object System.Windows.Forms.ListBox -Property @{
    name = "ListBox_windows"
    Location = "7, 14"
    Size = "394,500"
    BorderStyle = 0
    HorizontalScrollbar = 1
}

$ControlPanelItem = (Get-ControlPanelItem).Name
foreach($Item in $ControlPanelItem) {$ListBox_ControlPanel.Items.AddRange($Item)} 

$Button_Godmode = New-Object System.Windows.Forms.Button -Property @{
    Location = "5,515"
    Size = "128,35"
    Text = "Godmode"
    FlatStyle = "Flat"
}
$Button_Godmode.FlatAppearance.BorderSize = 0


$Button_ControlPanel = New-Object System.Windows.Forms.Button -Property @{
    Location = "273,515"
    Size = "128,35"
    Text = "Run"
    FlatStyle = "Flat"
}
$Button_ControlPanel.FlatAppearance.BorderSize = 0

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


#=========================================================================#
#                          Active Directory UI                            # 
#=========================================================================#

## TabPage AD ##
##===================================================================================================##

$Panel_ActiveDirectory = New-Object System.Windows.Forms.Panel -Property @{
    Location = "0,0"
    Size = "430, 560"
    Enabled = $false
}

# User accounts GroupBox 
#===========================================================

$GroupBox_Users = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "5,10"
    Size = "409, 192"
    Text = "Select Account"
}

$ComboBox_Users = New-Object System.Windows.Forms.ComboBox -Property @{
    Location = "7, 14"
    DropDownStyle = "DropDown"
    Width = 394
    FlatStyle = 'flat'
}

$ListBox_Users = New-Object System.Windows.Forms.ListBox -Property @{
    Name = "ListBox_Users"
    Location = "7, 42"
    Size = "394,105"
    BorderStyle = 0
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
    Location = "5,150"
    Size = "128,35"
    Text = "New User"
    FlatStyle = "Flat"
}
$Button_NewUser.FlatAppearance.BorderSize = 0


$Button_UserAction = New-Object System.Windows.Forms.Button -Property @{
    Location = "273,150"
    Size = "128,35"
    Text = "Run"
    FlatStyle = "Flat"
}
$Button_UserAction.FlatAppearance.BorderSize = 0

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
    Location = "5,210"
    Size = "409, 192"
    Text = "Select Computer"
}

$ComboBox_Computers = New-Object System.Windows.Forms.ComboBox -Property @{
    Location = "7, 14"
    Width = 394
    DropDownStyle = "DropDown"
    FlatStyle = 'flat'
}

$ListBox_Computers = New-Object System.Windows.Forms.ListBox -Property @{
    Name = "ListBox_Computers"
    Location = "7, 42"
    Size = "394,105"
    BorderStyle = 0
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
    Location = "273,150"
    Size = "128,35"
    Text = "Run"
    FlatStyle = "Flat"
}
$Button_ComputerAction.FlatAppearance.BorderSize = 0

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
    Location = "5,410"
    Size = "409, 145"
    Text = "Select a Group"
}

$ComboBox_Groups = New-Object System.Windows.Forms.ComboBox -Property @{
    location = "7, 14"
    Width = 394
    DropDownStyle = "DropDown"
    FlatStyle = 'flat'
}

$ListBox_Groups = New-Object System.Windows.Forms.ListBox -Property @{
    Name = "ListBox_Groups"
    Location = "7, 42"
    Size = "394,52"
    BorderStyle = 0
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
$Button_GroupAction = New-Object System.Windows.Forms.Button -Property @{
    Location = "273,100"
    Size = "128,37"
    Text = "Run"
    FlatStyle = "Flat"
}
$Button_GroupAction.FlatAppearance.BorderSize = 0


# controls
$ComboBox_Groups.add_TextChanged({ GroupInfo })
$ListBox_Groups.add_MouseDoubleClick({ Start-AD_GroupFunction })
$ListBox_Groups.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-AD_GroupFunction }})
$ListBox_Groups.add_KeyDown({IF($_.keycode -eq "Space"){ Start-AD_GroupFunction }})
$Button_GroupAction.add_Click({ Start-AD_GroupFunction })


$GroupBox_Groups.Controls.AddRange(@(
    $ListBox_Groups  
    $ComboBox_Groups 
    $Button_GroupAction
))


# TabPage AD - Control AddRange
#===========================================================

$Button_ActiveDirectory_StartButtion = New-Object System.Windows.Forms.Button -Property @{
    Name = "Button_ActiveDirectory_StartButtion"
    Location = "5, 560"
    Size = "410,30"
    Text = "Enable Active Directory"
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


#===================== Output GroupBox =====================

$GroupBox_Output = New-Object System.Windows.Forms.GroupBox -Property @{
    Location = "445,30"
    Size = "714, 615"
    Text = "Output"
    Anchor = "Top, Bottom, Left, Right"
}

$TextBox_Output = New-Object System.Windows.Forms.RichTextBox -Property @{
    Name = "TextBox_Output"
    Location = "7, 14"
    Size = "700, 593"
    ScrollBars = "both"
    Multiline = $true
    WordWrap = $false
    Anchor = "Top, Bottom, Left, Right"
    Font = "lucida console,9"
    RightToLeft = "No"
    Cursor = "IBeam"
    BorderStyle = 0
    DetectUrls = $true
}


#=========================== End ==========================

$Button_Clear = New-Object System.Windows.Forms.Button -Property @{
    Location = "750,655"
    Size = "130,37"
    Anchor = "Bottom, Right"
    Text = "Clear output"
    FlatStyle = "Flat"
}
$Button_Clear.FlatAppearance.BorderSize = 0

$Button_Copy = New-Object System.Windows.Forms.Button -Property @{
    Location = "890,655"
    Size = "130,37"
    Anchor = "Bottom, Right"
    Text = "Copy to Clipboard"
    FlatStyle = "Flat"
}
$Button_Copy.FlatAppearance.BorderSize = 0

$Button_Notepad = New-Object System.Windows.Forms.Button -Property @{
    Location = "1030,655"
    Size = "130,37"
    Anchor = "Bottom, Right"
    Text = "Copy to Notepad"
    FlatStyle = "Flat"
}
$Button_Notepad.FlatAppearance.BorderSize = 0


$StatusBar = New-Object System.Windows.Forms.StatusBar -Property @{
    Text = "   Ready"
}

# Button Controls
$Button_Clear.add_Click({ Clear-Output })
$Button_Copy.add_Click({ Copy_Outbox })
$Button_Notepad.add_Click({ Copy_Notepad })
$TextBox_Output.add_LinkClicked({ Start-Process -FilePath $_.LinkText })
$TextBox_Output.add_KeyDown({IF($_.keycode -eq "Enter"){ Start-OutPutCommand }})

# Add Controls
$GroupBox_Output.Controls.Add( $TextBox_Output )

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


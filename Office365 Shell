# logic to be added to Ultimate-Administrator-Console

# Office 365 Service desk Version 1.3
# Written by: Theo Bird

If ((Test-Path "$env:USERPROFILE\AppData\Roaming\365Connect") -eq $false) {
    New-Item -Path "$env:USERPROFILE\AppData\Roaming\365Connect" -ItemType "directory" -Force
    New-Item -Path "$env:USERPROFILE\AppData\Roaming\365Connect\365Profiles" -ItemType "directory" -Force 
} 
else {
  Remove-Item "$env:USERPROFILE\AppData\Roaming\365Connect" -Recurse -Force
    New-Item -Path "$env:USERPROFILE\AppData\Roaming\365Connect" -ItemType "directory" -Force
    New-Item -Path "$env:USERPROFILE\AppData\Roaming\365Connect\365Profiles" -ItemType "directory" -Force 
}

if (-not (Get-InstalledModule -Name "MSonline")) {
    Install-Module -Name "msonline" -Force -AllowClobber
}

#Create Connect365 Script
$Script_Path = "$env:USERPROFILE\AppData\Roaming\365Connect\Connect365.ps1" 
$Script_Body = @' 

# Empty variables to be populated with data from Connect-365_Profile
$UPN = $null
$DL = $null
$Mailbox = $null 
$Mailbox_Members = $null
# license conversion list 
$location = @{
    "AFGHANISTAN"                           = "AF"
    "ALAND ISLANDS"                         = "AX"
    "ALBANIA"                               = "AL"
    "ALGERIA"                               = "DZ"
    "AMERICAN SAMOA"                        = "AS"
    "ANDORRA"                               = "AD"
    "ANGOLA"                                = "AO"
    "ANGUILLA"                              = "AI"
    "ANTARCTICA"                            = "AQ"
    "ANTIGUA BARBUDA"                       = "AG"
    "ARGENTINA"                             = "AR"
    "ARMENIA"                               = "AM"
    "ARUBA"                                 = "AW"
    "AUSTRALIA"                             = "AU"
    "AUSTRIA"                               = "AT"
    "AZERBAIJAN"                            = "AZ"
    "BAHAMAS"                               = "BS"
    "BAHRAIN"                               = "BH"
    "BANGLADESH"                            = "BD"
    "BARBADOS"                              = "BB"
    "BELARUS"                               = "BY"
    "BELGIUM"                               = "BE"
    "BELIZE"                                = "BZ"
    "BENIN"                                 = "BJ"
    "BERMUDA"                               = "BM"
    "BHUTAN"                                = "BT"
    "BOLIVIA, PLURINATIONAL OF"             = "BO"
    "BONAIRE, SINT SABA"                    = "BQ"
    "BOSNIA HERZEGOVINA"                    = "BA"
    "BOTSWANA"                              = "BW"
    "BOUVET ISLAND"                         = "BV"
    "BRAZIL"                                = "BR"
    "BRITISH TERRITORY"                     = "IO"
    "BRUNEI DARUSSALAM"                     = "BN"
    "BULGARIA"                              = "BG"
    "BURKINA FASO"                          = "BF"
    "BURUNDI"                               = "BI"
    "CAMBODIA"                              = "KH"
    "CAMEROON"                              = "CM"
    "CANADA"                                = "CA"
    "CAPE VERDE"                            = "CV"
    "CAYMAN ISLANDS"                        = "KY"
    "CENTRAL REPUBLIC"                      = "CF"
    "CHAD"                                  = "TD"
    "CHILE"                                 = "CL"
    "CHINA"                                 = "CN"
    "CHRISTMAS ISLAND"                      = "CX"
    "COCOS (KEELING) ISLANDS"               = "CC"
    "COLOMBIA"                              = "CO"
    "COMOROS"                               = "KM"
    "CONGO"                                 = "CG"
    "CONGO, THE DEMOCRATIC REPUBLIC OF THE" = "CD"
    "COOK ISLANDS"                          = "CK"
    "COSTA RICA"                            = "CR"
    "COTE D'IVOIRE"                         = "CI"
    "CROATIA"                               = "HR"
    "CUBA"                                  = "CU"
    "CURACAO"                               = "CW"
    "CYPRUS"                                = "CY"
    "CZECH REPUBLIC"                        = "CZ"
    "DENMARK"                               = "DK"
    "DJIBOUTI"                              = "DJ"
    "DOMINICA"                              = "DM"
    "DOMINICAN REPUBLIC"                    = "DO"
    "ECUADOR"                               = "EC"
    "EGYPT"                                 = "EG"
    "EL SALVADOR"                           = "SV"
    "EQUATORIAL GUINEA"                     = "GQ"
    "ERITREA"                               = "ER"
    "ESTONIA"                               = "EE"
    "ETHIOPIA"                              = "ET"
    "FALKLAND ISLANDS (MALVINAS)"           = "FK"
    "FAROE ISLANDS"                         = "FO"
    "FIJI"                                  = "FJ"
    "FINLAND"                               = "FI"
    "FRANCE"                                = "FR"
    "FRENCH GUIANA"                         = "GF"
    "FRENCH POLYNESIA"                      = "PF"
    "FRENCH TERRITORIES"                    = "TF"
    "GABON"                                 = "GA"
    "GAMBIA"                                = "GM"
    "GEORGIA"                               = "GE"
    "GERMANY"                               = "DE"
    "GHANA"                                 = "GH"
    "GIBRALTAR"                             = "GI"
    "GREECE"                                = "GR"
    "GREENLAND"                             = "GL"
    "GRENADA"                               = "GD"
    "GUADELOUPE"                            = "GP"
    "GUAM"                                  = "GU"
    "GUATEMALA"                             = "GT"
    "GUERNSEY"                              = "GG"
    "GUINEA"                                = "GN"
    "GUINEA-BISSAU"                         = "GW"
    "GUYANA"                                = "GY"
    "HAITI"                                 = "HT"
    "HEARD ISLANDS"                         = "HM"
    "HOLY SEE (VATICAN CITY STATE)"         = "VA"
    "HONDURAS"                              = "HN"
    "HONG KONG"                             = "HK"
    "HUNGARY"                               = "HU"
    "ICELAND"                               = "IS"
    "INDIA"                                 = "IN"
    "INDONESIA"                             = "ID"
    "IRAQ"                                  = "IQ"
    "IRELAND"                               = "IE"
    "ISLAMIC IRAN"                          = "IR"
    "ISLE MAN"                              = "IM"
    "ISRAEL"                                = "IL"
    "ITALY"                                 = "IT"
    "JAMAICA"                               = "JM"
    "JAPAN"                                 = "JP"
    "JERSEY"                                = "JE"
    "JORDAN"                                = "JO"
    "KAZAKHSTAN"                            = "KZ"
    "KENYA"                                 = "KE"
    "KIRIBATI"                              = "KI"
    "KOREA, DEMOCRATIC PEOPLE'S OF"         = "KP"
    "KOREA, REPUBLIC OF"                    = "KR"
    "KUWAIT"                                = "KW"
    "KYRGYZSTAN"                            = "KG"
    "LAO PEOPLE'S REPUBLIC"                 = "LA"
    "LATVIA"                                = "LV"
    "LEBANON"                               = "LB"
    "LESOTHO"                               = "LS"
    "LIBERIA"                               = "LR"
    "LIBYA"                                 = "LY"
    "LIECHTENSTEIN"                         = "LI"
    "LITHUANIA"                             = "LT"
    "LUXEMBOURG"                            = "LU"
    "MACAO"                                 = "MO"
    "MACEDONIA, THE OF"                     = "MK"
    "MADAGASCAR"                            = "MG"
    "MALAWI"                                = "MW"
    "MALAYSIA"                              = "MY"
    "MALDIVES"                              = "MV"
    "MALI"                                  = "ML"
    "MALTA"                                 = "MT"
    "MARSHALL ISLANDS"                      = "MH"
    "MARTINIQUE"                            = "MQ"
    "MAURITANIA"                            = "MR"
    "MAURITIUS"                             = "MU"
    "MAYOTTE"                               = "YT"
    "MEXICO"                                = "MX"
    "MICRONESIA, FEDERATED OF"              = "FM"
    "MOLDOVA, REPUBLIC OF"                  = "MD"
    "MONACO"                                = "MC"
    "MONGOLIA"                              = "MN"
    "MONTENEGRO"                            = "ME"
    "MONTSERRAT"                            = "MS"
    "MOROCCO"                               = "MA"
    "MOZAMBIQUE"                            = "MZ"
    "MYANMAR"                               = "MM"
    "NAMIBIA"                               = "NA"
    "NAURU"                                 = "NR"
    "NEPAL"                                 = "NP"
    "NETHERLANDS"                           = "NL"
    "NEW CALEDONIA"                         = "NC"
    "NEW ZEALAND"                           = "NZ"
    "NICARAGUA"                             = "NI"
    "NIGER"                                 = "NE"
    "NIGERIA"                               = "NG"
    "NIUE"                                  = "NU"
    "NORFOLK ISLAND"                        = "NF"
    "NORTHERN ISLANDS"                      = "MP"
    "NORWAY"                                = "NO"
    "OMAN"                                  = "OM"
    "PAKISTAN"                              = "PK"
    "PALAU"                                 = "PW"
    "PALESTINE, STATE OF"                   = "PS"
    "PANAMA"                                = "PA"
    "PAPUA GUINEA"                          = "PG"
    "PARAGUAY"                              = "PY"
    "PERU"                                  = "PE"
    "PHILIPPINES"                           = "PH"
    "PITCAIRN"                              = "PN"
    "POLAND"                                = "PL"
    "PORTUGAL"                              = "PT"
    "PUERTO RICO"                           = "PR"
    "QATAR"                                 = "QA"
    "RÉUNION"                               = "RE"
    "ROMANIA"                               = "RO"
    "RUSSIAN FEDERATION"                    = "RU"
    "RWANDA"                                = "RW"
    "SAINT BARTHÉLEMY"                      = "BL"
    "SAINT HELENA, ASCENSION CUNHA"         = "SH"
    "SAINT NEVIS"                           = "KN"
    "SAINT LUCIA"                           = "LC"
    "SAINT MARTIN (FRENCH PART)"            = "MF"
    "SAINT MIQUELON"                        = "PM"
    "SAINT GRENADINES"                      = "VC"
    "SAMOA"                                 = "WS"
    "SAN MARINO"                            = "SM"
    "SAO PRINCIPE"                          = "ST"
    "SAUDI ARABIA"                          = "SA"
    "SENEGAL"                               = "SN"
    "SERBIA"                                = "RS"
    "SEYCHELLES"                            = "SC"
    "SIERRA LEONE"                          = "SL"
    "SINGAPORE"                             = "SG"
    "SINT MAARTEN (DUTCH PART)"             = "SX"
    "SLOVAKIA"                              = "SK"
    "SLOVENIA"                              = "SI"
    "SOLOMON ISLANDS"                       = "SB"
    "SOMALIA"                               = "SO"
    "SOUTH AFRICA"                          = "ZA"
    "SOUTH GEORGIA ISLANDS"                 = "GS"
    "SOUTH SUDAN"                           = "SS"
    "SPAIN"                                 = "ES"
    "SRILANKA"                              = "LK"
    "SUDAN"                                 = "SD"
    "SURINAME"                              = "SR"
    "SVALBARD MAYEN"                        = "SJ"
    "SWAZILAND"                             = "SZ"
    "SWEDEN"                                = "SE"
    "SWITZERLAND"                           = "CH"
    "SYRIAN REPUBLIC"                       = "SY"
    "TAIWAN"                                = "TW"
    "TAJIKISTAN"                            = "TJ"
    "TANZANIA"                              = "TZ"
    "THAILAND"                              = "TH"
    "TIMOR-LESTE"                           = "TL"
    "TOGO"                                  = "TG"
    "TOKELAU"                               = "TK"
    "TONGA"                                 = "TO"
    "TRINIDAD"                              = "TT"
    "TUNISIA"                               = "TN"
    "TURKEY"                                = "TR"
    "TURKMENISTAN"                          = "TM"
    "TURKS ISLANDS"                         = "TC"
    "TUVALU"                                = "TV"
    "UGANDA"                                = "UG"
    "UKRAINE"                               = "UA"
    "UNITED EMIRATES"                       = "AE"
    "UNITED KINGDOM"                        = "GB"
    "UNITED STATES"                         = "US"
    "UNITED ISLANDS"                        = "UM"
    "URUGUAY"                               = "UY"
    "UZBEKISTAN"                            = "UZ"
    "VANUATU"                               = "VU"
    "VENEZUELA, BOLIVARIAN OF"              = "VE"
    "VIET NAM"                              = "VN"
    "VIRGIN ISLANDS, BRITISH"               = "VG"
    "VIRGIN ISLANDS, U.S."                  = "VI"
    "WALLIS FUTUNA"                         = "WF"
    "WESTERN SAHARA"                        = "EH"
    "YEMEN"                                 = "YE"
    "ZAMBIA"                                = "ZM"
    "ZIMBABWE"                              = "ZW"
}
$licenses = @{
    "O365_BUSINESS_ESSENTIALS"           = "Office 365 Business Essentials"
    "O365_BUSINESS_PREMIUM"              = "Office 365 Business Premium"
    "DESKLESSPACK"                       = "Office 365 (Plan K1)"
    "DESKLESSWOFFPACK"                   = "Office 365 (Plan K2)"
    "LITEPACK"                           = "Office 365 (Plan P1)"
    "EXCHANGESTANDARD"                   = "Office 365 Exchange Online Only"
    "STANDARDPACK"                       = "Enterprise Plan E1"
    "STANDARDWOFFPACK"                   = "Office 365 (Plan E2)"
    "ENTERPRISEPACK"                     = "Enterprise Plan E3"
    "ENTERPRISEPACKLRG"                  = "Enterprise Plan E3"
    "ENTERPRISEWITHSCAL"                 = "Enterprise Plan E4"
    "STANDARDPACK_STUDENT"               = "Office 365 (Plan A1) for Students"
    "STANDARDWOFFPACKPACK_STUDENT"       = "Office 365 (Plan A2) for Students"
    "ENTERPRISEPACK_STUDENT"             = "Office 365 (Plan A3) for Students"
    "ENTERPRISEWITHSCAL_STUDENT"         = "Office 365 (Plan A4) for Students"
    "STANDARDPACK_FACULTY"               = "Office 365 (Plan A1) for Faculty"
    "STANDARDWOFFPACKPACK_FACULTY"       = "Office 365 (Plan A2) for Faculty"
    "ENTERPRISEPACK_FACULTY"             = "Office 365 (Plan A3) for Faculty"
    "ENTERPRISEWITHSCAL_FACULTY"         = "Office 365 (Plan A4) for Faculty"
    "ENTERPRISEPACK_B_PILOT"             = "Office 365 (Enterprise Preview)"
    "STANDARD_B_PILOT"                   = "Office 365 (Small Business Preview)"
    "VISIOCLIENT"                        = "Visio Pro Online"
    "POWER_BI_ADDON"                     = "Office 365 Power BI Addon"
    "POWER_BI_INDIVIDUAL_USE"            = "Power BI Individual User"
    "POWER_BI_STANDALONE"                = "Power BI Stand Alone"
    "POWER_BI_STANDARD"                  = "Power-BI Standard"
    "PROJECTESSENTIALS"                  = "Project Lite"
    "PROJECTCLIENT"                      = "Project Professional"
    "PROJECTONLINE_PLAN_1"               = "Project Online"
    "PROJECTONLINE_PLAN_2"               = "Project Online and PRO"
    "ProjectPremium"                     = "Project Online Premium"
    "ECAL_SERVICES"                      = "ECAL"
    "EMS"                                = "Enterprise Mobility Suite"
    "RIGHTSMANAGEMENT_ADHOC"             = "Windows Azure Rights Management"
    "MCOMEETADV"                         = "PSTN conferencing"
    "SHAREPOINTSTORAGE"                  = "SharePoint storage"
    "PLANNERSTANDALONE"                  = "Planner Standalone"
    "CRMIUR"                             = "CMRIUR"
    "BI_AZURE_P1"                        = "Power BI Reporting and Analytics"
    "INTUNE_A"                           = "Windows Intune Plan A"
    "PROJECTWORKMANAGEMENT"              = "Office 365 Planner Preview"
    "ATP_ENTERPRISE"                     = "Exchange Online Advanced Threat Protection"
    "EQUIVIO_ANALYTICS"                  = "Office 365 Advanced eDiscovery"
    "AAD_BASIC"                          = "Azure Active Directory Basic"
    "RMS_S_ENTERPRISE"                   = "Azure Active Directory Rights Management"
    "AAD_PREMIUM"                        = "Azure Active Directory Premium"
    "MFA_PREMIUM"                        = "Azure Multi-Factor Authentication"
    "STANDARDPACK_GOV"                   = "Microsoft Office 365 (Plan G1) for Government"
    "STANDARDWOFFPACK_GOV"               = "Microsoft Office 365 (Plan G2) for Government"
    "ENTERPRISEPACK_GOV"                 = "Microsoft Office 365 (Plan G3) for Government"
    "ENTERPRISEWITHSCAL_GOV"             = "Microsoft Office 365 (Plan G4) for Government"
    "DESKLESSPACK_GOV"                   = "Microsoft Office 365 (Plan K1) for Government"
    "ESKLESSWOFFPACK_GOV"                = "Microsoft Office 365 (Plan K2) for Government"
    "EXCHANGESTANDARD_GOV"               = "Microsoft Office 365 Exchange Online (Plan 1) only for Government"
    "EXCHANGEENTERPRISE_GOV"             = "Microsoft Office 365 Exchange Online (Plan 2) only for Government"
    "SHAREPOINTDESKLESS_GOV"             = "SharePoint Online Kiosk"
    "EXCHANGE_S_DESKLESS_GOV"            = "Exchange Kiosk"
    "RMS_S_ENTERPRISE_GOV"               = "Windows Azure Active Directory Rights Management"
    "OFFICESUBSCRIPTION_GOV"             = "Office ProPlus"
    "MCOSTANDARD_GOV"                    = "Lync Plan 2G"
    "SHAREPOINTWAC_GOV"                  = "Office Online for Government"
    "SHAREPOINTENTERPRISE_GOV"           = "SharePoint Plan 2G"
    "EXCHANGE_S_ENTERPRISE_GOV"          = "Exchange Plan 2G"
    "EXCHANGE_S_ARCHIVE_ADDON_GOV"       = "Exchange Online Archiving"
    "EXCHANGE_S_DESKLESS"                = "Exchange Online Kiosk"
    "SHAREPOINTDESKLESS"                 = "SharePoint Online Kiosk"
    "SHAREPOINTWAC"                      = "Office Online"
    "YAMMER_ENTERPRISE"                  = "Yammer Enterprise"
    "EXCHANGE_L_STANDARD"                = "Exchange Online (Plan 1)"
    "MCOLITE"                            = "Lync Online (Plan 1)"
    "SHAREPOINTLITE"                     = "SharePoint Online (Plan 1)"
    "OFFICE_PRO_PLUS_SUBSCRIPTION_SMBIZ" = "Office ProPlus"
    "EXCHANGE_S_STANDARD_MIDMARKET"      = "Exchange Online (Plan 1)"
    "MCOSTANDARD_MIDMARKET"              = "Lync Online (Plan 1)"
    "SHAREPOINTENTERPRISE_MIDMARKET"     = "SharePoint Online (Plan 1)"
    "OFFICESUBSCRIPTION"                 = "Office ProPlus"
    "YAMMER_MIDSIZE"                     = "Yammer"
    "DYN365_ENTERPRISE_PLAN1"            = "Dynamics 365 Customer Engagement Plan Enterprise Edition"
    "ENTERPRISEPREMIUM_NOPSTNCONF"       = "Enterprise E5 (without Audio Conferencing)"
    "ENTERPRISEPREMIUM"                  = "Enterprise E5 (with Audio Conferencing)"
    "MCOSTANDARD"                        = "Skype for Business Online Standalone Plan 2"
    "PROJECT_MADEIRA_PREVIEW_IW_SKU"     = "Dynamics 365 for Financials for IWs"
    "STANDARDWOFFPACK_IW_STUDENT"        = "Office 365 Education for Students"
    "STANDARDWOFFPACK_IW_FACULTY"        = "Office 365 Education for Faculty"
    "EOP_ENTERPRISE_FACULTY"             = "Exchange Online Protection for Faculty"
    "EXCHANGESTANDARD_STUDENT"           = "Exchange Online (Plan 1) for Students"
    "OFFICESUBSCRIPTION_STUDENT"         = "Office ProPlus Student Benefit"
    "STANDARDWOFFPACK_FACULTY"           = "Office 365 Education E1 for Faculty"
    "STANDARDWOFFPACK_STUDENT"           = "Microsoft Office 365 (Plan A2) for Students"
    "DYN365_FINANCIALS_BUSINESS_SKU"     = "Dynamics 365 for Financials Business Edition"
    "DYN365_FINANCIALS_TEAM_MEMBERS_SKU" = "Dynamics 365 for Team Members Business Edition"
    "FLOW_FREE"                          = "Microsoft Flow Free"
    "POWER_BI_PRO"                       = "Power BI Pro"
    "O365_BUSINESS"                      = "Office 365 Business"
    "DYN365_ENTERPRISE_SALES"            = "Dynamics Office 365 Enterprise Sales"
    "RIGHTSMANAGEMENT"                   = "Rights Management"
    "PROJECTPROFESSIONAL"                = "Project Professional"
    "VISIOONLINE_PLAN1"                  = "Visio Online Plan 1"
    "EXCHANGEENTERPRISE"                 = "Exchange Online Plan 2"
    "DYN365_ENTERPRISE_P1_IW"            = "Dynamics 365 P1 Trial for Information Workers"
    "DYN365_ENTERPRISE_TEAM_MEMBERS"     = "Dynamics 365 For Team Members Enterprise Edition"
    "CRMSTANDARD"                        = "Microsoft Dynamics CRM Online Professional"
    "EXCHANGEARCHIVE_ADDON"              = "Exchange Online Archiving For Exchange Online"
    "EXCHANGEDESKLESS"                   = "Exchange Online Kiosk"
    "SPZA_IW"                            = "App Connect"
    "WINDOWS_STORE"                      = "Windows Store for Business"
    "MCOEV"                              = "Microsoft Phone System"
    "VIDEO_INTEROP"                      = "Polycom Skype Meeting Video Interop for Skype for Business"
    "SPE_E5"                             = "Microsoft 365 E5"
    "SPE_E3"                             = "Microsoft 365 E3"
    "ATA"                                = "Advanced Threat Analytics"
    "MCOPSTN2"                           = "Domestic and International Calling Plan"
    "FLOW_P1"                            = "Microsoft Flow Plan 1"
    "FLOW_P2"                            = "Microsoft Flow Plan 2"
    "CRMSTORAGE"                         = "Microsoft Dynamics CRM Online Additional Storage"
    "SMB_APPS"                           = "Microsoft Business Apps"
    "MICROSOFT_BUSINESS_CENTER"          = "Microsoft Business Center"
    "DYN365_TEAM_MEMBERS"                = "Dynamics 365 Team Members"
    "STREAM"                             = "Microsoft Stream Trial"
    "EMSPREMIUM"                         = "ENTERPRISE MOBILITY + SECURITY E5"
}

<#============================= Added variables above here =====================================#>

# Connects to 365 tenent using a profile created with New-365_Profile
function Connect-365_Profile {
    $Company = (Get-ChildItem $env:USERPROFILE\AppData\Roaming\365Connect\365Profiles).name -replace '.csv', '' | Out-GridView -Title 'Select Company Profile' -PassThru
    Get-Pssession | Remove-PSSession
    Import-Module microsoft.powershell.security
    Import-module msonline
    $CSV = Import-Csv "$env:USERPROFILE\AppData\Roaming\365Connect\365Profiles\$Company.csv"
    foreach ($Object in $CSV) {
        $User = $Object.User
        $Password = $Object.Password | ConvertTo-SecureString
    }
	
    $cred = New-Object system.management.automation.pscredential -ArgumentList $User, $Password
    $outlook = "https://outlook.office365.com/powershell-liveid"
    Clear-Host
    Write-Host "Connecting to $Company`..." -ForegroundColor Green
    Try { 
        Write-Host "Importing MSonline module..." -ForegroundColor Green
        Connect-MsolService -Credential $cred -ErrorAction Stop
        Write-Host "Importing Exchange Online module..." -ForegroundColor Green
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $outlook -Authentication Basic -Credential $cred -AllowRedirection -ErrorAction Stop
        Import-PSSession $Session -AllowClobber
        $Domain = (Get-MsolDomain | Where-Object { $_.Authentication -match 'Federated' }).name
        $host.ui.RawUI.WindowTitle = "Connect365 - You are connceted to $Domain"
        Clear-Host
        # this stores the users and mailboxes into variables so these don't have to be looded every time a function calls data from 365 tenent
        Write-Host "Indexing Users..." -ForegroundColor Green
        $script:UPN = Get-MsolUser -All 
        Write-Host "Indexing Mailboxes..." -ForegroundColor Green
        $script:Mailbox = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.IsMailboxEnabled -eq $True } | Select-Object Name, UserPrincipalName, HiddenFromAddressListsEnabled, IsDirSynced  
        Write-Host "Indexing Distribution Groups..." -ForegroundColor Green
        $script:DL = Get-DistributionGroup
        $script:Mailbox_Members = $Mailbox
        Write-Verbose "Run command *Invoke-365_Command* to get started" -Verbose
    }
    Catch {
        Write-Error $error
    }
}

# this uses Get-Credential to connect to 365 tenent without using a profile
function Connect-365_Tenant {
    Get-Pssession | Remove-PSSession
    Import-Module microsoft.powershell.security
    Import-module msonline
    $Cred = Get-Credential
    $Connectedto = $Cred.UserName
    $Connectedto = $Connectedto.Remove(1, $Connectedto.IndexOf('@'))
    Write-Host "Connecting to $Connectedto`..." -ForegroundColor Green
    $outlook = "https://outlook.office365.com/powershell-liveid"
    try {
        Write-Host "Connecting to MsolService..." -ForegroundColor Green
        Connect-MsolService -Credential $cred -ErrorAction Stop
        Write-Host "Connecting to Exchange Online..." -ForegroundColor Green
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $outlook -Authentication Basic -Credential $Cred -AllowRedirection -ErrorAction Stop
        Import-PSSession $Session -AllowClobber
        $Domain = (Get-MsolDomain | Where-Object { $_.Authentication -match 'Federated' }).name
        $host.ui.RawUI.WindowTitle = "Connect365 - You are connceted $Domain"
        Clear-Host
        Write-Host "Indexing Users..." -ForegroundColor Green
        $script:UPN = Get-MsolUser -All 
        Write-Host "Indexing Mailboxes..." -ForegroundColor Green
        $script:Mailbox = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.IsMailboxEnabled -eq $True } | Select-Object name, UserPrincipalName 
        $script:DL = Get-DistributionGroup
        $script:Mailbox_Members = $Mailbox
    }
    catch {
        Write-Error $error
    }
}

# creates new profile - this is a csv stored in $env:USERPROFILE\AppData\Roaming\365Connect\365Profiles
# Password is encrypted with Get-Credential and stored as a string ConvertFrom-SecureString in CSV
Function New-365_Profile {  
    If ((Test-Path "$env:USERPROFILE\AppData\Roaming\365Connect") -eq $false) {
        New-Item -Path "$env:USERPROFILE\AppData\Roaming\365Connect\365Profiles" -ItemType "directory" -Force 
    } 
    $confirmation = "y"
    while ($confirmation -eq "y") {
        $Company = Read-Host "Enter company Name"
        New-Item "$env:USERPROFILE\AppData\Roaming\365Connect\365Profiles\$Company.csv" -Force | Out-Null
        $Cred = Get-Credential
        Add-Content -Path "$env:USERPROFILE\AppData\Roaming\365Connect\365Profiles\$Company.csv" -Value '"User","Password"' -Force
        $NewLine = "{0},{1}" -f $Cred.UserName, ($Cred.Password | ConvertFrom-SecureString)
        $NewLine | add-content -Path "$env:USERPROFILE\AppData\Roaming\365Connect\365Profiles\$Company.csv"
        Write-Host "$Company Proflie has been craeted" -ForegroundColor Green
        $confirmation = Read-Host "Create another Company profile [y/n]"
    }
}

# Opens Folder loation to 365 service desk files
Function Open-365_Location { Invoke-Item "$env:USERPROFILE\AppData\Roaming\365Connect" }

<#============================= Added 365 service desk Functions Above here =====================================#>

# one commend to run them all :)
function Invoke-365_Command { 
    $Commends = [ordered]@{
        <# MSOL options #>  
        'Show licenses'                              = 'Display all licenses and licenses quantities, opens webpage to 365 licensing'
        'Show Licenses Conversion Table'             = 'Show licenses conversion table powershell names and frendly names'   
        'Show user details'                          = 'Display User details ie assigned licenses'
        'New user account'                           = 'Creates a new online 365 user account with option to assign licenses'
        'Remove user account(s)'                     = 'Soft deletes selected MSOL user(s) accounts' 
        'Add License(s) to User'                     = 'Adds selected license(s) to selected user'
        'Remove License(s) from User'                = 'Removes selected license(s) to selected user'
        'Reset users password'                       = 'Reset user password to a temporary new password - has to be changed at next login'
        'Enable user account'                        = 'Enables  user login to 365 account with option to reset to a temporary password'
        'Disable user account'                       = 'Disables user login to 365 account with option to reset to a random password'
                    
        <# exchage online mailbox options #>
        'Create new shared MailBox'                  = 'Create new shared mailBox group with given name, Then gives opiton to grant full permissions and send as permissions to selected members(s)'
        'Change Mailbox Type'                        = 'Change Mailbox Type to Regular, Shared, Room, Equipment'  
        'Add full access To MailBox'                 = 'Adds full permissions and send as permissions to selected members(s) to selected mailBox'
        'Add Calendar access to a MailBox'           = 'Adds calendar access permissions to selected members(s) to selected mailBox'
        'Add read only access to a MailBox'          = 'Adds read only access permissions to selected Members(s) to selected mailBox'
        'Remove full access to a MailBox'            = 'Removes full permissions and send as permissions to selected members(s) to selected mailBox'
        'Remove all access to MailBox'               = 'Removes all access to mailbox' 
        'Hide Mailbox(s)'                            = 'Hides selected Mailbox(s) from GAL - only shows non hidden Mailbox(s)'
        'Unhide Mailbox(s)'                          = 'Unhides selected Mailbox(s) from GAL - only shows hidden Mailbox(s)'
      
        <# exchage distribution group options #>
        'Create new Distribution Group'              = 'Create new distribution group with given name'
        'List Distribution Group members'            = 'Show all members of selected distribution group with option to export list as CSV'
        'Add Member(s) to a Distribution Group'      = 'Adds selected members(s) to selected distribution group'
        'Remove Member(s) from a Distribution Group' = 'Removes selected members(s) to selected distribution group'
        'Export Distribution Groups'                 = 'Export Distribution Groups to CSV' 
        'Hide Distribution Group(s)'                 = 'Hides selected Distribution Group(s) from GAL-  only shows non hidden Distribution Group(s)'
        'Unhide Distribution Group(s)'               = 'Unhides selected Distribution Group(s) from GAL - only shows hidden distribution groups'
        <# 365 service desk commands #> 
        'Create new Connect365 Profile'              = 'Creates new 365 connect profile'
        'Connect to 365 tenant with stored profile'  = 'Connect to 365 tenant with a stored profile'
        'Connect to 365 tenant with credentials'     = 'Connect to 365 tenant with credentials'
        'Open 365 service desk files location'       = 'Opens files Location where profiles and logs are stored'  
        'Exit'                                       = 'Removes all PSSessions and closes 365Connect'
    }
    $Result = $Commends | Out-GridView -PassThru  -Title 'Make a  selection'
    Switch ($Result) {
        
        <# Msol user commands #>
        { $Result.Name -eq 'Show licenses' } { Get-365_AvailableLicenses }
        { $Result.Name -eq 'Show Licenses Conversion Table' } { Show-365_LicensesConversionTable }
        { $Result.Name -eq 'New user account' } { New-365_User }
        { $Result.Name -eq 'Remove user account(s)' } { Remove-365_User }
        { $Result.Name -eq 'Reset users password' } { Reset-365_UserPassword }
        { $Result.Name -eq 'Show user details' } { Get-365_UserDetails }
        { $Result.Name -eq 'Add License(s) to User' } { Add-365_UserLicense }
        { $Result.Name -eq 'Remove License(s) User' } { Remove-365_UserLicense }
        { $Result.Name -eq 'Disable user account' } { Disable-365_User }
        { $Result.Name -eq 'Enable user account' } { Enable-365_User }
        
        <# Mailbox commands #>
        { $Result.Name -eq 'Show MailBox details' } { Get-365_MailBoxDetails }
        { $Result.Name -eq 'Change Mailbox Type'  } { Set-365_MailboxType }
        { $Result.Name -eq 'Create new shared MailBox' } { New-365_SharedMailBox }
        { $Result.Name -eq 'Add full access To MailBox' } { Add-365_FullAccessToMailBox }
        { $Result.Name -eq 'Add Calendar access to a MailBox' } { Add-365_CalendarAccess }
        { $Result.Name -eq 'Add Read Only access to a MailBox' } { Add-365_ReadOnlyAccessToMailBox }
        { $Result.Name -eq 'Remove full access to a MailBox' } { Remove-365_FullAccessToMailBox }
        { $Result.Name -eq 'Remove all access to MailBox' } { Remove-365_AllAccessToMailBox }
        { $Result.Name -eq 'Hide Mailbox(s)' } { Set-365_MailboxToHidden }
        { $Result.Name -eq 'Unhide Mailbox(s)' } { Set-365_MailboxToNotHidden }
        <# Distribution Group commands #>
        { $Result.Name -eq 'Create new Distribution Group' } { New-365_DistributionGroup } 
        { $Result.Name -eq 'Remove a Distribution Group' } { Remove-365_DistributionGroup } 
        { $Result.Name -eq 'Add Member(s) to a Distribution Group' } { Add-365_DistributionGroupMember }
        { $Result.Name -eq 'Remove Member(s) from a Distribution Group' } { Remove-365_DistributionGroupMember }
        { $Result.Name -eq 'List Distribution Groups members' } { Get-365_DistributionGroupMembers }
        { $Result.Name -eq 'Export Distribution Groups' } { Export-365_AllDistributionGroupAndMembers }
        { $Result.Name -eq 'Hide Distribution Group(s)' } { Set-365_DistributionGroupToHidden }
        { $Result.Name -eq 'Unhide Distribution Group(s)' } { Set-365_DistributionGroupToNotHidden }
        
        <# 365 service desk commands #>
        { $Result.Name -eq 'Create new Connect365 Profile' } { New-365_Profile }  
        { $Result.Name -eq 'Connect to 365 tenant with stored profile' } { Connect-365_Profile }
        { $Result.Name -eq 'Connect to 365 tenant with credentials' } { Connect-365_Tenant }  
        { $Result.Name -eq 'Open 365 service desk files location' } { Open-365_Location }
        { $Result.Name -eq 'Exit' } { Exit-365 }  
    } 
} 

# kills powershell and all PSSessions 
function Exit-365 {
    Get-PSSession | Remove-PSSession
    Stop-Process -Id $PID
}

<#============================= Added non 365 Functions Above here =====================================#>

# Shows available licenses with the powershell name and the friendly license name conversion key 
function Get-365_AvailableLicenses {
    Get-MsolAccountSku
    $Confirmation = Read-Host "Export Available Licenses to CSV?[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Export Available Licenses to CSV?"
    }
    if ($confirmation -eq "y") {
        $FileName = (Get-MsolCompanyInformation).DisplayName
        Write-Host "Exporting list to $env:USERPROFILE\desktop\$FileName` Licenses.csv" -ForegroundColor Green
        Get-MsolAccountSku | Select-Object AccountSkuId, ActiveUnits, WarningUnits, ConsumedUnits | Export-Csv -Path "$env:USERPROFILE\desktop\$FileName` Licenses.csv"
    }
}
# Show licenses conversion table powershell names and frendly names
function Show-365_LicensesConversionTable {
    $licenses | Out-GridView -Title "Licenses conversion Table"
}

# Shows user details
function Get-365_UserDetails {
    $UPN = ($UPN | Out-GridView -Title 'Select User' -PassThru).UserPrincipalName
    Get-MsolUser -UserPrincipalName $UPN | Select-Object DisplayName, UserPrincipalName, ProxyAddresses, Title, Department, Office, UsageLocation, IsLicensed, Licenses, WhenCreated, LastDirSyncTime, BlockCredential | Format-List 
}

# Creates new Msol account for non-federated (non-AD synced) domains 
function New-365_User {
    $Domain = Get-MsolDomain | Where-Object { $_.Authentication -ne 'Federated' } | Out-GridView -Title "Select domain" -PassThru
    Write-Verbose "don't added *@$Domain* at the end"-Verbose
    $User = Read-Host "Enter Username" 
    $UPN = $User + '@' + $Domain.name
        $FirstName = Read-Host "Enter users first Name"
        $LastName = Read-Host "Enter users last Name"
        $DisplayName = $FirstName + ' ' + $LastName
        $Password = Read-Host "Enter password"
        $location = $location | Out-GridView -Title 'Select location' -PassThru 
        $License = (Get-MsolAccountSku | Out-GridView -Title 'Select License - you can shift/ctrl click multiple Licenses' -PassThru).AccountSkuId
        Try {            
            New-MsolUser -UserPrincipalName "$UPN" -FirstName $FirstName -LastName $LastName `
                -Password  $Password -DisplayName "$DisplayName" -UsageLocation $location.value `
                -LicenseAssignment $License -ForceChangePassword $true -ErrorAction stop
            Write-Host "Indexing Users..." -ForegroundColor Green
            $script:UPN = Get-MsolUser -All 
            Write-Host "Indexing Mailboxes..." -ForegroundColor Green
            $script:Mailbox = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.IsMailboxEnabled -eq $True } | Select-Object Name, UserPrincipalName, HiddenFromAddressListsEnabled, IsDirSynced  
        }
        catch {
            Write-Host "$error[0].Exception" -ForegroundColor red  
    }
}

# Soft deletes selected MSOL user(s) accounts
function Remove-365_User { 
    $UPN = ($UPN | Out-GridView -Title 'Select User - you can shift/ctrl click multiple Licenses' -PassThru).UserPrincipalName
        $Confirmation = Read-Host "Remove $UPN from office 365 Tenant?[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Remove $UPN from office 365 Tenant?[y/n]"
    }
    if ($confirmation -eq "y") { 
        foreach ($Account in $UPN) {
            Remove-msoluser -UserPrincipalName $Account -ErrorAction Stop
            Write-Host "$Account Deleted" -ForegroundColor Green
        }
    }
    Write-Host "Updating User Index..." -ForegroundColor Green
    $script:UPN = Get-MsolUser -All 
}

# Resets user password at the tenant level only unless AzureAD premium is enabled 
function Reset-365_UserPassword {    
    $UPN = ($UPN | Out-GridView -Title 'Select User' -PassThru).UserPrincipalName
    $Password = Read-Host "Enter new password" 
    $Confirmation = Read-Host "Reset Password for $UPN`?[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Reset Password for $UPN`?[y/n]"
    }
    if ($confirmation -eq "y") { 
        try {
            Set-MsolUserPassword -UserPrincipalName $UPN -NewPassword $Password -ForceChangePassword $true -ErrorAction Stop
            Write-Host "$UPN temporary password is $Password" -ForegroundColor Green
        }
        catch { 
            Write-Host "$error[0].Exception" -ForegroundColor red
        }
    }
}

# Enable user sign into 365 tenent and reset to a temporary password.
function Enable-365_User {
    $UPN = ($UPN | Out-GridView -Title 'Select User' -PassThru).UserPrincipalName
    $Confirmation = Read-Host "Enable $UPN`?[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Enable $UPN`?[y/n]"
    }
    if ($confirmation -eq "y") {
        Set-MsolUser -UserPrincipalName $UPN -blockcredential $false
        Write-Host "$UPN account is now enabled" -ForegroundColor Green
        $Confirmation = Read-Host "Reset Password for $UPN`?[y/n]"
        while ($confirmation -ne "y") {
            if ($confirmation -eq 'n') { Break } 
            $confirmation = Read-Host "Reset Password for $UPN`?[y/n]"
            if ($confirmation -eq "y") { 
                try {
                    Set-MsolUserPassword -UserPrincipalName $UPN -NewPassword $Password -ForceChangePassword -ErrorAction Stop
                    Write-Host "$UPN temporary password is $Password" -ForegroundColor Green
                }
                catch { 
                    Write-Host "$error[0].Exception" -ForegroundColor red
                }
            }
        }
    }
}

# disable user login to 365 tenent and reset to a random password 
function Disable-365_User {
    $UPN = ($UPN | Out-GridView -Title 'Select User' -PassThru).UserPrincipalName
    $Confirmation = Read-Host "Disable $UPN`?[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Disable $UPN`?[y/n]"
    }
    if ($confirmation -eq "y") {
        Set-MsolUser -UserPrincipalName $UPN -blockcredential $true
        Write-Host "$UPN account is now Blocked" -ForegroundColor Green
        $Confirmation = Read-Host "Reset Password for $UPN`?[y/n]"
        while ($confirmation -ne "y") {
            if ($confirmation -eq 'n') { Break } 
            $confirmation = Read-Host "Reset Password for $UPN`?[y/n]"
            if ($confirmation -eq "y") { 
                $Random = Get-Random
                $Password = "Rn" + $Random    
                Set-MsolUserPassword -UserPrincipalName $UPN -NewPassword $Password
                Write-Host "$UPN password has been reset to $Password" -ForegroundColor Green
            }
        }
    }
}

# Adds selceted licenses to selceted users
function Add-365_UserLicense {
    $UPN = ($UPN | Out-GridView -Title 'Select User' -PassThru).UserPrincipalName
    $Licenses = (Get-MsolAccountSku | Out-GridView -Title 'Select License(s) - you can shift/ctrl click multiple Licenses' -PassThru).AccountSkuId
    $confirmation = Read-Host "Add $Licenses from $UPN`?[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Add $Licenses from $UPN`?[y/n]"
    }
    if ($confirmation -eq "y") {
        Foreach ($License in $Licenses) {
            Write-Host "Adding $License" -ForegroundColor Green
            Set-MsolUserLicense -UserPrincipalName $UPN -AddLicenses $License
        }
        Write-Host "Updating User Index..." -ForegroundColor Green
        $script:UPN = Get-MsolUser -All 
    }	
}

# Removes licenses from selceted user
function Remove-365_UserLicense {
    $UPN = $UPN | Where-Object { $_.islicensed -match $true } | Out-GridView -Title 'Select User' -PassThru
    $Licenses = $UPN.Licenses.Accountskuid | Out-GridView -Title 'Select License(s) - you can shift/ctrl click multiple Licenses' -PassThru
    $Confirmation = Read-Host "Remove $Licenses from $UPN`?[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Remove $Licenses from $UPN`?[y/n]"
    }
    if ($confirmation -eq "y") {
        Foreach ($License in $Licenses) {
            Write-Host "Removing $License" -ForegroundColor Green
            Set-MsolUserLicense -UserPrincipalName $UPN.UserPrincipalName -RemoveLicenses $License
        }
        Write-Host "Updating User Index..." -ForegroundColor Green
        $script:UPN = Get-MsolUser -All 
    }	
}

<#============================= Added MSonline Functions Above here =====================================#>

function Get-365_MailBoxDetails {    
    $Mailbox = ($Mailbox | Out-GridView -Title 'Select Mailbox' -PassThru).UserPrincipalName
    Get-Mailbox $Mailbox | Format-List
}
function Set-365_MailboxType {
    $Mailbox = ($Mailbox | Out-GridView -Title 'Select Mailbox(s) - you can shift/ctrl click multiple Mailboxs' -PassThru).UserPrincipalName
    $Commends = @{
        'Regular'           = 'Regular mailboxes are the mailboxes that get assigned to every individual Exchange user'
        'Shared'            = 'Shared mailboxes are usually configured for multiple user access'
        'Equipment'         = 'These mailboxes are used for resources that are not location-specific like the portable system, microphones, projectors, or company cars.'
        'Room'              = 'This kind of mailbox gets assigned to different meeting locations, for example, auditoriums, conference and training rooms.'
    }
    $Result = $Commends | Out-GridView -PassThru  -Title 'Make a  selection'
    Switch ($Result) {
        { $Result.Name -eq 'Regular' } { $Type = 'Regular' }
        { $Result.Name -eq 'Shared' } { $Type  = 'Shared' }
        { $Result.Name -eq 'Equipment' } { $Type  = 'Equipment' }
        { $Result.Name -eq 'Room' } { $Type  = 'Room' }
    }   
    foreach ($box in $Mailbox) {
        Set-mailbox $box -type $Type -Confirm
        Write-Host "Convering $box to $Type" -ForegroundColor Green
    }
    Write-Host "Updating Mailbox Index..." -ForegroundColor Green
    $script:Mailbox = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.IsMailboxEnabled -eq $True } | Select-Object name, UserPrincipalName, HiddenFromAddressListsEnabled, IsDirSynced
}
# Creates new shared MailBox
function New-365_SharedMailBox {
    $Name = Read-Host -Prompt "Enter email Address name" 
    New-Mailbox -Shared -Name $Name -Confirm
    $Confirmation = Read-Host "Give users full asscess to $Name[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Give users full asscess to $Name[y/n]"
    }
    if ($confirmation -eq "y") {
        $Mailbox_Members = ($Mailbox_Members | Out-GridView -Title "Select Users to give FullAccess to $Mailbox" -PassThru).UserPrincipalName 
        foreach ($Member in $Mailbox_Members) {
            Add-MailboxPermission -Identity $Name -User $Member-AccessRights FullAccess -InheritanceType All -Confirm:$false 
            Add-RecipientPermission -Identity $Name -AccessRights SendAs -Trustee $Member -Confirm:$false 
        }
    }
    Write-Host "Updating Mailbox Index..." -ForegroundColor Green
    $script:Mailbox = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.IsMailboxEnabled -eq $True } | Select-Object name, UserPrincipalName, HiddenFromAddressListsEnabled, IsDirSynced
}

# Grants full access and send as permissions to mailbox 
function Add-365_FullAccessToMailBox {
    $Mailbox = ($Mailbox | Out-GridView -Title 'Select Mailbox' -PassThru).UserPrincipalName
    $Mailbox_Members = ($Mailbox_Members | Out-GridView -Title "Select Users to give FullAccess to $Mailbox - you can shift/ctrl click multiple Mailboxs" -PassThru).UserPrincipalName
    $Confirmation = Read-Host "Give full for all selceted users to $Name[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Give full for all selceted users to $Name[y/n]"    
    }
    if ($confirmation -eq "y") {
        foreach ($Member in $Mailbox_Members) {
            Add-MailboxPermission -Identity $Mailbox -User $Member -AccessRights FullAccess -InheritanceType All -Confirm:$True  
            Add-RecipientPermission -Identity $Mailbox -AccessRights SendAs -Trustee $Member -Confirm:$false 
        }
    }
}

# removes selected users send as and full mailbox permissions
function Remove-365_FullAccessToMailBox {
    $Domain = (Get-MsolDomain | Where-Object { $_.Authentication -match 'Federated' }).name
    $Mailbox = ($Mailbox | Out-GridView -Title 'Select Mailbox' -PassThru).UserPrincipalName
    $Title = "Select Mailboxs - you can shift/ctrl click multiple Mailboxs"
    $Mailbox_Members = (Get-Mailboxpermission $Mailbox.UserPrincipalName | Where-Object { $_.User -like "*$Domain*" } | Select-Object user | Out-GridView -Title $Title PassThru).user
    $Confirmation = Read-Host "Remove full for all users to $Name[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Remove full for all users to $Name[y/n]"    
    }
    if ($confirmation -eq "y") {
        foreach ($Member in $Mailbox_Members) {
            Remove-MailboxPermission -Identity $Mailbox -User $Member -AccessRights FullAccess -InheritanceType All
            Remove-RecipientPermission $Mailbox -AccessRights SendAs -Trustee $Member -Confirm:$false 
        }
    }
}

# Removes all access to mailbox
function Remove-365_AllAccessToMailBox {
    $Domain = (Get-MsolDomain | Where-Object { $_.Authentication -match 'Federated' }).name
    $Mailbox = ($Mailbox | Out-GridView -Title 'Select Mailbox' -PassThru).UserPrincipalName
    $Title = "Select Mailboxs - you can shift/ctrl click multiple Mailboxs"
    $Mailbox_Members = (Get-Mailboxpermission $Mailbox.UserPrincipalName | Where-Object { $_.User -like "*$Domain*" } | Select-Object user | Out-GridView -Title  $Title -PassThru).user
    $Access = "FullAccess", "SendAs", "ExternalAccount", "DeleteItem", "ReadPermission", "ChangePermission", "ChangeOwner"
    $Confirmation = Read-Host "Remove all access users to $Name[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Remove all access users to $Name[y/n]" 
    }
    if ($confirmation -eq "y") {
        foreach ($Member in $Mailbox_Members) {
            # remove send behalf of permissions
            Remove-MailboxPermission -Identity $Mailbox -User $Member -AccessRights $Access -InheritanceType All -Confirm:$false 
            Remove-RecipientPermission $Mailbox -AccessRights SendAs -Trustee $Member -Confirm:$false 
        }
    }
}

# Gives Editor or Reviewer calendar access to seclected mailbox 
function Add-365_CalendarAccess {
    $Mailbox = ($Mailbox | Out-GridView -Title 'Select Mailbox' -PassThru).UserPrincipalName
    $Mailbox_Members = ($Mailbox_Members | Out-GridView -Title "Select Users to give FullAccess to $Mailbox" -PassThru).UserPrincipalName
    $Commends = [ordered]@{
        'Editor' = 'Full acecss to to calender, Can create booking and meetings'
        'Reviewer' = 'Reviewer read only access to calender'
    }
    $Result = $Commends | Out-GridView -PassThru  -Title 'Make a  selection'
    Switch ($Result) {
        { $Result.Name -eq 'Editor' } { $Access = 'Editor' }
        { $Result.Name -eq 'Reviewer' } { $Access = 'Reviewer' }
    } 
    foreach ($Member in $Mailbox_Members) {
        Add-MailboxFolderPermission -Identity "$Mailbox`:\Calendar" -User $Member -AccessRights $Access -SharingPermissionFlags Delegate
    }
}

function Add-365_ReadOnlyAccessToMailBox {
    $Mailbox = ($Mailbox | Out-GridView -Title 'Select Mailbox' -PassThru).UserPrincipalName
    $user = ($Mailbox_Members | Out-GridView -Title "Select User to give Read only to $Mailbox" -PassThru).UserPrincipalName
    $exclusions = @("/Sync Issues",
        "/Sync Issues/Conflicts",
        "/Sync Issues/Local Failures",
        "/Sync Issues/Server Failures",
        "/Recoverable Items",
        "/Deletions",
        "/Purges",
        "/Versions"
    )
    $mailboxfolders = @(Get-MailboxFolderStatistics $Mailbox | Where-Object { !($exclusions -icontains $_.FolderPath) } | Select-Object FolderPath)
    foreach ($mailboxfolder in $mailboxfolders) {
        $folder = $mailboxfolder.FolderPath.Replace("/", "\")
        if ($folder -match "Top of Information Store") {
            $folder = $folder.Replace("\Top of Information Store", "\")
        }
        $identity = "$($mailbox):$folder"
        Write-Host "Adding $user to $identity with Reviewer permissions"
        Add-MailboxFolderPermission -Identity $identity -User $user -AccessRights Reviewer
    }
}

# Sets HiddenFromAddressListsEnabled to true for each selected Mailbox(s) (Not DirSynced)
function Set-365_MailboxToHidden {
    $Mailbox = ($Mailbox | Where-Object { $_.HiddenFromAddressListsEnabled -eq $false } | Where-Object { $_.IsDirSynced -eq $false } | Out-GridView -Title "Select Mailbox(s) - you can shift/ctrl click multiple Group(s)" -PassThru).UserPrincipalName
    foreach ($Mailbox_UPN in $Mailbox) {
        Set-Mailbox -Identity $Mailbox_UPN -HiddenFromAddressListsEnabled $true 
        Write-Host "$Mailbox_UPN is now hidden from global address list" -ForegroundColor Green
    }
    Write-Host "Updating Mailbox Index..." -ForegroundColor Green
    $script:Mailbox = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.IsMailboxEnabled -eq $True } | Select-Object name, UserPrincipalName, HiddenFromAddressListsEnabled, IsDirSynced
}

# removes HiddenFromAddressListsEnabled from selected Mailbox(s) (Not DirSynced)
function Set-365_MailboxToNotHidden {
    $Mailbox = ($Mailbox | Where-Object { $_.HiddenFromAddressListsEnabled -eq $true } | Where-Object { $_.IsDirSynced -eq $false } | Out-GridView -Title "Select Distribution Group(s) - you can shift/ctrl click multiple Group(s)" -PassThru).UserPrincipalName
    foreach ($Mailbox_UPN in $Mailbox) {
        Set-Mailbox -Identity $Mailbox_UPN -HiddenFromAddressListsEnabled $false
        Write-Host "$Mailbox_UPN is no longer hidden from global address list" -ForegroundColor Green
    }
    Write-Host "Updating Mailbox Index..." -ForegroundColor Green
    $script:Mailbox = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.IsMailboxEnabled -eq $True } | Select-Object name, UserPrincipalName, HiddenFromAddressListsEnabled, IsDirSynced
}

<#============================= Added Mailbox functions above here =====================================#>

# Creates new named distribution group and gives option to add members
function New-365_DistributionGroup {
    $Name = Read-Host -Prompt "Enter email Distribution Group name" 
    New-DistributionGroup -Name $Name -Confirm
    $Confirmation = Read-Host "Add Members to $Name[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Add Members to $Name[y/n]" 
    }
    if ($confirmation -eq "y") {
        $Members = ($Mailbox | Out-GridView -Title "Select Users to give FullAccess to $Mailbox" -PassThru).UserPrincipalName 
        foreach ($Member in $Members) {
            Add-DistributionGroupMember -Identity $Name -User $Member -Confirm:$True 
        }
    }
    Write-Host "Updating User Index..." -ForegroundColor Green
    $script:DL = Get-DistributionGroup
}
# List members from selected distribution group with option to export to .csv
function Get-365_DistributionGroupMembers {
    $DL = ($DL | Out-GridView -Title 'Select Distribution Group' -PassThru).PrimarySmtpAddress
    Get-DistributionGroupMember -Identity $DL | Select-Object Name, PrimarySmtpAddress, Office, Department
    Start-Sleep -Milliseconds 1
    $Confirmation = Read-Host "Export $DL user list to CSV?[y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Export $DL user list to CSV?[y/n]"
    }
    if ($confirmation -eq "y") {
        $DLFileName = $DL.Substring(0, $DL.IndexOf('@'))
        Get-DistributionGroupMember -Identity $DL | Select-Object Name, PrimarySmtpAddress, Office, Department | Export-Csv -Path "$env:USERPROFILE\desktop\$DLFileName.csv"
    }
}
# Added new members to selected distribution group 
function Add-365_DistributionGroupMember {
    $DL = ($DL | Out-GridView -Title 'Select Distribution Group' -PassThru).PrimarySmtpAddress
    $Members = ($Members | Out-GridView -Title 'Select Member' -PassThru).UserPrincipalName
    foreach ($Member in $Members) {
        Add-DistributionGroupMember -Identity $DL.Name -Member $Member -Confirm:$true
    }
    Write-Host "Updating User Index..." -ForegroundColor Green
    $script:DL = Get-DistributionGroup
}
# Removes members from selected distribution group 
function Remove-365_DistributionGroupMember {
    $DL = ($DL | Out-GridView -Title 'Select Distribution Group' -PassThru).PrimarySmtpAddress
    $Members = (Get-DistributionGroupMember -Identity $DL | Out-GridView -Title 'Select Distribution Group' -PassThru).name 
    foreach ($Member in $Members) {
        Remove-DistributionGroupMember -Identity $DL -Member $Member -Confirm:$true
    }
    Write-Host "Updating User Index..." -ForegroundColor Green
    $script:DL = Get-DistributionGroup
}
# Exports all distribution groups menmbers to .CSV for each distribution group
function Export-365_AllDistributionGroupAndMembers { 
    $DL = $DL.primarysmtpaddress
    New-Item -ItemType Directory -Path "$env:USERPROFILE\desktop\ALL_DL_$FolderName"
    foreach ($list in $DL) {
        $DLFileName = $list.Substring(0, $list.IndexOf('@'))
        Get-DistributionGroupMember -Identity $list | Select-Object Name, PrimarySmtpAddress, Office, Department | Export-Csv -Path "$env:USERPROFILE\desktop\ALL_DL_$FolderName\$DLFileName.csv"
        Write-Host "Exporting $list to $env:USERPROFILE\desktop\ALL_DL_$FolderName" -ForegroundColor Green
    }
}

# Sets HiddenFromAddressListsEnabled to true for each selected distribution group (Not DirSynced)
function Set-365_DistributionGroupToHidden {
    $DL = ($DL | Where-Object { $_.HiddenFromAddressListsEnabled -eq $false } | Where-Object { $_.IsDirSynced -eq $false } | Out-GridView -Title "Select Distribution Group(s) - you can shift/ctrl click multiple Group(s)" -PassThru).PrimarySmtpAddress
    foreach ($list in $DL) {
        Set-DistributionGroup -Identity $list -HiddenFromAddressListsEnabled $true 
        Write-Host "$list is now hidden from global address list" -ForegroundColor Green
    }
    Write-Host "Updating Distribution Groups Index..." -ForegroundColor Green
    $script:DL = Get-DistributionGroup
}

# removes HiddenFromAddressListsEnabled from selected distribution groups (Not DirSynced)
function Set-365_DistributionGroupToNotHidden {
    $DL = ($DL | Where-Object { $_.HiddenFromAddressListsEnabled -eq $true } | Where-Object { $_.IsDirSynced -eq $false } | Out-GridView -Title "Select Distribution Group(s) - you can shift/ctrl click multiple Group(s)" -PassThru).PrimarySmtpAddress
    foreach ($list in $DL) {
        Set-DistributionGroup -Identity $list -HiddenFromAddressListsEnabled $false
        Write-Host "$list is no longer hidden from global address list" -ForegroundColor Green
    }
    Write-Host "Updating Distribution Groups Index..." -ForegroundColor Green
    $script:DL = Get-DistributionGroup
}

<#============================= Added Distribution Group  functions above here =====================================#>

if (-not (Get-InstalledModule -Name "MSonline")) {
    try {
        Install-Module -Name "msonline" -Force -AllowClobber -ErrorAction Stop
    }
    catch {
        Write-Warning "Fail to install to msonline module - run this with script with administator rights and make sure there is a internet connention" 
    }
}

# Check for profiles then connect to 365 tenant
if ((Get-ChildItem $env:USERPROFILE\AppData\Roaming\365Connect\365Profiles).Exists) {
    Connect-365_Profile
}

# if no profiles exists then prompt to create new profile and then connect or bypass and connect with credentials
else {
    Write-Warning "There are no Company Profiles."
    $Confirmation = Read-Host "Create new Company Profile? [y/n]"
    while ($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Break } 
        $confirmation = Read-Host "Create new Company Profile? [y/n]" 
    }
    if ($confirmation -eq "y") {        
        New-365_Profile
        Connect-365_Profile
    }
    Else { 
        Connect-365_Tenant
    }
}
'@

New-Item -Path $Script_Path -ItemType File -Value $Script_Body -Force

$Icon_URL = "https://icon-icons.com/descargaimagen.php?id=61639&root=699/ICO/512/&file=office365_icon-icons.com_61639.ico"
$Icon_Path = "$env:USERPROFILE\AppData\Roaming\365Connect\365Icon.ico"
(New-Object Net.WebClient).DownloadFile($Icon_URL, $Icon_Path) 

#Create a Shortcuts
$TargetFile = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
$ShortcutFile = "$env:USERPROFILE\Desktop\365_Shell.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.Arguments = "-noexit -ExecutionPolicy Bypass -File $env:USERPROFILE\AppData\Roaming\365Connect\Connect365.ps1"
$Shortcut.TargetPath = $TargetFile
$Shortcut.IconLocation = $Icon_Path
$Shortcut.Save()

$bytes = [System.IO.File]::ReadAllBytes($ShortcutFile)
$bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
[System.IO.File]::WriteAllBytes($ShortcutFile, $bytes)

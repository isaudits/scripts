#Thjs code is no longer maintained as the new report uses the AzureAD Module

$CompanyLogo = "http://thelazyadministrator.com/wp-content/uploads/2018/06/logo-2-e1529684959389.png"
$RightLogo = "http://thelazyadministrator.com/wp-content/uploads/2018/06/amd.png"
$ReportSavePath = "C:\Automation\"


$credential = Get-Credential -Message "Please enter your Office 365 credentials"
Import-Module MsOnline
Connect-MsolService -Credential $credential
$exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://outlook.office365.com/powershell-liveid/" -Credential $credential -Authentication "Basic" -AllowRedirection
Import-PSSession $exchangeSession -AllowClobber

$Table = @()
$LicenseTable = @()
$UserTable = @()
$SharedMailboxTable = @()
$GroupTypetable = @()
$IsLicensedUsersTable = @()
$ContactTable = @()
$MailUser = @()
$ContactMailUserTable = @()
$RoomTable = @()
$EquipTable = @()
$GlobalAdminTable = @()
$StrongPasswordTable = @()
$CompanyInfoTable = @()
$MessageTraceTable = @()
$DomainTable = @()

$Sku = @{
	"O365_BUSINESS_ESSENTIALS"			   = "Office 365 Business Essentials"
	"O365_BUSINESS_PREMIUM"			       = "Office 365 Business Premium"
	"DESKLESSPACK"						   = "Office 365 (Plan K1)"
	"DESKLESSWOFFPACK"					   = "Office 365 (Plan K2)"
	"LITEPACK"							   = "Office 365 (Plan P1)"
	"EXCHANGESTANDARD"					   = "Office 365 Exchange Online Only"
	"STANDARDPACK"						   = "Enterprise Plan E1"
	"STANDARDWOFFPACK"					   = "Office 365 (Plan E2)"
	"ENTERPRISEPACK"					   = "Enterprise Plan E3"
	"ENTERPRISEPACKLRG"				       = "Enterprise Plan E3"
	"ENTERPRISEWITHSCAL"				   = "Enterprise Plan E4"
	"STANDARDPACK_STUDENT"				   = "Office 365 (Plan A1) for Students"
	"STANDARDWOFFPACKPACK_STUDENT"		   = "Office 365 (Plan A2) for Students"
	"ENTERPRISEPACK_STUDENT"			   = "Office 365 (Plan A3) for Students"
	"ENTERPRISEWITHSCAL_STUDENT"		   = "Office 365 (Plan A4) for Students"
	"STANDARDPACK_FACULTY"				   = "Office 365 (Plan A1) for Faculty"
	"STANDARDWOFFPACKPACK_FACULTY"		   = "Office 365 (Plan A2) for Faculty"
	"ENTERPRISEPACK_FACULTY"			   = "Office 365 (Plan A3) for Faculty"
	"ENTERPRISEWITHSCAL_FACULTY"		   = "Office 365 (Plan A4) for Faculty"
	"ENTERPRISEPACK_B_PILOT"			   = "Office 365 (Enterprise Preview)"
	"STANDARD_B_PILOT"					   = "Office 365 (Small Business Preview)"
	"VISIOCLIENT"						   = "Visio Pro Online"
	"POWER_BI_ADDON"					   = "Office 365 Power BI Addon"
	"POWER_BI_INDIVIDUAL_USE"			   = "Power BI Individual User"
	"POWER_BI_STANDALONE"				   = "Power BI Stand Alone"
	"POWER_BI_STANDARD"				       = "Power-BI Standard"
	"PROJECTESSENTIALS"				       = "Project Lite"
	"PROJECTCLIENT"					       = "Project Professional"
	"PROJECTONLINE_PLAN_1"				   = "Project Online"
	"PROJECTONLINE_PLAN_2"				   = "Project Online and PRO"
	"ProjectPremium"					   = "Project Online Premium"
	"ECAL_SERVICES"					       = "ECAL"
	"EMS"								   = "Enterprise Mobility Suite"
	"RIGHTSMANAGEMENT_ADHOC"			   = "Windows Azure Rights Management"
	"MCOMEETADV"						   = "PSTN conferencing"
	"SHAREPOINTSTORAGE"				       = "SharePoint storage"
	"PLANNERSTANDALONE"				       = "Planner Standalone"
	"CRMIUR"							   = "CMRIUR"
	"BI_AZURE_P1"						   = "Power BI Reporting and Analytics"
	"INTUNE_A"							   = "Windows Intune Plan A"
	"PROJECTWORKMANAGEMENT"			       = "Office 365 Planner Preview"
	"ATP_ENTERPRISE"					   = "Exchange Online Advanced Threat Protection"
	"EQUIVIO_ANALYTICS"				       = "Office 365 Advanced eDiscovery"
	"AAD_BASIC"						       = "Azure Active Directory Basic"
	"RMS_S_ENTERPRISE"					   = "Azure Active Directory Rights Management"
	"AAD_PREMIUM"						   = "Azure Active Directory Premium"
	"MFA_PREMIUM"						   = "Azure Multi-Factor Authentication"
	"STANDARDPACK_GOV"					   = "Microsoft Office 365 (Plan G1) for Government"
	"STANDARDWOFFPACK_GOV"				   = "Microsoft Office 365 (Plan G2) for Government"
	"ENTERPRISEPACK_GOV"				   = "Microsoft Office 365 (Plan G3) for Government"
	"ENTERPRISEWITHSCAL_GOV"			   = "Microsoft Office 365 (Plan G4) for Government"
	"DESKLESSPACK_GOV"					   = "Microsoft Office 365 (Plan K1) for Government"
	"ESKLESSWOFFPACK_GOV"				   = "Microsoft Office 365 (Plan K2) for Government"
	"EXCHANGESTANDARD_GOV"				   = "Microsoft Office 365 Exchange Online (Plan 1) only for Government"
	"EXCHANGEENTERPRISE_GOV"			   = "Microsoft Office 365 Exchange Online (Plan 2) only for Government"
	"SHAREPOINTDESKLESS_GOV"			   = "SharePoint Online Kiosk"
	"EXCHANGE_S_DESKLESS_GOV"			   = "Exchange Kiosk"
	"RMS_S_ENTERPRISE_GOV"				   = "Windows Azure Active Directory Rights Management"
	"OFFICESUBSCRIPTION_GOV"			   = "Office ProPlus"
	"MCOSTANDARD_GOV"					   = "Lync Plan 2G"
	"SHAREPOINTWAC_GOV"				       = "Office Online for Government"
	"SHAREPOINTENTERPRISE_GOV"			   = "SharePoint Plan 2G"
	"EXCHANGE_S_ENTERPRISE_GOV"		       = "Exchange Plan 2G"
	"EXCHANGE_S_ARCHIVE_ADDON_GOV"		   = "Exchange Online Archiving"
	"EXCHANGE_S_DESKLESS"				   = "Exchange Online Kiosk"
	"SHAREPOINTDESKLESS"				   = "SharePoint Online Kiosk"
	"SHAREPOINTWAC"					       = "Office Online"
	"YAMMER_ENTERPRISE"				       = "Yammer for the Starship Enterprise"
	"EXCHANGE_L_STANDARD"				   = "Exchange Online (Plan 1)"
	"MCOLITE"							   = "Lync Online (Plan 1)"
	"SHAREPOINTLITE"					   = "SharePoint Online (Plan 1)"
	"OFFICE_PRO_PLUS_SUBSCRIPTION_SMBIZ"   = "Office ProPlus"
	"EXCHANGE_S_STANDARD_MIDMARKET"	       = "Exchange Online (Plan 1)"
	"MCOSTANDARD_MIDMARKET"			       = "Lync Online (Plan 1)"
	"SHAREPOINTENTERPRISE_MIDMARKET"	   = "SharePoint Online (Plan 1)"
	"OFFICESUBSCRIPTION"				   = "Office ProPlus"
	"YAMMER_MIDSIZE"					   = "Yammer"
	"DYN365_ENTERPRISE_PLAN1"			   = "Dynamics 365 Customer Engagement Plan Enterprise Edition"
	"ENTERPRISEPREMIUM_NOPSTNCONF"		   = "Enterprise E5 (without Audio Conferencing)"
	"ENTERPRISEPREMIUM"				       = "Enterprise E5 (with Audio Conferencing)"
	"MCOSTANDARD"						   = "Skype for Business Online Standalone Plan 2"
	"PROJECT_MADEIRA_PREVIEW_IW_SKU"	   = "Dynamics 365 for Financials for IWs"
	"STANDARDWOFFPACK_IW_STUDENT"		   = "Office 365 Education for Students"
	"STANDARDWOFFPACK_IW_FACULTY"		   = "Office 365 Education for Faculty"
	"EOP_ENTERPRISE_FACULTY"			   = "Exchange Online Protection for Faculty"
	"EXCHANGESTANDARD_STUDENT"			   = "Exchange Online (Plan 1) for Students"
	"OFFICESUBSCRIPTION_STUDENT"		   = "Office ProPlus Student Benefit"
	"STANDARDWOFFPACK_FACULTY"			   = "Office 365 Education E1 for Faculty"
	"STANDARDWOFFPACK_STUDENT"			   = "Microsoft Office 365 (Plan A2) for Students"
	"DYN365_FINANCIALS_BUSINESS_SKU"	   = "Dynamics 365 for Financials Business Edition"
	"DYN365_FINANCIALS_TEAM_MEMBERS_SKU"   = "Dynamics 365 for Team Members Business Edition"
	"FLOW_FREE"						       = "Microsoft Flow Free"
	"POWER_BI_PRO"						   = "Power BI Pro"
	"O365_BUSINESS"					       = "Office 365 Business"
	"DYN365_ENTERPRISE_SALES"			   = "Dynamics Office 365 Enterprise Sales"
	"RIGHTSMANAGEMENT"					   = "Rights Management"
	"PROJECTPROFESSIONAL"				   = "Project Professional"
	"VISIOONLINE_PLAN1"				       = "Visio Online Plan 1"
	"EXCHANGEENTERPRISE"				   = "Exchange Online Plan 2"
	"DYN365_ENTERPRISE_P1_IW"			   = "Dynamics 365 P1 Trial for Information Workers"
	"DYN365_ENTERPRISE_TEAM_MEMBERS"	   = "Dynamics 365 For Team Members Enterprise Edition"
	"CRMSTANDARD"						   = "Microsoft Dynamics CRM Online Professional"
	"EXCHANGEARCHIVE_ADDON"			       = "Exchange Online Archiving For Exchange Online"
	"EXCHANGEDESKLESS"					   = "Exchange Online Kiosk"
	"SPZA_IW"							   = "App Connect"
	"WINDOWS_STORE"					       = "Windows Store for Business"
	"MCOEV"							       = "Microsoft Phone System"
	"VIDEO_INTEROP"					       = "Polycom Skype Meeting Video Interop for Skype for Business"
	"SPE_E5"							   = "Microsoft 365 E5"
	"SPE_E3"							   = "Microsoft 365 E3"
	"ATA"								   = "Advanced Threat Analytics"
	"MCOPSTN2"							   = "Domestic and International Calling Plan"
	"FLOW_P1"							   = "Microsoft Flow Plan 1"
	"FLOW_P2"							   = "Microsoft Flow Plan 2"
}

#Company Information
$CompanyInfo = Get-MsolCompanyInformation

    $CompanyName = $CompanyInfo.DisplayName
	$TechEmail = $CompanyInfo.TechnicalNotificationEmails | Out-String
    $SelfServePassword = $CompanyInfo.SelfServePasswordResetEnabled
    $DirSync = $CompanyInfo.DirectorySynchronizationEnabled
    $PasswordSync = $CompanyInfo.PasswordSynchronizationEnabled
    $LastDirSync = $CompanyInfo.LastDirSyncTime
    $LastPasswordSync = $CompanyInfo.LastPasswordSyncTime
    If ($DirSync -eq $False)
    {
        $LastDirSync = "Not Available"
    }
    If ($PasswordSync -eq $False)
    {
        $LastPasswordSync = "Not Available"
    }
	
	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name Name -Value $CompanyName
	$obj | Add-Member -MemberType NoteProperty -Name "Techcnical Email" -Value $TechEmail 
	$obj | Add-Member -MemberType NoteProperty -Name "Self Service Password Reset" -value $SelfServePassword
    $obj | Add-Member -MemberType NoteProperty -Name "Directory Sync" -value $DirSync
    $obj | Add-Member -MemberType NoteProperty -Name "Password Sync" -value $PasswordSync
    $obj | Add-Member -MemberType NoteProperty -Name "Last Directory Sync" -value $LastDirSync
    $obj | Add-Member -MemberType NoteProperty -Name "Last Password Sync" -value $LastPasswordSync
	
	$CompanyInfoTable += $obj

#Get Tenant Global Admins
$role = Get-MsolRole -RoleName "Company Administrator"
$Admins = Get-MsolRoleMember -RoleObjectId $role.ObjectId
Foreach ($Admin in $Admins)
{
    $Name = $Admin.DisplayName
	$Licensed = $Admin.IsLicensed
    $EmailAddress = $Admin.EmailAddress
	
	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name Name -Value $Name
	$obj | Add-Member -MemberType NoteProperty -Name "Is Licensed" -value $Licensed
    $obj | Add-Member -MemberType NoteProperty -Name "E-Mail Address" -value $EmailAddress
	
	$GlobalAdminTable += $obj
}


#Users with Strong Password Requirements disabled
$LooseUsers = Get-Msoluser | Where-Object {$_.StrongPasswordRequired -eq $False}
Foreach ($LooseUser in $LooseUsers)
{
    $NameLoose = $LooseUser.DisplayName
	$UPNLoose = $LooseUser.UserPrincipalName
	$LicensedLoose = $LooseUser.IsLicensed
    $StrongPasswordLoose = $LooseUser.StrongPasswordRequired
	
	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name Name -Value $NameLoose
	$obj | Add-Member -MemberType NoteProperty -Name UserPrincipalName -Value $UPNLoose
	$obj | Add-Member -MemberType NoteProperty -Name "Is Licensed" -value $LicensedLoose
    $obj | Add-Member -MemberType NoteProperty -Name "Strong Password Required" -value $StrongPasswordLoose
	
	$StrongPasswordTable += $obj
}

#Message Trace / Recent Messages
$RecentMessages = Get-MessageTrace
Foreach ($RecentMessage in $RecentMessages)
{
    $TraceDate = $RecentMessage.Received
	$Sender = $RecentMessage.SenderAddress
	$Recipient = $RecentMessage.RecipientAddress
    $Subject = $RecentMessage.Subject
    $Status = $RecentMessage.Status
	
	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name "Received Date" -Value $TraceDate
    $obj | Add-Member -MemberType NoteProperty -Name "E-Mail Subject" -Value $Subject
	$obj | Add-Member -MemberType NoteProperty -Name "Sender" -Value $Sender
	$obj | Add-Member -MemberType NoteProperty -Name "Recipient" -value $Recipient
    $obj | Add-Member -MemberType NoteProperty -Name "Status" -value $Status
	
	$MessageTraceTable += $obj
}

#Tenant Domain
$Domains = Get-MSOLDomain
foreach ($Domain in $Domains)
{
    $DomainName = $Domain.Name
	$Verified = $Domain.Status
	$DefaultStatus = $Domain.IsDefault

	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name "Domain Name" -Value $DomainName
    $obj | Add-Member -MemberType NoteProperty -Name "Verification Status" -Value $Verified
	$obj | Add-Member -MemberType NoteProperty -Name "Default" -Value $DefaultStatus

	
	$DomainTable += $obj
}


#Get groups and sort in alphabetical order
$Groups = Get-Msolgroup -All | Sort-Object DisplayName
$DistroCount = ($Groups | Where-Object { $_.GroupType -eq "DistributionList" }).Count
$obj1 = New-Object -TypeName PSObject
$obj1 | Add-Member -MemberType NoteProperty -Name Name -Value "Distribution Group"
$obj1 | Add-Member -MemberType NoteProperty -Name Count -Value $DistroCount

$GroupTypetable += $obj1

$SecurityCount = ($Groups | Where-Object { $_.GroupType -eq "Security" }).Count
$obj1 = New-Object -TypeName PSObject
$obj1 | Add-Member -MemberType NoteProperty -Name Name -Value "Security Group"
$obj1 | Add-Member -MemberType NoteProperty -Name Count -Value $SecurityCount

$GroupTypetable += $obj1

$SecurityMailEnabledCount = ($Groups | Where-Object { $_.GroupType -eq "MailEnabledSecurity" }).Count
$obj1 = New-Object -TypeName PSObject
$obj1 | Add-Member -MemberType NoteProperty -Name Name -Value "Mail Enabled Security Group"
$obj1 | Add-Member -MemberType NoteProperty -Name Count -Value $SecurityMailEnabledCount

$GroupTypetable += $obj1

Foreach ($Group in $Groups)
{
	$Users = (Get-MSOLGroupMember -GroupObjectId $Group.ObjectID | Sort-Object DisplayName | Select-Object -ExpandProperty DisplayName) -join ", "
	$GName = $Group.DisplayName
	$Type = $Group.GroupType
	$hash = New-Object PSObject -property @{ Name = "$GName"; Type = "$Type"; Members = "$Members" }
	$GEmail = $Group.EmailAddress
	
	
	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name Name -Value $GName
	$obj | Add-Member -MemberType NoteProperty -Name Type -Value $Type
	$obj | Add-Member -MemberType NoteProperty -Name Members -value $users
	$obj | Add-Member -MemberType NoteProperty -Name "E-mail Address" -value $GEmail
	
	$table += $obj
}

#Get all licenses
$Licenses = Get-MsolAccountSku
#Split licenses at colon
Foreach ($License in $Licenses)
{
	$Objs = ($License).AccountSkuId
	$ASku = $Objs -split ":" | Select-Object -Last 1
	$TextLic = $Sku.Item("$ASku")
	If (!($TextLic))
	{
		$OLicense = $License.AccountSkuId
	}
	Else
	{
		$OLicense = $TextLic
	}
	
	$TotalAmount = $License.Activeunits
	$Assigned = $License.ConsumedUnits
	$Unassigned = ($TotalAmount - $Assigned)
	If ($TotalAmount -lt 1000)
	{
		
		$obj = New-Object -TypeName PSObject
		$obj | Add-Member -MemberType NoteProperty -Name Name -Value $Olicense
		$obj | Add-Member -MemberType NoteProperty -Name "Total Amount" -Value $TotalAmount
		$obj | Add-Member -MemberType NoteProperty -Name "Assigned Licenses" -value $Assigned
		$obj | Add-Member -MemberType NoteProperty -Name "Unassigned Licenses" -value $Unassigned
		
		$licensetable += $obj
	}
}

#Get all users
$Users = Get-MsolUser -All
#$user = get-msoluser | Where-Object {$_.DisplayName -like "*Brad Wyatt*"}

$IsLicensed = (Get-MSOLUser | Where-Object { $_.IsLicensed -eq $True }).Count
$objULic = New-Object -TypeName PSObject
$objULic | Add-Member -MemberType NoteProperty -Name Name -Value "Users Licensed"
$objULic | Add-Member -MemberType NoteProperty -Name Count -Value $IsLicensed

$IsLicensedUsersTable += $objULic

$ISNotLicensed = (Get-MSOLUser | Where-Object { $_.IsLicensed -eq $False }).Count
$objULic = New-Object -TypeName PSObject
$objULic | Add-Member -MemberType NoteProperty -Name Name -Value "Users Not Licensed"
$objULic | Add-Member -MemberType NoteProperty -Name Count -Value $IsNotLicensed

$IsLicensedUsersTable += $objULic


Foreach ($User in $Users)
{
	$ProxyA = @()
	$NewObject02 = @()
	$NewObject01 = @()
	$UserLicenses = ($User | Select-Object -ExpandProperty Licenses).AccountSkuId
	If (($UserLicenses).count -gt 1)
	{
		Foreach ($UserLicense in $UserLicenses)
		{
			$lic = $UserLicense -split ":" | Select-Object -Last 1
			$TextLic = $Sku.Item("$lic")
			If (!($TextLic))
			{
				$NewObject01 = New-Object PSObject
				$NewObject01 | Add-Member -MemberType NoteProperty -Name "Licenses" -Value $lic
				$NewObject02 += $NewObject01
			}
			Else
			{
				$NewObject01 = New-Object PSObject
				$NewObject01 | Add-Member -MemberType NoteProperty -Name "Licenses" -Value $textlic
				$NewObject02 += $NewObject01
			}
			
		}
	}
	Else
	{
		$lic = $UserLicenses -split ":" | Select-Object -Last 1
		$TextLic = $Sku.Item("$lic")
		If (!($TextLic))
		{
			$NewObject01 = New-Object PSObject
			$NewObject01 | Add-Member -MemberType NoteProperty -Name "Licenses" -Value $lic
			$NewObject02 += $NewObject01
		}
		Else
		{
			$NewObject01 = New-Object PSObject
			$NewObject01 | Add-Member -MemberType NoteProperty -Name "Licenses" -Value $textlic
			$NewObject02 += $NewObject01
		}
	}
	
	$ProxyAddresses = ($User | Select-Object -ExpandProperty ProxyAddresses)
	If ($ProxyAddresses -ne $Null)
	{
		Foreach ($Proxy in $ProxyAddresses)
		{
			$ProxyB = $Proxy -split ":" | Select-Object -Last 1
			$ProxyA += $ProxyB
			$ProxyC = $ProxyA -join ", "
		}
	}
	Else
	{
		$ProxyC = $Null
	}
	
	$Name = $User.DisplayName
	$UPN = $User.UserPrincipalName
	$Licenses = ($NewObject02 | Select-Object -ExpandProperty Licenses) -join ", "
    $Disabled = $User.BlockCredential
    $LastLogonUser = (Get-Mailbox -Identity $User.DisplayName -ErrorAction SilentlyContinue | Get-MailboxStatistics -ErrorAction SilentlyContinue).LastLogonTime


	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name Name -Value $Name
	$obj | Add-Member -MemberType NoteProperty -Name UserPrincipalName -Value $UPN
	$obj | Add-Member -MemberType NoteProperty -Name Licenses -value $Licenses
    $obj | Add-Member -MemberType NoteProperty -Name "Last Logon" -value $LastLogonUser
    $obj | Add-Member -MemberType NoteProperty -Name Disabled -value $Disabled
	$obj | Add-Member -MemberType NoteProperty -Name "E-mail Addresses" -value $ProxyC
	
	$usertable += $obj
}

#Get all Shared Mailboxes
$SharedMailboxes = Get-Recipient -Resultsize unlimited | Where-Object { $_.RecipientTypeDetails -eq "SharedMailbox" } 
Foreach ($SharedMailbox in $SharedMailboxes)
{
	$ProxyA = @()
	$Name = $SharedMailbox.Name
	$PrimEmail = $SharedMailbox.PrimarySmtpAddress
	$ProxyAddresses = ($SharedMailbox | Where-Object { $_.EmailAddresses -notlike "*$PrimEmail*" } | Select-Object -ExpandProperty EmailAddresses)
	If ($ProxyAddresses -ne $Null)
	{
		Foreach ($ProxyAddress in $ProxyAddresses)
		{
			$ProxyB = $ProxyAddress -split ":" | Select-Object -Last 1
			If ($ProxyB -eq $PrimEmail)
			{
				$ProxyB = $Null
			}
			$ProxyA += $ProxyB
			$ProxyC = $ProxyA
		}
	}
	Else
	{
		$ProxyC = $Null
	}
	
	$ProxyF = ($ProxyC -join ", ").TrimEnd(", ")
	
	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name Name -Value $Name
	$obj | Add-Member -MemberType NoteProperty -Name "Primary E-Mail" -Value $PrimEmail
	$obj | Add-Member -MemberType NoteProperty -Name "E-mail Addresses" -value $ProxyF
	
	$SharedMailboxTable += $obj
	
}

#Get all Contacts
$Contacts = Get-MailContact
#Split licenses at colon
Foreach ($Contact in $Contacts)
{
	
	$ContactName = $Contact.DisplayName
	$ContactPrimEmail = $Contact.PrimarySmtpAddress
	
	
	$objContact = New-Object -TypeName PSObject
	$objContact | Add-Member -MemberType NoteProperty -Name Name -Value $ContactName
	$objContact | Add-Member -MemberType NoteProperty -Name "E-mail Address" -Value $ContactPrimEmail
	
	$ContactTable += $objContact
	
}

#Get all Mail Users
$MailUsers = Get-MailUser
foreach ($MailUser in $mailUsers)
{
	$MailArray = @()
	$MailPrimEmail = $MailUser.PrimarySmtpAddress
	$MailName = $MailUser.DisplayName
	$MailEmailAddresses = ($MailUser.EmailAddresses | Where-Object { $_ -cnotmatch '^SMTP' })
	foreach ($MailEmailAddress in $MailEmailAddresses)
	{
		$MailEmailAddressSplit = $MailEmailAddress -split ":" | Select-Object -Last 1
		$MailArray += $MailEmailAddressSplit
		
		
	}
	
	$UserEmails = $MailArray -join ", "
	
	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name Name -Value $MailName
	$obj | Add-Member -MemberType NoteProperty -Name "Primary E-Mail" -Value $MailPrimEmail
	$obj | Add-Member -MemberType NoteProperty -Name "E-mail Addresses" -value $UserEmails
	
	$ContactMailUserTable += $obj
}

$Rooms = Get-Mailbox -Filter '(RecipientTypeDetails -eq "RoomMailBox")'
Foreach ($Room in $Rooms)
{
    $RoomArray = @()

    $RoomName = $Room.DisplayName
    $RoomPrimEmail = $Room.PrimarySmtpAddress
    $RoomEmails = ($Room.EmailAddresses | Where-Object { $_ -cnotmatch '^SMTP' })
    foreach ($RoomEmail in $RoomEmails)
        {
            $RoomEmailSplit = $RoomEmail -split ":" | Select-Object -Last 1
            $RoomArray += $RoomEmailSplit
        }
    $RoomEMailsF = $RoomArray -join ", "

    $obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name Name -Value $RoomName
	$obj | Add-Member -MemberType NoteProperty -Name "Primary E-Mail" -Value $RoomPrimEmail
	$obj | Add-Member -MemberType NoteProperty -Name "E-mail Addresses" -value $RoomEmailsF
	
	$RoomTable += $obj
}

$EquipMailboxes = Get-Mailbox -Filter '(RecipientTypeDetails -eq "EquipmentMailBox")'
Foreach ($EquipMailbox in $EquipMailboxes)
{
    $EquipArray = @()

    $EquipName = $EquipMailbox.DisplayName
    $EquipPrimEmail = $EquipMailbox.PrimarySmtpAddress
    $EquipEmails = ($EquipMailbox.EmailAddresses | Where-Object { $_ -cnotmatch '^SMTP' })
    foreach ($EquipEmail in $EquipEmails)
        {
            $EquipEmailSplit = $EquipEmail -split ":" | Select-Object -Last 1
            $EquipArray += $EquipEmailSplit
        }
    $EquipEMailsF = $EquipArray -join ", "

    $obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name Name -Value $EquipName
	$obj | Add-Member -MemberType NoteProperty -Name "Primary E-Mail" -Value $EquipPrimEmail
	$obj | Add-Member -MemberType NoteProperty -Name "E-mail Addresses" -value $EquipEmailsF
	
	$EquipTable += $obj
}


$tabarray = @('Dashboard','Groups', 'Licenses', 'Users', 'Shared Mailboxes', 'Contacts', 'Resources')

#basic Properties 
$PieObject2 = Get-HTMLPieChartObject
$PieObject2.Title = "Office 365 Total Licenses"
$PieObject2.Size.Height = 250
$PieObject2.Size.width = 250
$PieObject2.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObject2.ChartStyle.ColorSchemeName = "ColorScheme4"
#There are 8 generated schemes, randomly generated at runtime 
$PieObject2.ChartStyle.ColorSchemeName = "Generated7"
#you can also ask for a random scheme.  Which also happens if you have too many records for the scheme
$PieObject2.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObject2.DataDefinition.DataNameColumnName = 'Name'
$PieObject2.DataDefinition.DataValueColumnName = 'Total Amount'

#basic Properties 
$PieObject3 = Get-HTMLPieChartObject
$PieObject3.Title = "Office 365 Assigned Licenses"
$PieObject3.Size.Height = 250
$PieObject3.Size.width = 250
$PieObject3.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObject3.ChartStyle.ColorSchemeName = "ColorScheme4"
#There are 8 generated schemes, randomly generated at runtime 
$PieObject3.ChartStyle.ColorSchemeName = "Generated5"
#you can also ask for a random scheme.  Which also happens if you have too many records for the scheme
$PieObject3.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObject3.DataDefinition.DataNameColumnName = 'Name'
$PieObject3.DataDefinition.DataValueColumnName = 'Assigned Licenses'

#basic Properties 
$PieObject4 = Get-HTMLPieChartObject
$PieObject4.Title = "Office 365 Unassigned Licenses"
$PieObject4.Size.Height = 250
$PieObject4.Size.width = 250
$PieObject4.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObject4.ChartStyle.ColorSchemeName = "ColorScheme4"
#There are 8 generated schemes, randomly generated at runtime 
$PieObject4.ChartStyle.ColorSchemeName = "Generated4"
#you can also ask for a random scheme.  Which also happens if you have too many records for the scheme
$PieObject4.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObject4.DataDefinition.DataNameColumnName = 'Name'
$PieObject4.DataDefinition.DataValueColumnName = 'Unassigned Licenses'

#basic Properties 
$PieObjectGroupType = Get-HTMLPieChartObject
$PieObjectGroupType.Title = "Office 365 Groups"
$PieObjectGroupType.Size.Height = 250
$PieObjectGroupType.Size.width = 250
$PieObjectGroupType.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObjectGroupType.ChartStyle.ColorSchemeName = "ColorScheme4"
#There are 8 generated schemes, randomly generated at runtime 
$PieObjectGroupType.ChartStyle.ColorSchemeName = "Generated8"
#you can also ask for a random scheme.  Which also happens if you have too many records for the scheme
$PieObjectGroupType.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectGroupType.DataDefinition.DataNameColumnName = 'Name'
$PieObjectGroupType.DataDefinition.DataValueColumnName = 'Count'

##--LICENSED AND UNLICENSED USERS PIE CHART--##
#basic Properties 
$PieObjectULicense = Get-HTMLPieChartObject
$PieObjectULicense.Title = "License Status"
$PieObjectULicense.Size.Height = 250
$PieObjectULicense.Size.width = 250
$PieObjectULicense.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObjectULicense.ChartStyle.ColorSchemeName = "ColorScheme3"
#There are 8 generated schemes, randomly generated at runtime 
$PieObjectULicense.ChartStyle.ColorSchemeName = "Generated3"
#you can also ask for a random scheme.  Which also happens if you have too many records for the scheme
$PieObjectULicense.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectULicense.DataDefinition.DataNameColumnName = 'Name'
$PieObjectULicense.DataDefinition.DataValueColumnName = 'Count'

$rpt = @()
$rpt += get-htmlopenpage -TitleText 'Office 365 Tenant Report' -LeftLogoString $CompanyLogo -RightLogoString $RightLogo 

$rpt += Get-HTMLTabHeader -TabNames $tabarray 
    $rpt += get-htmltabcontentopen -TabName $tabarray[0] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))
        $rpt+= Get-HtmlContentOpen -HeaderText "Office 365 Dashboard"
          $rpt += Get-HTMLContentOpen -HeaderText "Company Information"
            $rpt += Get-HtmlContentTable $CompanyInfoTable 
          $rpt += Get-HTMLContentClose

	        $rpt+= get-HtmlColumn1of2
		        $rpt+= Get-HtmlContentOpen -BackgroundShade 1 -HeaderText 'Global Administrators'
			        $rpt+= get-htmlcontentdatatable  $GlobalAdminTable -HideFooter
		        $rpt+= Get-HtmlContentClose
	        $rpt+= get-htmlColumnClose
	            $rpt+= get-htmlColumn2of2
		            $rpt+= Get-HtmlContentOpen -HeaderText 'Users With Strong Password Enforcement Disabled'
			            $rpt+= get-htmlcontentdatatable  $StrongPasswordTable -HideFooter
		        $rpt+= Get-HtmlContentClose
	        $rpt+= get-htmlColumnClose

          $rpt += Get-HTMLContentOpen -HeaderText "Recent E-Mails"
            $rpt += Get-HTMLContentDataTable $MessageTraceTable -HideFooter
          $rpt += Get-HTMLContentClose

          $rpt += Get-HTMLContentOpen -HeaderText "Domains"
            $rpt += Get-HtmlContentTable $DomainTable 
          $rpt += Get-HTMLContentClose

        $rpt+= Get-HtmlContentClose 
    $rpt += get-htmltabcontentclose

    $rpt += get-htmltabcontentopen -TabName $tabarray[1] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))
        $rpt += Get-HTMLContentOpen -HeaderText "Office 365 Groups"
            $rpt += get-htmlcontentdatatable $Table -HideFooter
        $rpt += Get-HTMLContentClose
        $rpt += Get-HTMLContentOpen -HeaderText "Office 365 Groups Chart"
		    $rpt += Get-HTMLPieChart -ChartObject $PieObjectGroupType -DataSet $GroupTypetable
	    $rpt += Get-HTMLContentClose
    $rpt += get-htmltabcontentclose
    $rpt += get-htmltabcontentopen -TabName $tabarray[2]  -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))
        $rpt += Get-HTMLContentOpen -HeaderText "Office 365 Licenses"
            $rpt += get-htmlcontentdatatable $LicenseTable -HideFooter
        $rpt += Get-HTMLContentClose
	$rpt += Get-HTMLContentOpen -HeaderText "Office 365 Licensing Charts"
	    $rpt += Get-HTMLColumnOpen -ColumnNumber 1 -ColumnCount 2
	        $rpt += Get-HTMLPieChart -ChartObject $PieObject2 -DataSet $licensetable
	    $rpt += Get-HTMLColumnClose
	    $rpt += Get-HTMLColumnOpen -ColumnNumber 2 -ColumnCount 2
	        $rpt += Get-HTMLPieChart -ChartObject $PieObject3 -DataSet $licensetable
	    $rpt += Get-HTMLColumnClose
    $rpt += Get-HTMLContentclose
    $rpt += get-htmltabcontentclose
    $rpt += get-htmltabcontentopen -TabName $tabarray[3] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))
        $rpt += Get-HTMLContentOpen -HeaderText "Office 365 Users"
            $rpt += get-htmlcontentdatatable $UserTable -HideFooter
        $rpt += Get-HTMLContentClose
        $rpt += Get-HTMLContentOpen -HeaderText "Licensed & Unlicensed Users Chart"
		    $rpt += Get-HTMLPieChart -ChartObject $PieObjectULicense -DataSet $IsLicensedUsersTable
	    $rpt += Get-HTMLContentClose
    $rpt += get-htmltabcontentclose
    $rpt += get-htmltabcontentopen -TabName $tabarray[4] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy)) 
        $rpt += Get-HTMLContentOpen -HeaderText "Office 365 Shared Mailboxes"
        $rpt += get-htmlcontentdatatable $SharedMailboxTable -HideFooter
        $rpt += Get-HTMLContentClose
    $rpt += get-htmltabcontentclose
        $rpt += get-htmltabcontentopen -TabName $tabarray[5] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy)) 
        $rpt += Get-HTMLContentOpen -HeaderText "Office 365 Contacts"
            $rpt += get-htmlcontentdatatable $ContactTable -HideFooter
        $rpt += Get-HTMLContentClose
        $rpt += Get-HTMLContentOpen -HeaderText "Office 365 Mail Users"
            $rpt += get-htmlcontentdatatable $ContactMailUserTable -HideFooter
        $rpt += Get-HTMLContentClose
    $rpt += get-htmltabcontentclose
    $rpt += get-htmltabcontentopen -TabName $tabarray[6] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy)) 
        $rpt += Get-HTMLContentOpen -HeaderText "Office 365 Room Mailboxes"
            $rpt += get-htmlcontentdatatable $RoomTable -HideFooter
        $rpt += Get-HTMLContentClose
        $rpt += Get-HTMLContentOpen -HeaderText "Office 365 Equipment Mailboxes"
            $rpt += get-htmlcontentdatatable $EquipTable -HideFooter
        $rpt += Get-HTMLContentClose
    $rpt += get-htmltabcontentclose

$rpt += Get-HTMLClosePage

$Day = (Get-Date).Day
$Month = (Get-Date).Month
$Year = (Get-Date).Year
$ReportName = ("$Day" + "-" + "$Month" + "-" + "$Year" + "-" + "O365 Tenant Report")
Save-HTMLReport -ReportContent $rpt -ShowReport -ReportName $ReportName -ReportPath $ReportSavePath
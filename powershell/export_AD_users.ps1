#Designed to export information in same format as DumpSec

Function OctetToHours ($Octet)
{
    # Function to convert Octet value (byte array) into binary string
    # representing the logonHours attribute. The 168 bits represent 24 hours
    # per day for 7 days, Sunday through Saturday. The logonHours attribute
    # in Active Directory is in UTC. This function converts into the local
    # time zone. If the bit is "1", the user is allowed to logon during
    # that hour. If the bit is "0", the user is not allowed to logon.
    
    if (!$octet) {return 'All'}
    
    # Loop through the 21 bytes in the array, each representing 8 hours.
    For ($j = 0; $j -le 20; $j = $j + 1)
    {
        # Check each of the 8 bits in each byte.
        For ($k = 7; $k -ge 0; $k = $k - 1)
        {
            # Adjust the index into an array of hours for the
            # local time zone bias.
            $m = 8*$j + $k - $Bias
            # The index into the  array of hours ranges from 0 to 167.
            If ($m -lt 0) {$m = $m + 168}
            # Check the bit of the byte and assign the corresponding
            # element of the array.
            If ($Octet[$j] -band [Math]::Pow(2, $k)) {$LH[$m] = "1"}
            Else {$LH[$m] = "0"}
        }
    }

    $arrDays = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")

    # Loop through the array of 168 hours.
    For ($j = 0; $j -le 167; $j = $j + 1)
    {
        $Hour = [string]($j % 24)

        If (($j % 24) -eq 0)
        {
            # First hour of a day.
            $Line = $arrDays[$j / 24] + "("
            If ($LH[$j] -eq 1) {$line = $Line + $Hour}
        }
        
        If (($LH[$j] -eq 1) -and ($LH[$j-1] -eq 0))
        {
            $Line = $Line+$Hour
        }

        If (($LH[$j] -eq 0) -and ($LH[$j-1] -eq 1))
        {
            $Line = $Line+"-"+$Hour+","
        }
        
        # If this is the last hour of the day, output.
        If ((($j + 1) % 24) -eq 0) 
        {
            If ($LH[$j] -eq 1) {$line = $Line + "-" + $Hour}
            $Line=$Line+")"
            
            $Line=$Line.Replace("0-23", "All")
            
            $Line=$Line.Replace(",)", ")")

            $Line
        }
    }
}

function FileTime2Date($time) {
  $time = ([datetime]::FromFileTime($time))
  if (!$time -or $time -eq '') {$time='Never'}
  return $time
}

#import the ActiveDirectory Module 
Import-Module ActiveDirectory 

$reportdate = Get-Date -Format ssddmmyyyy 
 
#$csvreportfile = "ALLADUsers_$reportdate.csv" 
$csvreportfile = "AD_users.csv"

# Retrieve local Time Zone bias from machine registry in hours.
# This bias does not change with Daylight Savings Time.
# Modified September 19, 2012, to handle fractions of an hour properly.
$Bias = [Math]::Round((Get-ItemProperty `
    -Path HKLM:\System\CurrentControlSet\Control\TimeZoneInformation).Bias/60, `
    0, [MidpointRounding]::AwayFromZero)

# Create an empty array for logon hours with 168 elements, one for each hour of the week.
$LH = New-Object 'object[]' 168
     
#Perform AD search. The quotes "" used in $SearchLoc is essential 
#Without it, Export-ADUsers returuned error 
Get-ADUser -Properties *,"msDS-UserPasswordExpiryTimeComputed" -Filter * | Sort-Object SamAccountName | Where {$_.ObjectClass -ne "computer"} |
Select-Object @{Label = "UserName";Expression = {$_.sAMAccountName}}, 
@{Label = "FullName";Expression = {$_.DisplayName}}, 
@{Label = "AccountType";Expression = {$_.ObjectClass}}, 
@{Label = "Comment";Expression = {$_.Description}}, 
@{Label = "HomeDrive";Expression = {$_.HomeDrive}},
@{Label = "HomeDir";Expression = {$_.HomeDir}},
@{Label = "Profile";Expression = {$_.ProfilePath}},
@{Label = "LogonScript";Expression = {$_.ScriptPath}},
@{Label = "Workstations";Expression = {$_.LogonWorkstations}},
@{Label = "PswdCanBeChanged";Expression = {if ($_.CannotChangePassword -eq 'TRUE') {'No'} Else {'Yes'}}},
@{Label = "PswdLastSetTime";Expression = {if($_.PasswordLastSet) {$_.PasswordLastSet} else {'Never'}}},
@{Label = "PswdRequired";Expression = {if ($_.PasswordNotRequired -eq 'TRUE') {'No'} Else {'Yes'}}},
@{Label = "PswdExpires";Expression = {if ($_.PasswordNeverExpires -eq 'TRUE') {'No'} Else {'Yes'}}},
@{Label = "PswdExpiresTime";Expression = {FileDateToTime $_."msDS-UserPasswordExpiryTimeComputed"}},
@{Label = "AcctDisabled";Expression = {if ($_.Enabled -eq 'TRUE') {'No'} Else {'Yes'}}},
@{Label = "AcctLockedOut";Expression = {if ($_.LockedOut -eq 'TRUE') {'Yes'} Else {'No'}}}, 
@{Label = "AcctExpiresTime";Expression = {if ($_.accountExpirationDate) {$_.accountExpirationDate} else {'Never'}}}, 
@{Label = "LastLogonTime";Expression = {if ($_.lastlogondate) {$_.LastLogonDate} else {'Never'}}},
@{Label = "LastLogonServer";Expression = {'placeholder'}}, 
@{Label = "LogonHours";Expression = {OctetToHours $_.logonHours}}, 
@{Label = "Sid";Expression = {$_.objectSid}}, 
@{Label = "Password Expired";Expression = {if ($_.PasswordExpired -eq 'TRUE') {'Yes'} Else {'No'}}} |
                    
                   
#Export CSV report 
Export-Csv -Path $csvreportfile -NoTypeInformation
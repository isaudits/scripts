#Designed to export information in same format as DumpSec

$reportdate = Get-Date -Format ssddmmyyyy 
 
#$csvreportfile = "ALLADGroups_$reportdate.csv" 
$csvreportfile = "AD_group_membership.csv" 
     
#import the ActiveDirectory Module
Import-Module ActiveDirectory 

$ADGroups = Get-ADGroup -Filter '*' -Properties '*'| Where {$_.GroupCategory -eq "Security"} | Sort-Object SamAccountName
$Results = ForEach ($AdGroup in $ADGroups) 
{
    $Members = Get-AdGroupMember -Identity $AdGroup.SamAccountName -Recursive | Where {$_.ObjectClass -ne "computer"}
    ForEach ($Member in $Members) 
    {
        $Hash = @{
            Group  = $AdGroup.SamAccountName
            Description = $AdGroup.Description
            GroupType = $AdGroup.GroupScope
            Member = $Member.SamAccountName
            MemberType = $Member.objectClass
        }
        New-Object -TypeName PSObject -Property $Hash
    }
}

$Results | Select Group,Description,GroupType,Member,MemberType | Export-Csv -Path $csvreportfile -NoTypeInformation
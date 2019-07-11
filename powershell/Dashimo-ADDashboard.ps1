<#
.Synopsis
   Powershell Script to get details AD reports

.NOTES    
    Adopted from https://github.com/EvotecIT/Dashimo/blob/master/Example/Run-AdvancedActiveDirectoryDashboard.ps1
#>

<###########################
    Install Modules
############################>

function Load-Module ($m) {

    # If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        write-host "Module $m is already imported."
    }
    else {

        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $m}) {
            Import-Module $m -Verbose
        }
        else {

            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $m | Where-Object {$_.Name -eq $m}) {
                Install-Module -Name $m -Force -Verbose -Scope CurrentUser
                Import-Module $m -Verbose
            }
            else {

                # If module is not imported, not available and not in online gallery then abort
                write-host "Module $m not imported, not available and not in online gallery, exiting."
                EXIT 1
            }
        }
    }
}


Load-Module Dashimo
Load-Module PSWinDocumentation.AD
Load-Module PSWinReportingV2

<###########################
    Get Data
############################>

if ($null -eq $DataSetForest) {
    $DataSetForest = Get-WinADForestInformation -Verbose -DontRemoveEmpty -PasswordQuality -Splitter "`r`n"
}

$DomainControllers = $DataSetForest.ForestDomainControllers | ForEach-Object {$_.HostName}


if ($null -eq $DataSetEvents) {
   $DataSetEvents = Find-Events -Report ADUserChangesDetailed, ADUserChanges, ADUserLockouts, ADUserStatus, ADGroupChanges -Servers $DomainControllers -DatesRange Last7days -Quiet
}

<###########################
    Generate Dashboard
############################>

Dashboard -Name 'Dashimo Test' -FilePath $PSScriptRoot\DashboardActiveDirectory.html -Show {
    Tab -Name 'Forest' {
        Section -Name 'Forest Information' -Invisible {
            Section -Name 'Forest Information' {
                Table -HideFooter -DataTable $DataSetForest.ForestInformation
            }
            Section -Name 'FSMO Roles' {
                Table -HideFooter -DataTable $DataSetForest.ForestFSMO
            }

        }
        Section -Name 'Forest Domain Controllers' -Collapsable {
            Panel {
                Table -HideFooter -DataTable $DataSetForest.ForestDomainControllers
            }
        }
        Section -Name 'Forest Optional Features / UPN Suffixes / SPN Suffixes' -Collapsable {

            Panel {
                Table -HideFooter -DataTable $DataSetForest.ForestOptionalFeatures -Verbose
            }
            Panel {
                Table -HideFooter -DataTable $DataSetForest.ForestUPNSuffixes -Verbose
            }
            Panel {
                Table -HideFooter -DataTable $DataSetForest.ForestSPNSuffixes -Verbose
            }
        }
        Section -Name 'Sites / Subnets / SiteLinks' -Collapsable {
            Panel {
                Table -HideFooter -DataTable $DataSetForest.ForestSites -Verbose
            }
            Panel {
                Table -HideFooter -DataTable $DataSetForest.ForestSubnets -Verbose
            }
            Panel {
                Table -HideFooter -DataTable $DataSetForest.ForestSiteLinks -Verbose
            }
        }
    }

    foreach ($Domain in $DataSetForest.FoundDomains.Keys) {
        Tab -Name $Domain {
            Section -Name 'Domain Controllers / FSMO Roles' {
                Panel {
                    Table -HideFooter -DataTable $DataSetForest.FoundDomains.$Domain.DomainControllers -Verbose
                }
                Panel {
                    Table -HideFooter -DataTable $DataSetForest.FoundDomains.$Domain.DomainFSMO -Verbose
                }
            }


            Section -Name 'Password Policies' -Invisible {
                Section -Name 'Default Password Policy' {
                    Table -HideFooter -DataTable $DataSetForest.FoundDomains.$Domain.DomainDefaultPasswordPolicy -Verbose
                }

                Section -Name 'Domain Fine Grained Policies' {
                    Table -HideFooter -DataTable $DataSetForest.FoundDomains.$Domain.DomainFineGrainedPolicies -Verbose
                }
            }
            Section -Name 'Users' {
                Panel {
                    Table -HideFooter -DataTable $DataSetForest.FoundDomains.$Domain.DomainUsers
                }
            }
            Section -Name 'Computers' {
                Panel {
                    Table -HideFooter -DataTable $DataSetForest.FoundDomains.$Domain.DomainComputers
                }
            }
            Section -Name 'Groups Priviliged' {
                Panel {
                    Table -HideFooter -DataTable $DataSetForest.FoundDomains.$Domain.DomainGroupsPriviliged
                }
            }
            Section -Name 'Organizational Units' {
                Table -HideFooter -DataTable $DataSetForest.FoundDomains.$Domain.DomainOrganizationalUnits
            }
            Section -Name 'OU ACL Basic' {
                Panel {
                    Table -HideFooter -DataTable $DataSetForest.FoundDomains.$Domain.DomainOrganizationalUnitsBasicACL
                }
            }
            Section -Name 'OU ACL Extended' {
                Panel {
                    Table -HideFooter -DataTable $DataSetForest.FoundDomains.$Domain.DomainOrganizationalUnitsExtended
                }
            }

        }
    }
    Tab -Name 'Changes in Last 7 days' {
        Section -Name 'Group Changes' -Collapsable {
            Table -HideFooter -DataTable $DataSetEvents.ADGroupChanges
        }
        Section -Name 'User Status' -Collapsable {
            Table -HideFooter -DataTable $DataSetEvents.ADUserStatus
        }
        Section -Name 'User Changes' -Collapsable {
            Table -HideFooter -DataTable $DataSetEvents.ADUserChanges
        }
        Section -Name 'User Lockouts' -Collapsable {
            Table -HideFooter -DataTable $DataSetEvents.ADUserLockouts
        }
    }
}
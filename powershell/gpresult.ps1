Import-Module -Name grouppolicy

function get_more
{
    $title = "Add more"
    $message = "Add GPResult command for alternate computer / user?"

    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
        "Adds another."

    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
        "Runs the commands."

    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    $result = $host.ui.PromptForChoice($title, $message, $options, 1) 

    switch ($result)
    {
        0 {return "TRUE"}
    }
}

function get_params
{
$return = "" | Select-Object -Property run_name,target_computer,user_name

#$return.run_name = Read-Host -Prompt 'Enter the name to be assigned for the run (e.g. DomainController, MemberServer, etc):'
$return.target_computer = Read-Host -Prompt "Enter the machine name / IP to analyze: "
$return.user_name = Read-Host -Prompt "Enter the user context to analyze (must have profile on target machine): "
return $return

}

$params=@()

"Running GPResult on the current machine using the current user"
$path = "gpresult_" + $env:computername

Get-GPResultantSetOfPolicy -ReportType html -Path $path

While (get_more) 
{
    $params += get_params
} 

ForEach ($command in $params)
{   
    #$path = 'gpresult_'+$command.run_name + '.html'
    $path = 'gpresult_'+$command.target_computer + '.html'
    "Running GPResult on "+$command.target_computer+" as "+ $command.user_name
    Get-GPResultantSetOfPolicy -ReportType html -Path $path -Computer $command.target_computer -User $command.user_name
}
    
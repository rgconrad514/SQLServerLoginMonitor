."$PSScriptRoot\LoginMonitor.ps1"
Add-Type -AssemblyName PresentationFramework

#Run as elevated
if(-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
{
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000)
    {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}
Import-Module “sqlps” -DisableNameChecking

#Remove any firewall rules from previous install
Remove-NetFirewallRule -Group 'SQL Server Login Monitor'

#Create folder in ProgramData and copy files
New-Item -ItemType directory -Path "$env:ProgramData\SQL Server Login Monitor" -Force
Copy-Item -Path $PSScriptRoot\LoginMonitor.ps1 -Destination "$env:ProgramData\SQL Server Login Monitor\" -Force
Copy-Item -Path $PSScriptRoot\config.xml -Destination "$env:ProgramData\SQL Server Login Monitor\" -Force

#Get database credentials from config.xml file
$config = "$env:ProgramData\SQL Server Login Monitor\config.xml"

$xml = [xml](Get-Content $config)

$Server = $xml.SelectSingleNode("//Server[1]").FirstChild.Value
$TrustedConnection = $xml.SelectSingleNode(“//TrustedConnection[1]”).FirstChild.Value
[int] $UseIPSec = $xml.SelectSingleNode("//UseIPSec[1]").FirstChild.Value

#Create database
if($TrustedConnection -eq "true")
{
    Invoke-Sqlcmd -ServerInstance $Server -InputFile  $PSScriptRoot\LoginMonitor.sql
}
else
{
    $User = $xml.SelectSingleNode("//User[1]").FirstChild.Value
    $Password = $xml.SelectSingleNode("//Password[1]").FirstChild.Value
    Invoke-Sqlcmd -ServerInstance $Server -InputFile  $PSScriptRoot\LoginMonitor.sql -Username $User -Password $Password
}

#Create IPSec policy
if($UseIPSec -eq 1)
{
    Create-IPSecPolicy
}
else
{
    #Enable Windows Firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

$msgBoxInput = [System.Windows.MessageBox]::Show('Do you want to whitelist the LAN?','Whitelist LAN','YesNo','Information')

if($msgBoxInput -eq "Yes")
{
    $ConnectionString = Get-DBConnectionString
    $IPConfig = Get-LANSubnet
    $IPAddress = $IPConfig[0]
    $SubnetMask = $IPConfig[1]

    $Connection = [System.Data.SqlClient.SqlConnection]::new($ConnectionString)
    $Command = [System.Data.SqlClient.SqlCommand]::new('EXEC dbo.WhitelistIP  @IPAddress, @Mask', $Connection)

    try
    {
        $Connection.Open()

        $Command.Parameters.AddWithValue('@IPAddress', $IPAddress)
        $Command.Parameters.AddWithValue('@Mask', $SubnetMask)

        $Command.ExecuteNonQuery()
    }
    finally
    {
        $Command.Dispose()
        $Connection.Dispose()
    }
}

#Get credentials for running the scheduled tasks
$msg = "Enter the username and password that will run scheduler tasks" 
$credential = $Host.UI.PromptForCredential("User name and password", $msg, "$env:userdomain\$env:username", $env:userdomain)
$username = $credential.UserName
$password = $credential.GetNetworkCredential().Password

#Create scheduled tasks
Register-ScheduledTask -Xml (get-content "$PSScriptRoot\OnFailedLogin.xml" | out-string) -TaskName 'SQL Server Login Monitor - On Failed Login' -User $username -Password $password –Force
Register-ScheduledTask -Xml (get-content "$PSScriptRoot\ClearBlockedClients.xml" | out-string) -TaskName 'SQL Server Login Monitor - Clear Blocked Clients' -User $username -Password $password –Force

Write-Host -NoNewLine "Tasks registered, press any key to continue..."

$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

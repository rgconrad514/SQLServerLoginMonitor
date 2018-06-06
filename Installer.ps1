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

Import-Module "sqlps" -DisableNameChecking

#Create folder in ProgramData and copy files
New-Item -ItemType directory -Path "$env:ProgramData\SQL Server Login Monitor" -Force
Copy-Item -Path $PSScriptRoot\LoginMonitor.ps1 -Destination "$env:ProgramData\SQL Server Login Monitor\" -Force
Copy-Item -Path $PSScriptRoot\config.xml -Destination "$env:ProgramData\SQL Server Login Monitor\" -Force

#Get configs from config.xml file
$config = "$env:ProgramData\SQL Server Login Monitor\config.xml"
$xml = [xml](Get-Content $config)
$Server = $xml.SelectSingleNode("//Server[1]").FirstChild.Value
[int] $UseIPSec = $xml.SelectSingleNode("//UseIPSec[1]").FirstChild.Value

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

#Create database

$messageBoxMsg = "Do you want to use integrated security to create the LoginMonitor database? " +
    "The current windows user account must be in the sa or dbcreator server role. Otherwise click No to enter a sysadmin login and password. " +
    "This password will NOT be saved. The Windows Scheduler tasks will be run using the SYSTEM security context."

$useIntegratedSecurity = [System.Windows.MessageBox]::Show($messageBoxMsg,'Create Database','YesNo','Information')
$ConnectionString = ""

if($useIntegratedSecurity -eq "No")
{
    $msg = "Enter the username and password of a sysadmin SQL Server login (e.g. sa)." 
    $credential = $Host.UI.PromptForCredential("User name and password", $msg, "", "")
    $User = $credential.UserName
    $Password = $credential.GetNetworkCredential().Password

    $ConnectionString = "server=$($Server);database=LoginMonitor;user=$($User);password=$($Password);"
    Invoke-Sqlcmd -ServerInstance $Server -InputFile  $PSScriptRoot\LoginMonitor.sql -Username $User -Password $Password
}
else
{
    $ConnectionString = "server=$($Server);database=LoginMonitor;trusted_connection=true;"
    Invoke-Sqlcmd -ServerInstance $Server -InputFile  $PSScriptRoot\LoginMonitor.sql
}

$msgBoxInput = [System.Windows.MessageBox]::Show('Do you want to whitelist the LAN?','Whitelist LAN','YesNo','Information')

if($msgBoxInput -eq "Yes")
{
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

#Create scheduled tasks and run with SYSTEM account

Register-ScheduledTask -Xml (get-content "$PSScriptRoot\OnFailedLogin.xml" | out-string) -TaskName 'SQL Server Login Monitor - On Failed Login' -User "NT AUTHORITY\SYSTEM" -Force
Register-ScheduledTask -Xml (get-content "$PSScriptRoot\ClearBlockedClients.xml" | out-string) -TaskName 'SQL Server Login Monitor - Clear Blocked Clients' -User "NT AUTHORITY\SYSTEM" -Force

Write-Host -NoNewLine "Tasks registered, press any key to continue..."

$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
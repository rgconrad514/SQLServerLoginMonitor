<#
    Gets DB connection string parameters from config.xml
#>
function Get-DBConnectionString
{
    [cmdletbinding()]

    $config = "$PSScriptRoot\config.xml"

    $xml = [xml](Get-Content $config)

    $Server = $xml.SelectSingleNode("//Server[1]").FirstChild.Value

    $ConnectionString = "server=$($Server);database=LoginMonitor;trusted_connection=true;"

    return $ConnectionString
}

function Log-GeoIP
{
    [cmdletbinding()]
    Param
    (
        [parameter(position = 0, Mandatory=$true)]
        [System.Data.SQLClient.SQLConnection]
        $Connection,
        [parameter(position = 1, Mandatory=$true)]
        [string]
        $IPAddress
    )

    $url = "http://api.geoiplookup.net/?query=" + $IPAddress
    $http_Request = [System.Net.WebClient]::new()
    try
    {
        [xml] $Result = $http_Request.DownloadString($url)

        $Hst = $Result.ip.results.result.host
        $ISP = $Result.ip.results.result.isp
        $City = $Result.ip.results.result.city
        $CountryCode = $Result.ip.results.result.countrycode
        $CountryName = $Result.ip.results.result.countryname
        $Latitude = $Result.ip.results.result.latitude
        $Longitude = $Result.ip.results.result.longitude

        $Command = [System.Data.SqlClient.SqlCommand]::new('dbo.InsertGeoIP', $Connection)
        $Command.CommandType = [System.Data.CommandType]::StoredProcedure

        try
        {
            $null = $Command.Parameters.AddWithValue('@IPAddress', $IPAddress)
            $null = $Command.Parameters.AddWithValue('@Host', $Hst)
            $null = $Command.Parameters.AddWithValue('@ISP', $ISP)
            $null = $Command.Parameters.AddWithValue('@City', $City)
            $null = $Command.Parameters.AddWithValue('@CountryCode', $CountryCode)
            $null = $Command.Parameters.AddWithValue('@CountryName', $CountryName)
            $null = $Command.Parameters.AddWithValue('@Latitude', $Latitude)
            $null = $Command.Parameters.AddWithValue('@Longitude', $Longitude)

            $Command.ExecuteNonQuery()
        }
        finally
        {
            $Command.Dispose()
        }
    }
    catch
    {
        return
    }
    finally
    {
        $http_Request.Dispose()
    }
}

function Add-BlockRule
{
    [cmdletbinding()]
    param
    (
        [parameter(position = 0, Mandatory=$true)]
        [string]
        $IPAddress,
        [parameter(position = 1, Mandatory=$true)]
        [string]
        $RuleName,
        [parameter(position = 2, Mandatory=$true)]
        [string]
        $RuleGroup
    )
    
    $config = "$PSScriptRoot\config.xml"
    $xml = [xml](Get-Content $config)

    [int] $UseIPSec = $xml.SelectSingleNode("//UseIPSec[1]").FirstChild.Value
    
    if($UseIPSec -eq 1)
    {
        # A filter list is created for each IP because netsh apparently has a bug when running a command to delete
        # an IP address from an existing list, e.g.:
        #   netsh ipsec static delete filter filterlist="SQL Server Login Monitor" srcaddr=123.123.123.123 dstaddr=any
        # always returns ERR IPsec[05050] : Filter with the specified spec does not exist in FilterList with name 'SQL Server Login Monitor'.
        # This apparently worked in previous versions of Windows, it doesn't work in Windows Server 2016/Windows 10 that I use for testing.
        # Therefore creating a filter list for each IP is the only way around this. From testing this doesn't appear to affect performance
        # when the number of blocked IPs approaches ~1000. I haven't tested it beyond this.
        netsh ipsec static add filter filterlist=$RuleName srcaddr=$IPAddress dstaddr=me
        netsh ipsec static add rule name=$RuleName policy=$RuleGroup filterlist=$RuleName filteraction=$RuleGroup
    }
    else
    {
        # From testing it appears this is the fastest method for creating the firewall rule so the client is blocked
        # as quickly as possible. The rule is first created using netsh, but because netsh does not allow for specifying
        # the firewall group, the rule is retreived via COM after creation to set the group (just to keep the rules organized
        # in the windows firewall UI).
        netsh advfirewall firewall add rule name=$RuleName dir=in interface=any action=block remoteip=$IPAddress
        Get-NetFirewallRule -DisplayName $RuleName | ForEach { $_.Group = $RuleGroup; Set-NetFirewallRule -InputObject $_ }
    }
}

function Delete-BlockRule
{
    [cmdletbinding()]
    param
    (
        [parameter(position = 0, Mandatory=$true)]
        [string]
        $RuleName,
        [parameter(position = 1, Mandatory=$true)]
        [string]
        $RuleGroup
    )

    $config = "$PSScriptRoot\config.xml"
    $xml = [xml](Get-Content $config)

    [int] $UseIPSec = $xml.SelectSingleNode("//UseIPSec[1]").FirstChild.Value

    if($UseIPSec -eq 1)
    {
        netsh ipsec static delete rule name=$RuleName policy=$RuleGroup
        netsh ipsec static delete filterlist name=$RuleName
    }
    else
    {
        netsh advfirewall firewall delete rule name=$RuleName dir=in
    }
}

function Create-IPSecPolicy
{
    [cmdletbinding()]

    $RuleGroup = 'SQL Server Login Monitor'
    $Desc = 'SQL Server Login Monitor block list'

    netsh ipsec static add filteraction name=$RuleGroup action=block
    netsh ipsec static add policy name=$RuleGroup description=$Desc
    netsh ipsec static set policy name=$RuleGroup assign=y
}

<#
    Used to extract event data passed from task scheduler to get user ID, error message and client IP address
#>
function Extract-EventData
{
    [cmdletbinding()]
    param
    (
        [parameter(position = 0, Mandatory=$true)]
        [int]
        $EventID,
        [parameter(position = 1, Mandatory=$true)]
        [string]
        $EventData
    )

    [string] $UserID = ''
    [string] $Message = ''
    [string] $IPAddress = ''

    $EventDataArray = $EventData.Split(',')

    if($EventID -eq 18456)
    {
        if($EventDataArray.Length -gt 0)
        {
            $UserID = $EventDataArray[0].Trim()
        }
        if($EventDataArray.Length -gt 1)
        {
            $Message = $EventDataArray[1].Trim()
        }
    }# For some reason the event description is not provided for these events
    elseif($EventID -eq 17828)
    {
        $Message = 'The prelogin packet used to open the connection is structurally invalid; the connection has been closed. Please contact the vendor of the client library.'
    }
    elseif($EventID -eq 17832)
    {
        $Message = 'The login packet used to open the connection is structurally invalid; the connection has been closed. Please contact the vendor of the client library.'
    }
    elseif($EventID -eq 17836)
    {
        $Message = 'Length specified in network packet payload did not match number of bytes read; the connection has been closed. Please contact the vendor of the client library.'
    }
    else
    {
        return
    }

    # Use Regex to extract client IP address
    $Regex = [Regex]::new('(?<=\[CLIENT: )(.*)(?=\])')
    foreach ($data in $EventDataArray)
    {
        $Match = $Regex.Match($data)
        if ($Match.Success)
        {
            $IPAddress = $Match.Value.Trim()
            break
        }
    }

    $UserID
    $Message
    $IPAddress
    return
}
<#
    Logs a failed login to the database and blocks the client if needed. 
#>
function Log-FailedLogin
{
    [cmdletbinding()]
    Param
    (
        [parameter(position = 0, Mandatory=$true)]
        [System.Data.SQLClient.SQLConnection]
        $Connection,
        [parameter(position = 1, Mandatory=$true)]
        [int]
        $EventID,
        [parameter(position = 2, Mandatory=$true)]
        [string]
        $IPAddress,
        [parameter(position = 3, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $UserID,
        [parameter(position = 4, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $Message
    )

    $Command = [System.Data.SqlClient.SqlCommand]::new('dbo.LogFailedLogin', $Connection)
    $Command.CommandType = [System.Data.CommandType]::StoredProcedure

    try
    {
        $null = $Command.Parameters.AddWithValue('@EventID', $EventID)
        $null = $Command.Parameters.AddWithValue('@IPAddress', $IPAddress)
        $null = $Command.Parameters.AddWithValue('@UserID', $UserID)
        $null = $Command.Parameters.AddWithValue('@Message', $Message)

        $Reader = $Command.ExecuteReader([System.Data.CommandBehavior]::SingleRow)

        $FirewallRule = ''

        try
        {
            if($Reader.Read())
            {
                #SP will return a result if a firewall rule needs to be created.
                $FirewallGroup = $Reader.GetString(0)
                $FirewallRule = $Reader.GetString(1)

                $null = Add-BlockRule $IPAddress $FirewallRule $FirewallGroup
            }
        }
        finally
        {
            $Reader.Dispose()
        }
        
        return $FirewallRule
    }
    finally
    {
        $Command.Dispose()
    } 
}

<#
    Updates a blocked client after a firewall rule is created
#>
function Update-BlockedClient
{
    [cmdletbinding()]
    Param
    (
        [parameter(position = 0, Mandatory=$true)]
        [System.Data.SQLClient.SQLConnection]
        $Connection,
        [parameter(position = 1, Mandatory=$true)]
        [string]
        $IPAddress,
        [parameter(position = 2, Mandatory=$true)]
        [string]
        $FirewallRule
    )

    $Command = [System.Data.SqlClient.SqlCommand]::new('UpdateBlockedClient', $Connection)
    $Command.CommandType = [System.Data.CommandType]::StoredProcedure

    try
    {
        [void]$Command.Parameters.AddWithValue('@IPAddress', $IPAddress)
        [void]$Command.Parameters.AddWithValue('@FirewallRule', $FirewallRule)

        [void]$Command.ExecuteNonQuery()
    }
    finally
    {
        $Command.Dispose()
    }
}
<#
    Gets the server subnet for automatic whitelisting. Used by the installer.
#>
function Get-LANSubnet
{
    $nic_config = gwmi -computer .  -class "win32_networkadapterconfiguration" | Where-Object {$_.defaultIPGateway -ne $null}
    $IPAddress = $nic_config.ipaddress
    $SubnetMask = 0

    switch ($nic_config.ipsubnet) 
    {
        255.255.255.255   {$SubnetMask = 32}
        255.255.255.254   {$SubnetMask = 31}
        255.255.255.252   {$SubnetMask = 30}
        255.255.255.248   {$SubnetMask = 29}
        255.255.255.240   {$SubnetMask = 28}
        255.255.255.224   {$SubnetMask = 27}
        255.255.255.192   {$SubnetMask = 26}
        255.255.255.128   {$SubnetMask = 25}
        255.255.255.0     {$SubnetMask = 24}
        255.255.254.0     {$SubnetMask = 23}
        255.255.252.0     {$SubnetMask = 22}
        255.255.248.0     {$SubnetMask = 21}
        255.255.240.0     {$SubnetMask = 20}
        255.255.224.0     {$SubnetMask = 19}
        255.255.192.0     {$SubnetMask = 18}
        255.255.128.0     {$SubnetMask = 17}
        255.255.0.0       {$SubnetMask = 16}
        255.254.0.0       {$SubnetMask = 15}
        255.252.0.0       {$SubnetMask = 14}
        255.248.0.0       {$SubnetMask = 13}
        255.240.0.0       {$SubnetMask = 12}
        255.224.0.0       {$SubnetMask = 11}
        255.192.0.0       {$SubnetMask = 10}
        255.128.0.0       {$SubnetMask = 9}
        255.0.0.0         {$SubnetMask = 8}
        254.0.0.0         {$SubnetMask = 7}
        252.0.0.0         {$SubnetMask = 6}
        248.0.0.0         {$SubnetMask = 5}
        240.0.0.0         {$SubnetMask = 4}
        224.0.0.0         {$SubnetMask = 3}
        192.0.0.0         {$SubnetMask = 2}
    }

    $IPAddress
    $SubnetMask
}

<#Task Scheduler functions#>

<#
    Called by scheduled task to clear clients flagged for unblocking
    or counter reset.
#>
function Clear-BlockedClients
{
    $ConnectionString = Get-DBConnectionString

    $Connection = [System.Data.SqlClient.SqlConnection]::new($ConnectionString)
    $Command = [System.Data.SqlClient.SqlCommand]::new('dbo.ResetClients', $Connection)
    $Command.CommandType = [System.Data.CommandType]::StoredProcedure

    try
    {
        $Connection.Open()
    
        # ResetClients deletes records in ClientStatus that need to be unblocked
        # or counters reset. Returns a result set of firewall rules to delete.
        $Reader = $Command.ExecuteReader([System.Data.CommandBehavior]::SingleResult)
        try
        {
            while($Reader.Read())
            {
                $FirewallRule = $Reader.GetString(0)
                Delete-BlockRule $FirewallRule 'SQL Server Login Monitor'
            }
        }
        finally
        {
            $Reader.Dispose()
        }
    }
    finally
    {
        $Command.Dispose()
        $Connection.Dispose()
    }
}
<#
    Called by event-triggered task for login failures (event IDs 18456, 17828, 17832 and 17836)
#>
function On-FailedLogin
{
    [cmdletbinding()]
    Param
    (
        [parameter(position = 0, Mandatory=$true)]
        [int]
        $EventID,
        [parameter(position = 1, Mandatory=$true)]
        [string]
        $EventData
    )
    $EventDataArray = Extract-EventData $EventID $EventData

    $UserID = $EventDataArray[0]
    $Message = $EventDataArray[1]
    $IPAddress = $EventDataArray[2]
    
    if($IPAddress -eq '')
    {
        return;
    }

    $ConnectionString = Get-DBConnectionString

    $Connection = [System.Data.SQLClient.SQLConnection]::new($ConnectionString)

    try
    {
        $Connection.Open()

        $FirewallRule = Log-FailedLogin $Connection $EventID $IPAddress $UserID $Message

        if($FirewallRule -ne '')
        {
            #Firewall rule was created so the record is updated in ClientStatus
            Update-BlockedClient $Connection $IPAddress $FirewallRule
        }

        Log-GeoIP $Connection $IPAddress
    }
    finally
    {
        $Connection.Dispose()
    }
}
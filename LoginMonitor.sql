USE [master]
GO

IF EXISTS(SELECT * FROM sys.databases WHERE name = 'LoginMonitor')
BEGIN
  ALTER DATABASE [LoginMonitor] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
  DROP DATABASE [LoginMonitor];
END
GO

CREATE DATABASE [LoginMonitor];
ALTER DATABASE [LoginMonitor] SET RECOVERY SIMPLE;
GO

USE [LoginMonitor]
GO

CREATE TABLE EventLog
(
	LogId BIGINT NOT NULL PRIMARY KEY IDENTITY,
	LogDate DATETIME DEFAULT GETDATE(),
	IPAddress VARCHAR(100),
	Action VARCHAR(20),
	EventDesc VARCHAR(512)
);
CREATE INDEX IX_EventLog_IP_Action_LogDate ON EventLog(IPAddress, Action, LogDate);
CREATE INDEX IX_EventLog_LogDate ON EventLog(LogDate);

CREATE TABLE ClientStatus
(
	IPAddress VARCHAR(100) NOT NULL PRIMARY KEY,
	LastFailedLogin DATETIME,
	UnblockDate DATETIME,
	CounterResetDate DATETIME,
	FailedLogins INT DEFAULT 1,
	Blocked BIT DEFAULT 0,
	FirewallRule VARCHAR(255)
);
CREATE INDEX IX_ClientStatus_CounterResetDate ON ClientStatus(CounterResetDate);
CREATE INDEX IX_ClientStatus_UnblockDate ON ClientStatus(UnblockDate);

CREATE TABLE ClientStatusDtl
(
	IPAddress VARCHAR(100) NOT NULL,
	LogID INT NOT NULL IDENTITY,
	LogDate DATETIME,
	UserID VARCHAR(128),
	Message VARCHAR(1000),
	PRIMARY KEY(IPAddress, LogID),
	FOREIGN KEY(IPAddress)REFERENCES ClientStatus ON DELETE CASCADE
);
CREATE INDEX IX_ClientStatusDtl_UserId_LogDate ON ClientStatusDtl(UserID, LogDate)INCLUDE(IPAddress);

CREATE TABLE Config
(
	ConfigID INT NOT NULL PRIMARY KEY,
	ConfigDesc VARCHAR(255),
	ConfigValue INT NOT NULL
);
INSERT INTO Config(ConfigID, ConfigDesc, ConfigValue)
VALUES(1, 'Time in minutes before counters are reset', 15),
	(2, 'Number of failed logins before client is blocked', 3),
  (3, 'Hours before client is unblocked (<=0 for never)', 24),
	(4, 'Penalty in hours for additional blocks (for repeat offenders)', 24),
	(5, 'EventLog retention days (<=0 to retain forever)', 90);

CREATE TABLE ConfigEvent
(
	EventID INT NOT NULL PRIMARY KEY,
	Block BIT NOT NULL DEFAULT 1
);
INSERT INTO ConfigEvent(EventID)
VALUES(17828), (17832), (17836), (18456);

CREATE TABLE ConfigMsgFilter
(
	MsgFilterID INT NOT NULL PRIMARY KEY IDENTITY,
	FilterText VARCHAR(512)
);
-- Some error messages that can probably be ignored.
INSERT INTO ConfigMsgFilter(FilterText)
VALUES('Login is valid login, but server access failed.'),
	('Login is valid, but server access failed.'),
	('Password must be changed.');

CREATE TABLE Whitelist
(
	IPAddress VARCHAR(100) NOT NULL PRIMARY KEY,
	Description VARCHAR(255)
);

CREATE TABLE GeoIP
(
	IPAddress VARCHAR(100) NOT NULL PRIMARY KEY,
	Host VARCHAR(512),
	ISP VARCHAR(512),
	City VARCHAR(255),
	CountryCode VARCHAR(2),
	CountryName VARCHAR(100),
	Latitude FLOAT,
	Longitude FLOAT,
	LastUpdate DATETIME DEFAULT GETDATE()
);

GO

CREATE VIEW BlockedClient
AS
	SELECT IPAddress,
		LastFailedLogin,
		UnblockDate,
		CounterResetDate,
		FailedLogins,
		FirewallRule
	FROM ClientStatus
	WHERE Blocked = 1
GO

/*
  Instead of trigger to provide more intuitive delete logic for unblocking
	clients within an application. This will flag a client in ClientStatus
	for immediate unblocking the next time ClearBlockedClients.ps1 script runs.
*/
CREATE TRIGGER trg_BlockedClient_D
	ON BlockedClient
	INSTEAD OF DELETE
AS
BEGIN
  UPDATE ClientStatus
	SET UnblockDate = GETDATE(), Blocked = 0
	WHERE EXISTS (SELECT * FROM DELETED WHERE DELETED.IPAddress = ClientStatus.IPAddress);
END
GO

CREATE VIEW BlockedClientDtl
AS
	SELECT * FROM ClientStatusDtl
GO

/*
  Use a schema-bound view to persist some useful statistics for clients
	based on data from EventLog.
*/
CREATE VIEW ClientStatistics
WITH SCHEMABINDING
AS
SELECT IPAddress,
  SUM(CASE WHEN Action = 'Blocked' THEN 1 ELSE 0 END) AS Blocks,
	SUM(CASE WHEN Action = 'Unblock' THEN 1 ELSE 0 END) AS Unblocks,
	SUM(CASE WHEN Action = 'Login Failure' THEN 1 ELSE 0 END) AS LoginFailures,
	SUM(CASE WHEN Action = 'Ignored' THEN 1 ELSE 0 END) AS Ignores,
	SUM(CASE WHEN Action = 'Reset Counter' THEN 1 ELSE 0 END) AS CounterResets,
	COUNT_BIG(*) AS Cnt
FROM dbo.EventLog
GROUP BY IPAddress;
GO
-- Index for quick lookup by IP address.
CREATE UNIQUE CLUSTERED INDEX IX_ClientStatics_IPAddress ON ClientStatistics(IPAddress)
GO

CREATE TRIGGER trg_Whitelist_I
	ON Whitelist
	AFTER INSERT
AS
BEGIN
  DELETE FROM BlockedClient
	WHERE IPAddress IN (SELECT IPAddress FROM INSERTED);
END
GO
/*
Create some IP helper functions (reference: http://www.jasinskionline.com/technicalwiki/IP-Address-Conversion-Between-Integer-and-String-SQL-Server.ashx)
*/

CREATE FUNCTION ConvertIPToLong(@IP VARCHAR(15))
RETURNS BIGINT
AS
BEGIN
	DECLARE @Long bigint
	SET @Long = CONVERT(bigint, PARSENAME(@IP, 4)) * 256 * 256 * 256 +
			CONVERT(bigint, PARSENAME(@IP, 3)) * 256 * 256 +
			CONVERT(bigint, PARSENAME(@IP, 2)) * 256 +
			CONVERT(bigint, PARSENAME(@IP, 1))

	RETURN @Long
END
GO

CREATE FUNCTION ConvertLongToIp(@IpLong bigint) 
RETURNS VARCHAR(15)
AS 
BEGIN
	DECLARE @IpHex varchar(8), @IpDotted  varchar(15)

	SELECT @IpHex = substring(convert(varchar(30), master.dbo.fn_varbintohexstr(@IpLong)), 11, 8)

	SELECT @IpDotted = CONVERT(VARCHAR(3), CONVERT(INT, (CONVERT(VARBINARY, SUBSTRING(@IpHex, 1, 2), 2)))) + '.' +
									CONVERT(VARCHAR(3), CONVERT(INT, (CONVERT(VARBINARY, SUBSTRING(@IpHex, 3, 2), 2)))) + '.' +
									CONVERT(VARCHAR(3), CONVERT(INT, (CONVERT(VARBINARY, SUBSTRING(@IpHex, 5, 2), 2)))) + '.' +
									CONVERT(VARCHAR(3), CONVERT(INT, (CONVERT(VARBINARY, SUBSTRING(@IpHex, 7, 2), 2))))

	RETURN @IpDotted
END
GO

/*
  Encapsulates logic for ClientStatus.UnblockDate. Add any custom heuristic-like logic
	for blocking more malicious clients here. Data can be pulled from ClientStatistics or
	EventLog to customize the amount of time to block an IP (or to permanently block).
*/
CREATE FUNCTION GetUnblockDate
(
	@IPAddress VARCHAR(100),
	@LastFailedLogin DATETIME
)
RETURNS DATETIME
AS
BEGIN
  DECLARE @UnblockDate DATETIME;
	DECLARE @BlockHours INT;
	DECLARE @BlockCnt INT;
	DECLARE @RepeatBlockPenaltyHours INT;

	SELECT @BlockHours = ConfigValue
	FROM Config
	WHERE ConfigID = 3;

	IF @BlockHours > 0 -- If a parameter for block hours has been set calculate unblock date,
	BEGIN              -- otherwise ignore and return null (block permanently).
		SELECT @BlockCnt = Blocks
		FROM ClientStatistics
		WHERE IPAddress = @IPAddress;

		-- Get hours per block penalty for repeat offenders if we want to extend the block time
		SELECT @RepeatBlockPenaltyHours = CASE WHEN ConfigValue < 0 THEN 0 ELSE ConfigValue END
		FROM Config
		WHERE ConfigID = 4;

		/*
		Calculate total block hours. Consider adding other logic based on calculations from EventLog
		such as number of failed login attempts per unit time. Some brute force software will attempt
		hundreds of logins per minute which could be calculated using lead/lag functions and perhaps used
		to apply longer or permanent blocks (set @UnblockDate = null).
		*/
		SET @BlockHours = @BlockHours + @BlockCnt * @RepeatBlockPenaltyHours;

		SET @UnblockDate = DATEADD(hour, @BlockHours, @LastFailedLogin);
	END

	RETURN @UnblockDate;
END
GO

/*
  Can be used to customize logic for determining failed login threshold.
*/
CREATE FUNCTION [dbo].[GetLoginThreshold] 
(
	@EventID int,
	@IPAddress VARCHAR(100),
	@UserID VARCHAR(128),
	@Message VARCHAR(1000)
)
RETURNS INT
AS
BEGIN
	DECLARE @FailedLoginThreshold INT;

	SELECT @FailedLoginThreshold = ConfigValue
	FROM Config
	WHERE ConfigID = 2;
  
	-- Example custom logic
	/*
	SELECT @FailedLoginThreshold =
	CASE
	  WHEN @EventID IN (17828, 17832, 17836) THEN 1 -- Bad packets sent from client, often from port scanning software (but can be the result of server misconfiguration on older MSSQL versions)
		WHEN @UserID IN (SELECT [name] FROM master.sys.sql_logins WHERE is_disabled = 1) THEN 1 -- Immediately block attempts with disabled users accounts
		WHEN COALESCE(IS_SRVROLEMEMBER('sysadmin', @UserID), 0) = 1 THEN 1 -- If remote users are expected to not be sysadmins
		ELSE @FailedLoginThreshold
	END;
	*/
	RETURN @FailedLoginThreshold;
END
GO

/*
	Add any custom logic for setting counter reset date
*/
CREATE FUNCTION [dbo].[GetCounterResetDate]
(
	@IPAddress VARCHAR(100),
	@LogDate DATETIME
)
RETURNS DATETIME
AS
BEGIN
	DECLARE @CounterResetDate DATETIME;

	SELECT @CounterResetDate = DATEADD(MINUTE, CASE WHEN ConfigValue < 1 THEN 1 ELSE ConfigValue END, @LogDate)
	FROM Config
	WHERE ConfigId = 1;

	RETURN @CounterResetDate;
END
GO

/*
Create stored procedures.
*/

/*
  SP for quickly adding CIDR IP address ranges to the whitelist. Make sure to add LAN IPs with this.
*/
CREATE PROCEDURE WhitelistIP
(
	@IpAddress varchar(15),
	@Mask int = 32,
	@Description text = null
)
AS
BEGIN
	SET NOCOUNT ON;
	DECLARE @Base BIGINT  = CAST(4294967295 AS BIGINT);
	DECLARE @Power BIGINT  = Power(2.0, 32.0 - @Mask) - 1;
	DECLARE @LowRange BIGINT  = dbo.ConvertIPToLong(@IpAddress) & (@Base ^ @Power);
	DECLARE @HighRange BIGINT  = @LowRange + @Power;
	DECLARE @CurrentIP VARCHAR(15)

	WHILE @LowRange <= @HighRange
	BEGIN
	  SET @CurrentIP = dbo.ConvertLongToIp(@LowRange);

		IF @Description IS NULL
			SET @Description = 'Whitelist for ' + @CurrentIP + '/' + CONVERT(varchar(2), @Mask);

		INSERT INTO Whitelist(IPAddress, Description)
		SELECT @CurrentIP, @Description
		WHERE NOT EXISTS (SELECT * FROM Whitelist WHERE IPAddress = @CurrentIP);

		SET @LowRange = @LowRange + 1;
	END;
END
GO

/*
  Called by OnFailedLogin task, shouldn't be called by any other application.
*/

CREATE PROCEDURE LogFailedLogin
(
	@EventID int,
	@IPAddress VARCHAR(100),
	@UserID VARCHAR(128),
	@Message VARCHAR(1000)
)
AS
BEGIN
	SET NOCOUNT ON;
	DECLARE @LogDate DATETIME = GETDATE();
	DECLARE @FailedLoginThreshold INT;
	DECLARE @CounterResetDate DATETIME;
	DECLARE @FirewallGroup VARCHAR(100) = 'SQL Server Login Monitor'
	DECLARE @FirewallRules TABLE
	(
		FirewallGroup VARCHAR(100),
		FirewallRule VARCHAR(255)
	)
	
	IF @IPAddress = '<local machine>' RETURN; -- Ignore login failures on local machine
	IF NOT EXISTS (SELECT * FROM ConfigEvent WHERE EventID = @EventID AND Block = 1) RETURN; -- Check if event is being monitored
	IF EXISTS (SELECT * FROM ConfigMsgFilter  WHERE CHARINDEX(FilterText, @Message) > 0) RETURN; -- Check event message against exclusions

	IF @UserID = '' SET @UserID = NULL;

	SELECT @FailedLoginThreshold = dbo.GetLoginThreshold(@EventID, @IPAddress, @UserID, @Message);
	SELECT @CounterResetDate = dbo.GetCounterResetDate(@IPAddress, @LogDate);

	INSERT INTO EventLog(IPAddress, Action, EventDesc)
	VALUES(@IPAddress, 'Login Failure', @Message);

	MERGE INTO ClientStatus t USING
	(
		VALUES(@IPAddress, @LogDate, @CounterResetDate)
	)AS s(IPAddress, LogDate, CounterResetDate)
	ON t.IPAddress = s.IPAddress
	WHEN MATCHED THEN
	  UPDATE SET t.LastFailedLogin = s.LogDate,
			t.FailedLogins = t.FailedLogins + 1,
	    t.CounterResetDate = CASE WHEN t.Blocked = 0 THEN s.CounterResetDate END
	WHEN NOT MATCHED THEN
		INSERT(IPAddress, LastFailedLogin, CounterResetDate)
		VALUES(s.IPAddress, s.LogDate, s.CounterResetDate);
	/*
	Updates a client if it needs to be blocked and outputs to the @FirewallRules
	table variable that the SP can return to signal a firewall needs to be created.
	*/
	UPDATE ClientStatus
	SET Blocked = 1, CounterResetDate = NULL
	OUTPUT @FirewallGroup, @FirewallGroup + ' - ' + INSERTED.IPAddress
	INTO @FirewallRules(FirewallGroup, FirewallRule)
	WHERE IPAddress = @IPAddress
	  AND Blocked = 0
		AND FailedLogins >= @FailedLoginThreshold
		AND NOT EXISTS (SELECT * FROM WhiteList WHERE WhiteList.IPAddress = ClientStatus.IPAddress);

	INSERT INTO ClientStatusDtl(IPAddress, LogDate, UserID, Message)
	VALUES(@IPAddress, @LogDate, @UserID, @Message);

	-- Log when whitelisted client is ignored.
	INSERT INTO EventLog(IPAddress, Action, EventDesc)
	SELECT IPAddress,
		'Ignored',
		'Ignoring client ' + IPAddress + ' after ' + CONVERT(varchar(10), FailedLogins)
		+ ' failed login attempt' + CASE WHEN FailedLogins > 1 THEN 's' ELSE '' END + '. Client is whitelisted.'
	FROM ClientStatus c
	WHERE IPAddress = @IPAddress
		AND EXISTS (SELECT * FROM WhiteList w WHERE w.IPAddress = c.IPAddress)
		AND FailedLogins >= @FailedLoginThreshold;

	-- Return firewall group/rule to add to firewall
	SELECT FirewallGroup, FirewallRule
	FROM @FirewallRules;
END
GO

/*
  Used by ClearBlockedClients task to remove firewall rules; shouldn't
	be called by any other application otherwise firewall rules will become out of synch with
	ClientStatus table.
*/
CREATE PROCEDURE ResetClients
AS
BEGIN
	SET NOCOUNT ON;
	DECLARE @DeletedClients TABLE
	(
	  IPAddress VARCHAR(100),
		Action VARCHAR(20),
		EventDesc VARCHAR(512),
		FirewallRule VARCHAR(255),
		LogDate DATETIME
	);
	DELETE FROM ClientStatus
	OUTPUT DELETED.IPAddress,
	  CASE
		  WHEN DELETED.FirewallRule IS NULL THEN 'Reset Counter'
			ELSE 'Unblock'
		END,
		CASE
		  WHEN DELETED.FirewallRule IS NULL THEN 'Failed login counter reset for client '
			ELSE 'Unblocked client '
		END + DELETED.IPAddress + '.',
		DELETED.FirewallRule,
		COALESCE(DELETED.LastFailedLogin, DELETED.CounterResetdate)
	INTO @DeletedClients(IPAddress, Action, EventDesc, FirewallRule, LogDate)
	WHERE (UnblockDate < GETDATE() AND FirewallRule IS NOT NULL) -- Clients to unblock
	  OR CounterResetDate < GETDATE(); -- Clients to reset counters on

	INSERT INTO EventLog(IPAddress, Action, EventDesc)
	SELECT IPAddress, Action, EventDesc
	FROM @DeletedClients
	ORDER BY LogDate;

	DELETE FROM EventLog -- Purge EventLog if needed.
	WHERE LogDate < (SELECT DATEADD(DAY, -ConfigValue, GETDATE())
									 FROM Config
									 WHERE ConfigID = 5
									 AND ConfigValue > 0)

	SELECT FirewallRule -- Return list of firewall rules to delete.
	FROM @DeletedClients
	WHERE FirewallRule IS NOT NULL;
END
GO

/*
	Updates firewall rule name and inserts event log record.
*/
CREATE PROCEDURE [dbo].[UpdateBlockedClient]
(
	@IPAddress VARCHAR(100),
	@FirewallRule VARCHAR(255)
)
AS
BEGIN
	SET NOCOUNT ON;

	UPDATE ClientStatus
	SET FirewallRule = @FirewallRule,
		UnblockDate = dbo.GetUnblockDate(IPAddress, LastFailedLogin)
	OUTPUT INSERTED.IPAddress, 'Blocked', 'Blocked client ' + INSERTED.IPAddress + ' after '
		+ CONVERT(VARCHAR(10), INSERTED.FailedLogins) + ' failed login attempt'
		+ CASE WHEN INSERTED.FailedLogins > 1 THEN 's' ELSE '' END + '.'
	INTO EventLog(IPAddress, Action, EventDesc)
	WHERE IPAddress = @IPAddress
	  AND FirewallRule IS NULL;
END
GO

/*
Unblocks a client by user ID; can be incorporated into an application
utilizing a password reset API.
*/
CREATE PROCEDURE UnblockUser(@UserID VARCHAR(128))
AS
BEGIN
	SET NOCOUNT ON;
	DELETE FROM BlockedClient
	WHERE IPAddress IN (SELECT IPAddress
	                    FROM BlockedClientDtl
											WHERE UserID = @UserID);
END
GO

CREATE PROCEDURE InsertGeoIP
(
  @IPAddress VARCHAR(100),
	@Host VARCHAR(512),
	@ISP VARCHAR(512),
	@City VARCHAR(255),
	@CountryCode VARCHAR(2),
	@CountryName VARCHAR(100),
	@Latitude FLOAT,
	@Longitude FLOAT
)
AS
BEGIN
	SET NOCOUNT ON;
	MERGE INTO GeoIP AS t USING
	(
		VALUES(@IPAddress, @Host, @ISP, @City, @CountryCode, @CountryName, @Latitude, @Longitude)
	)s(IPAddress, Host, ISP, City, CountryCode, CountryName, Latitude, Longitude)
	ON t.IPAddress = s.IPAddress
	WHEN NOT MATCHED THEN
	  INSERT(IPAddress, Host, ISP, City, CountryCode, CountryName, Latitude, Longitude)
		VALUES(s.IPAddress, s.Host, s.ISP, s.City, s.CountryCode, s.CountryName, s.Latitude, s.Longitude)
	WHEN MATCHED
	  AND (
			COALESCE(s.Host, '') <> COALESCE(t.host, '')
			OR COALESCE(s.ISP, '') <> COALESCE(t.ISP, '')
			OR COALESCE(s.City, '') <> COALESCE(t.City, '')
			OR COALESCE(s.CountryCode, '') <> COALESCE(t.CountryCode, '')
			OR COALESCE(s.CountryName, '') <> COALESCE(t.CountryName, '')
			OR COALESCE(s.Latitude, 0) <> COALESCE(t.Latitude, 0)
			OR COALESCE(s.Longitude, 0) <> COALESCE(t.Longitude, 0)
			)
	THEN
	  UPDATE SET t.Host = s.Host,
		  t.ISP = s.ISP,
			t.City = s.City,
			t.CountryCode = s.CountryCode,
			t.CountryName = s.CountryName,
			t.Latitude = s.Latitude,
			t.Longitude = s.Longitude,
			t.LastUpdate = GETDATE();
END
GO

/*
  Create role for access to unblock clients via BlockedClient/BlockedClientDtl tables
*/
CREATE ROLE UnblockUsers
GRANT EXECUTE ON UnblockUser TO UnblockUsers
GRANT SELECT ON BlockedClientDtl TO UnblockUsers
GRANT DELETE ON BlockedClient TO UnblockUsers
GRANT SELECT ON BlockedClient TO UnblockUsers
GO

/*
	Minimum permissions for user running task scheduler scripts
*/
CREATE ROLE LoginMonitorService
GRANT EXECUTE ON LogFailedLogin TO LoginMonitorService
GRANT EXECUTE ON ResetClients TO LoginMonitorService
GRANT EXECUTE ON UpdateBlockedClient TO LoginMonitorService
GRANT EXECUTE ON InsertGeoIP TO LoginMonitorService
GO

/*
  Create user for NT AUTHORITY\SYSTEM account
*/
CREATE USER LoginMonitor FOR LOGIN [NT AUTHORITY\SYSTEM]
ALTER ROLE LoginMonitorService ADD MEMBER LoginMonitor
GO

# SQL Server Login Monitor
More details in this article: https://www.codeproject.com/Articles/1240243/SQL-Server-Brute-Force-Attack-Detection-Part

## Installation:

1. Login to the windows machine running SQL Server as a local admin. Ideally this account is also a login on the SQL Server instance the database will be created
on and a member of the sysadmin SQL Server role (make sure to set a strong password!). If the SQL Server instance only allows SQL Server logins, edit the config.xml
and set TrustedConnection = false and enter the user and password to use for database connections. The installer will create the database using these credentials
and the powershell scripts will also use them for their database connections.
2. Make sure that logging of failed logins is enabled for the instance(s) being monitored. This can be set in the registry, but is dependent on the version of
SQL Server so I haven't included it in the installer. Easiest way to set is from SSMS, right-click the server instance and go to Properties->Security->Login auditing and
select either "Failed logins only" or "Both failed and successful logins". This is needed to generate the event IDs in the event log that will trigger the OnFailedLogin
task.
3. Run installer.bat, the script will self-elevate and prompt for admin credentials if needed. Another prompt will appear for the user account to run the scheduled
tasks, set this to the current user and password.

## License:
  This code is licensed under CPOL (https://www.codeproject.com/info/cpol10.aspx), a copy is provided.

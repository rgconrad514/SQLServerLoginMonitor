# SQL Server Login Monitor
Brute force attack prevention for remotely accessible SQL Server databases using PowerShell and Windows Task Scheduler API.
More details in this article: https://www.codeproject.com/Articles/1240243/SQL-Server-Brute-Force-Attack-Detection-Part

## Installation:

1. Login to the Windows machine running SQL Server as a local Windows admin (or domain admin). If a local admin account is not used the self-elevating install.bat installer will prompt for admin credentials.
2. Make sure that logging of failed logins is enabled for the instance(s) being monitored. This can be set in the registry, but is dependent on the version of SQL Server so I haven't included it in the installer. The easiest way to set it is from SSMS; right-click the server instance and go to Properties->Security->Login auditing and select either "Failed logins only" or "Both failed and successful logins". This is needed to generate the event IDs in the event log that will trigger the OnFailedLogin task.
3. Choose whether to use Windows Firewall or IPSec-based rules in the config.xml file. Default is Windows Firewall (IPSec = 0); set IPSec = 1 to use IPSec-based block rules if Windows Firewall is turned off (e.g. using 3rd-party firewall provided by AV software).
4. Run installer.bat, the script will self-elevate and prompt for admin credentials if needed. Another prompt will display asking if integrated security should be used. Choose Yes if the Windows admin account is also a login for SQL Server and is a member of the sysadmin or dbcreator server role. This will typically be the case if the Windows account was used to install SQL Server originally and it's permissions have not been changed. Choose No if only SQL Server logins (typically the sa account) have sysadmin or dbcreator priviledges. You will then be prompted to enter the login credentials. These credentials are only used to create the database and necessary permissions for the SYSTEM security context to execute SQL commands, they are not stored anywhere.

## License
This code is licensed under CPOL (https://www.codeproject.com/info/cpol10.aspx), a copy is provided.

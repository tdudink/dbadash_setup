/*
DbaDash_SQLSecurity.sql 

Modification History:
---------------------
2026-04-26  tdu  $(ComputerName)\svc_dbadash is now the default monitoring account for DbaDash.  Updated script to create login and grant permissions to this account.
2026-04-25  tdu  use .\svc_dbadash as default monitoring account
2024-12-21  tino/opt  reated script with initial content
*/
Use Master;
GO
PRINT convert(varchar, getdate(), 121) + ' ' + @@SERVERNAME + '.' + DB_Name() + ' : Deploy DbaDash_SQLSecurity.sql';
GO

declare @sSQLCMD nvarchar(4000);
declare @sSQLLogin sysname;
SET @sSQLLogin  = '$(COMPUTERNAME)\svc_dbadash';
 
if not exists (select [name] from syslogins where [name] = @sSQLLogin)
begin
   print convert(varchar, getdate(), 121) + ' ' + @@SERVERNAME + ' : Create SQL Login ' + @sSQLLogin
   SET @sSQLCMD = N'CREATE LOGIN [' + @sSQLLogin + N'] FROM WINDOWS WITH DEFAULT_DATABASE=[tempdb], DEFAULT_LANGUAGE=[us_english]';
   exec(@sSQLCMD);
end

SET @sSQLCMD = N'
GRANT VIEW SERVER STATE TO ' + QUOTENAME(@sSQLLogin) + ';
GRANT VIEW ANY DATABASE TO ' + QUOTENAME(@sSQLLogin) + ';
GRANT CONNECT ANY DATABASE TO ' + QUOTENAME(@sSQLLogin) + ';
GRANT VIEW ANY DEFINITION TO ' + QUOTENAME(@sSQLLogin) + ';
GRANT ALTER ANY EVENT SESSION TO ' + QUOTENAME(@sSQLLogin) + '; /* Required if you want to use slow query capture */
USE [msdb]
IF NOT EXISTS(SELECT [name]  
			FROM msdb.sys.database_principals
			WHERE name = ' + QUOTENAME(@sSQLLogin,'''') + ')
BEGIN
	CREATE USER ' + QUOTENAME(@sSQLLogin) + ' FOR LOGIN ' + QUOTENAME(@sSQLLogin) + ';
END
ALTER ROLE [db_datareader] ADD MEMBER ' + QUOTENAME(@sSQLLogin) + ';
ALTER ROLE [SQLAgentReaderRole] ADD MEMBER ' + QUOTENAME(@sSQLLogin) + ';
'
PRINT @sSQLCMD
EXEC sp_executesql @sSQLCMD

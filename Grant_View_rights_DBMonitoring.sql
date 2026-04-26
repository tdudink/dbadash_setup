/*
File: SQLpermits_DBMonitoring.sql

BSD-14507 Activity Monitor rights

Purpose: 
--------
In order TO allow the SIEM/Elastic tool TO be able TO monitor the SQL Server instance 
all kind of read (not write) permissions have TO be assigned.

To make sure AD user account nutsservices\svc_elastic_sql_mon can be used TO read all SQL Server properties
, databases and other objects, but not TO have any modification rights
(least privilege principle). 

Impact of this T-SQL Script TO be run ON every SQL Server instance:
* A SQL server Login $(SQLLogin_DBMonitoring) will be created (with tempdb as default database)
* The following SQL Server instance rights will be granted:

Server level permissions
1. Connect TO SQL Instance 
2. Connect ANY Database
3. View ANY Database
4. view ANY definition

Database permissions are tight TO database role RoleDbMonitoring 
(Role based Security principle:  when cloning a database permissions not tight TO a user account will not get lost)

5. SQLAgentReaderRole membership in msdb TO be able TO read SQL Server agent jobs, schedules and properties

Important notes before usage:
-----------------------------
It is advised TO run this script from SQL Server Management Studio (SSMS) 


Modification History:
---------------------
2021-06-06  t.dudink  deployed onto DB01 (only) as requested 
-- Sergey Grechko 

*/

--IMPORTANT:  Change the next line TO set:setvar SQLLogin_DBMonitoring "nutsservices\monitoring" for the right account

:setvar SQLLogin_DBMonitoring "nutsservices\svc_mssql_hc"
--:connect DB01

use [master];
if not exists (select 1 from syslogins where name = '$(SQLLogin_DBMonitoring)') 
begin
  print convert(varchar, getdate(),120) + '  ' + @@servername + ' : create login [$(SQLLogin_DBMonitoring)]';
  CREATE LOGIN [$(SQLLogin_DBMonitoring)] FROM WINDOWS WITH DEFAULT_DATABASE=[tempdb], DEFAULT_LANGUAGE=[us_english];
end;
go
if DATABASE_PRINCIPAL_ID('RoleDbMonitoring') IS NULL
begin
  print convert(varchar, getdate(),120) + '  ' + @@servername + ' : CREATE ROLE RoleDbMonitoring;';
  CREATE ROLE RoleDbMonitoring;
end;

print convert(varchar, getdate(),120) + '  ' + @@servername + ' : GRANT CONNECT TO [$(SQLLogin_DBMonitoring)]';
GRANT CONNECT sql TO [$(SQLLogin_DBMonitoring)];
go
print convert(varchar, getdate(),120) + '  ' + @@servername + ' : GRANT CONNECT ANY DATABASE [$(SQLLogin_DBMonitoring)]';
GRANT CONNECT ANY DATABASE TO [$(SQLLogin_DBMonitoring)];
go
print convert(varchar, getdate(),120) + '  ' + @@servername + ' : GRANT VIEW ANY DATABASE TO [$(SQLLogin_DBMonitoring)]';
GRANT VIEW ANY Database TO [$(SQLLogin_DBMonitoring)];
GO
print convert(varchar, getdate(),120) + '  ' + @@servername + ' : GRANT VIEW ANY DEFINITION TO [$(SQLLogin_DBMonitoring)]';
GRANT VIEW ANY DEFINITION TO [$(SQLLogin_DBMonitoring)];
GO
print convert(varchar, getdate(),120) + '  ' + @@servername + ' : GRANT VIEW SERVER STATE TO [$(SQLLogin_DBMonitoring)]';
GRANT VIEW SERVER STATE TO [$(SQLLogin_DBMonitoring)];
GO

declare @sDBname as sysname;
declare @li_rowcount as int;
declare @li_errorno as int;
declare @intDbID int;
declare @intDbIdMax int;
declare @intDatabaseId int;
declare @strDatabaseName varchar(128);
declare @tblDb table (autId int identity (1,1), intDatabaseID int, strName nvarchar(128));

declare @strSql nvarchar(4000);

---- Define working perimiter - select databases TO check
insert into @tblDb (intDatabaseID, strName)
select database_id, [name] 
from sys.databases 
where database_id > 0                          -- exclude system databases
  and [state] = 0 	                           -- database is online
  and DATABASEPROPERTYEX(name,'Updateability') = 'READ_WRITE'
  and is_auto_close_on = 0                     -- NO SUPPORT for AUTO_CLOSE = ON
;

-- First, loop through the all available databases
set @intDbID = 1;
set @intDbIdMax = (select max(autId) from @tblDb);
print 'intDbIdMax: ' + convert(varchar, @intDbIdMax);
while @intDbID <= @intDbIdMax 
begin
  -- remember the database ID of the current database
  select @intDatabaseId = intDatabaseID 
       , @strDatabaseName = strName
  from @tblDb 
  where autId = @intDbID;

    PRINT @@servername + '.' + @strDatabaseName + N' Step 1: CREATE ROLE RoleDbMonitoring';

    set @strSql = N'USE [' + @strDatabaseName + '];
	if DATABASE_PRINCIPAL_ID(''RoleDbMonitoring'') IS NULL
	begin
	  print convert(varchar, getdate(),120) + ''  '' + @@servername + ''.'' + DB_Name() + '' : CREATE ROLE RoleDbMonitoring;'';
	  CREATE ROLE RoleDbMonitoring;
	end';
	exec sp_executesql @strSql;

    PRINT @@servername + '.' + @strDatabaseName + N' Step 2: Create SQL User SQLLogin_DBMonitoring member if not exist ';
	/* Create SQL User SQLLogin_DBMonitoring member if not exist  */
    set @strSql = N'USE [' + @strDatabaseName + '];
	if not exists (select 1 from sysusers where [name] = ''$(SQLLogin_DBMonitoring)'')
	begin
		print convert(varchar, getdate(),120) + ''  '' + @@servername + ''.'' + DB_Name() + '' : CREATE USER [$(SQLLogin_DBMonitoring)] FOR LOGIN [$(SQLLogin_DBMonitoring)]'';
		CREATE USER [$(SQLLogin_DBMonitoring)] FOR LOGIN [$(SQLLogin_DBMonitoring)];
	end;';
	exec sp_executesql @strSql;

	/* Make SQLLogin_DBMonitoring member of RoleDbMonitoring role */
    PRINT @@servername + '.' + @strDatabaseName + N' Step 3: Make SQLLogin_DBMonitoring member of RoleDbMonitoring role';
    set @strSql = N'USE [' + @strDatabaseName + '];
	print convert(varchar, getdate(),121) + ''  '' + @@servername + ''.'' + DB_Name() + '' : EXEC sp_addrolemember ''''RoleDbMonitoring'''',''''$(SQLLogin_DBMonitoring)''''''
	EXECUTE sp_addrolemember @rolename = ''RoleDbMonitoring'', @membername = ''$(SQLLogin_DBMonitoring)''';
	--print @strSql;
	exec sp_executesql @strSql;
	/*

	DO NOT MAKE RoleDbMonitoring member of the db_datareader Role as it is not necessary and allowed TO read data from base tables or views!
	the exception is for (certain) tables in the master and msdb tables

	-->  least privilege principle
	-->  security data protection measure!

	*/

    PRINT @@servername + '.' + @strDatabaseName + N' Step 4:  GRANT SELECT, EXECUTE objects rights TO RoleDbMonitoring ';
	if 	@strDatabaseName = 'master'
	begin
	print 'master database'
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.master : GRANT VIEW SERVER STATE TO [$(SQLLogin_DBMonitoring)];';
		set @strSql = N'USE [' + @strDatabaseName + N']; GRANT VIEW SERVER STATE TO [$(SQLLogin_DBMonitoring)]';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.master : GRANT EXECUTE ON sp_helplogins TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + N']; GRANT EXECUTE ON sp_helplogins TO RoleDbMonitoring;'
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + '.master : GRANT EXECUTE ON sp_readErrorLog TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + N']; GRANT EXECUTE ON sp_readErrorLog TO RoleDbMonitoring;';
		exec sp_executesql @strSql;
		set @strSql = N'USE [' + @strDatabaseName + N']; GRANT SELECT ON master.sys.dm_exec_procedure_stats TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		set @strSql = N'USE [' + @strDatabaseName + N']; GRANT SELECT ON master.dbo.sysconfigures TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		set @strSql = N'USE [' + @strDatabaseName + N']; GRANT EXECUTE ON xp_msver TO RoleDbMonitoring';
		exec sp_executesql @strSql;

		print convert(varchar, getdate(),120) + '  ' + @@servername + '.' + @strDatabaseName + ' : GRANT SELECT ON sys.master_files TO RoleDbMonitoring';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON [sys].[master_files] TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(varchar, getdate(),120) + '  ' + @@servername + '.' + @strDatabaseName + ' : GRANT SELECT ON sys.configurations TO RoleDbMonitoring';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.configurations TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(varchar, getdate(),120) + '  ' + @@servername + '.' + @strDatabaseName + ' : GRANT SELECT ON sys.dm_os_performance_counters TO RoleDbMonitoring';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_os_performance_counters TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(varchar, getdate(),120) + '  ' + @@servername + '.' + @strDatabaseName + ' : GRANT SELECT ON sys.fn_virtualfilestats TO RoleDbMonitoring';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.fn_virtualfilestats TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(varchar, getdate(),120) + '  ' + @@servername + '.' + @strDatabaseName + ' : GRANT SELECT ON sys.sysperfinfo TO RoleDbMonitoring';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.sysperfinfo TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.sysprocesses TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.syscurconfigs TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.dm_db_database_page_allocations TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_db_database_page_allocations TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.dm_os_ring_buffers TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_os_ring_buffers TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.dm_os_sys_memory TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_os_sys_memory TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.master_files TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.master_files TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.dm_io_virtual_file_stats TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_io_virtual_file_stats TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.dm_exec_query_plan TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_exec_query_plan TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.dm_exec_text_query_plan TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_exec_text_query_plan TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.sysusers TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.sysusers TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.sysdatabases TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.sysdatabases TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON dm_exec_requests TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_exec_requests TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON dm_exec_sessions TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_exec_sessions TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON dm_exec_query_stats TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_exec_query_stats TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON dm_exec_sql_text TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.dm_exec_sql_text TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.fn_get_sql TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.fn_get_sql TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT EXECUTE ON sys.sp_spaceused TO RoleDbMonitoring;';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT EXECUTE ON sp_spaceused TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT EXECUTE ON sp_readErrorLog TO RoleDbMonitoring';
		GRANT EXECUTE ON sp_readErrorLog TO RoleDbMonitoring;
	end;
	if 	@strDatabaseName = 'msdb'
	begin
		print convert(varchar, getdate(),120) + '  ' + @@servername + ' : GRANT SELECT ON msdb.dbo.sysjobsteps TO RoleDbMonitoring';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON msdb.dbo.sysjobsteps TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(varchar, getdate(),120) + '  ' + @@servername + ' : GRANT SELECT ON msdb.dbo.sysjobs TO RoleDbMonitoring';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON msdb.dbo.sysjobs TO RoleDbMonitoring';
		exec sp_executesql @strSql;
		print convert(varchar, getdate(),120) + '  ' + @@servername + ' : GRANT SELECT ON msdb.dbo.sysjobhistory TO RoleDbMonitoring';
		set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON msdb.dbo.sysjobhistory TO RoleDbMonitoring';
		exec sp_executesql @strSql;
	end;
	print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.partitions TO RoleDbMonitoring;';
	set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.partitions TO RoleDbMonitoring';
	exec sp_executesql @strSql;
	print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.objects TO RoleDbMonitoring;';
	set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.objects TO RoleDbMonitoring';
	exec sp_executesql @strSql;
	print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.indexes TO RoleDbMonitoring;';
	set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.indexes TO RoleDbMonitoring';
	exec sp_executesql @strSql;
	print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.tables TO RoleDbMonitoring;';
	set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.tables TO RoleDbMonitoring';
	exec sp_executesql @strSql;
	print convert(nvarchar, getdate(),120) + N'  ' + @@servername + N'.' + @strDatabaseName + N' : GRANT SELECT ON sys.syscolumns TO RoleDbMonitoring;';
	set @strSql = N'USE [' + @strDatabaseName + ']; GRANT SELECT ON sys.syscolumns TO RoleDbMonitoring';
	exec sp_executesql @strSql;
  -- next record
  set @intDbID = @intDbID + 1;
end  -- end loop all available databases


/*
use [msdb];
go
print convert(varchar, getdate(),120) + '  ' + @@servername + '.' + DB_Name() + ' : EXEC sp_addrolemember ''SQLAgentReaderRole'',''[$(SQLLogin_DBMonitoring)]''';
EXECUTE sp_addrolemember @rolename = 'SQLAgentReaderRole', @membername = '$(SQLLogin_DBMonitoring)';
go
*/

/* print 'Print Object permissions';

use [master];
GRANT VIEW ANY DATABASE TO DBMon_Agent_User;
GRANT VIEW ANY definition TO DBMon_Agent_User;
GRANT VIEW SERVER STATE TO DBMon_Agent_User;
GRANT SELECT ON [sys].[master_files] TO DBMon_Agent_User;
GRANT EXECUTE ON sp_helplogins TO DBMon_Agent_User;
GRANT EXECUTE ON sp_readErrorLog TO DBMon_Agent_User;

use [msdb];
GRANT SELECT ON dbo.sysjobsteps  TO DBMon_Agent_User;
GRANT SELECT ON dbo.sysjobs  TO DBMon_Agent_User;
GRANT SELECT ON dbo.sysjobhistory  TO DBMon_Agent_User;
GRANT EXECUTE ON xp_msver TO DBMon_Agent_User;
GRANT EXECUTE ON sp_spaceused TO DBMon_Agent_User;
GRANT SELECT ON msdb.dbo.sysjobhistory TO DBMon_Agent_User;
*/

/*
where DBMon_Agent_User is the name of the SQL Server user account specified in Create New Collector, Connection Details, Username field. 

--Note: You can execute the statements above as a batch from a query window in Management Studio.
--Object Permissions for Monitoring SQL Server

--You can GRANT permissions individually for the following objects in order TO monitor SQL Server:
GRANT VIEW SERVER STATE TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_exec_requests TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_exec_sessions TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_os_performance_counters TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_exec_query_stats TO DBMon_Agent_User;
GRANT SELECT ON sys.fn_virtualfilestats TO DBMon_Agent_User;
GRANT SELECT ON [sys].[master_files] TO DBMon_Agent_User;
GRANT SELECT ON sys.configurations TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_exec_sql_text TO DBMon_Agent_User;
GRANT SELECT ON sys.sysperfinfo TO DBMon_Agent_User;
GRANT SELECT ON sys.sysprocesses TO DBMon_Agent_User;
GRANT SELECT ON sys.syscurconfigs TO DBMon_Agent_User;
GRANT SELECT ON sys.fn_get_sql TO DBMon_Agent_User;
GRANT SELECT ON sys.partitions TO DBMon_Agent_User;
GRANT SELECT ON sys.objects TO DBMon_Agent_User;
GRANT SELECT ON sys.indexes TO DBMon_Agent_User;
GRANT SELECT ON sys.tables TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_db_database_page_allocations TO DBMon_Agent_User;
GRANT SELECT ON master.sys.dm_exec_procedure_stats TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_os_ring_buffers TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_os_sys_memory TO DBMon_Agent_User;
GRANT SELECT ON sys.master_files TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_io_virtual_file_stats TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_exec_query_plan TO DBMon_Agent_User;
GRANT SELECT ON sys.dm_exec_text_query_plan TO DBMon_Agent_User;
GRANT SELECT ON sys.syscolumns TO DBMon_Agent_User;
GRANT SELECT ON sys.sysusers TO DBMon_Agent_User;
GRANT SELECT ON master.dbo.sysconfigures TO DBMon_Agent_User;
GRANT SELECT ON sys.sysdatabases TO DBMon_Agent_User;
*/





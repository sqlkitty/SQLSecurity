--set server if want to use sqlcmd
--:CONNECT servername 

--set this if you want to just get one group/user
DECLARE @user varchar(50) 
--SET @user = NULL --use NULL to get all users/groups, if you want only one user/group then use the next line instead 
SET @user = null --this only works for explictly named users/groups
							  --if you need to get a user's perms and they are in a group 
							  --you will first need to enumerate them with the query below 
							  --this way you can find the group they are part of to put into this variable 
/****this is for if you need to figure out a user's group on the sql server *****
DECLARE @LoginName varchar(50)
SET @LoginName = 'domain\user'
exec xp_logininfo @LoginName, 'all'
 *********/ 

DECLARE @database varchar(50) 
SET @database = NULL --use NULL to get all databases, if you want only one database then use the next line instead 
--SET @database = 'entitlement'


/** server level **/ 
select
        ServerName=@@servername, 
		spr.name as principal_name,
        spr.type_desc as principal_type,
        spm.permission_name collate SQL_Latin1_General_CP1_CI_AS as security_entity,
        'permission' as security_type,
        spm.state_desc, 
		state_desc + ' ' + permission_name collate SQL_Latin1_General_CP1_CI_AS + ' TO [' + name + '];' as script
    from sys.server_principals spr
    inner join sys.server_permissions spm
    on spr.principal_id = spm.grantee_principal_id
	WHERE spr.name = IIF(@user IS NULL, spr.name, @user)
    --where spr.type in ('s', 'u')

    union all

    select ServerName=@@servername, 
        sp.name as principal_name,
        sp.type_desc as principal_type,
        spr.name as security_entity,
        'role membership' as security_type,
        null as state_desc, 
		'ALTER SERVER ROLE ' + spr.name + ' ADD MEMBER ' +  '[' + sp.name + '];' as script
    from sys.server_principals sp
    inner join sys.server_role_members srm
    on sp.principal_id = srm.member_principal_id
    inner join sys.server_principals spr
    on srm.role_principal_id = spr.principal_id
	WHERE sp.name = IIF(@user IS NULL, sp.name, @user)
    --where sp.type in ('s', 'u')

ORDER BY principal_name

/** db roles perms**/ 
DECLARE @command varchar(4000)

SELECT @command = 'USE [?] SELECT
ServerName=@@servername, dbname=db_name(db_id()),p.name as UserName, 
p.type_desc as TypeOfLogin, pp.name as PermissionLevel, pp.type_desc as TypeOfRole, 
''USE '' + db_name(db_id()) + ''; '' + ''EXEC sp_addrolemember @rolename = '' + char(39) + pp.name + char(39) +'', @membername = ''+ char(39) + p.name + char(39) + '';'' as script
FROM sys.database_role_members roles
JOIN sys.database_principals p ON roles.member_principal_id = p.principal_id
JOIN sys.database_principals pp ON roles.role_principal_id = pp.principal_id'

DECLARE @UserPerms TABLE
(
  ServerName varchar(50), 
  dbname VARCHAR(50),
  UserName varchar(50), 
  TypeOfLogin varchar(50), 
  PermissionLevel varchar(50), 
  TypeOfRole varchar(50), 
  script varchar(max)
)

INSERT  INTO @UserPerms
EXEC sp_MSforeachdb @command

select * from @UserPerms
WHERE username = IIF(@user IS NULL, username, @user)
AND dbname = IIF(@database IS NULL, dbname, @database)
ORDER BY dbname, username, TypeOfLogin

/**db securables**/

SELECT @command = 'USE [?] 
SELECT ServerName=@@servername, ''?'' AS DB_Name, o.name as objectname,
USER_NAME(grantee_principal_id), permission_name,   
''USE '' + db_name(db_id()) + ''; '' + ''GRANT '' + permission_name + '' ON '' + ''['' + s.name collate SQL_Latin1_General_CP1_CI_AS + ''].'' + ''['' + o.name collate SQL_Latin1_General_CP1_CI_AS + '']'' + '' TO ['' + USER_NAME(grantee_principal_id) + ''];'' as script
FROM sys.database_permissions p
INNER JOIN sys.objects o
ON p.major_id = o.object_id
INNER JOIN sys.schemas s
on o.schema_id = s.schema_id
WHERE p.class = 1 AND OBJECTPROPERTY(major_id, ''IsMSSHipped'') = 0
ORDER BY OBJECT_NAME(major_id), USER_NAME(grantee_principal_id), permission_name'

DECLARE @SecurablePerms TABLE
(
  servername varchar(50),
  db_name varchar(50),
  objectname varchar(150),
  user_name VARCHAR(50),
  permission_name varchar(50), 
  script varchar(max)
)

INSERT  INTO @SecurablePerms
EXEC sp_MSforeachdb @command

select distinct * from @SecurablePerms
WHERE user_name = IIF(@user IS NULL, user_name, @user)
AND db_name = IIF(@database IS NULL, db_name, @database)


/** db types **/ 
SELECT @command = 'USE [?] SELECT
ServerName=@@servername, dbname=db_name(db_id()), u.name as UserName, 
p.permission_name as PermissionName, p.state_desc as state_desc, 
''USE '' + db_name(db_id()) + ''; '' + state_desc + '' '' + permission_name + '' ON TYPE::'' + ''['' + s.name collate SQL_Latin1_General_CP1_CI_AS + ''].'' + ''['' + t.name collate SQL_Latin1_General_CP1_CI_AS + '']'' + '' TO ['' + u.name + ''];'' as script
FROM sys.database_permissions AS p
INNER JOIN sys.database_principals AS u
  ON p.grantee_principal_id = u.principal_id
INNER JOIN sys.types AS t
  ON p.major_id = t.user_type_id--.[object_id]
INNER JOIN sys.schemas AS s
  ON t.[schema_id] = s.[schema_id]
WHERE p.class = 6; -- TYPE'

DECLARE @TypePerms TABLE
(
  ServerName varchar(50), 
  dbname VARCHAR(50),
  UserName varchar(50), 
  PermissionName varchar(50), 
  state_desc varchar(50),  
  script varchar(max)
)

INSERT  INTO @TypePerms
EXEC sp_MSforeachdb @command

select * from @TypePerms
WHERE username = IIF(@user IS NULL, username, @user)
AND dbname = IIF(@database IS NULL, dbname, @database)
ORDER BY dbname, username, state_desc


/** db schema perms **/ 
SELECT @command = 'USE [?] SELECT
ServerName=@@servername, dbname=db_name(db_id()), USER_NAME(grantee_principal_id) as UserName, 
p.permission_name as PermissionName, p.state_desc as state_desc, 
''USE '' + db_name(db_id()) + ''; '' + state_desc + '' '' + permission_name + '' ON SCHEMA::'' + ''['' + SCHEMA_NAME(major_id) collate SQL_Latin1_General_CP1_CI_AS + '']'' + '' TO ['' + u.name + ''];'' as script
FROM sys.database_permissions AS p
INNER JOIN sys.database_principals AS u
  ON p.grantee_principal_id = u.principal_id
WHERE class_desc = ''SCHEMA'';'

DECLARE @SchemaPerms TABLE
(
  ServerName varchar(50), 
  dbname VARCHAR(50),
  UserName varchar(50), 
  PermissionName varchar(50), 
  state_desc varchar(50),  
  script varchar(max)
)

INSERT  INTO @SchemaPerms
EXEC sp_MSforeachdb @command

select * from @SchemaPerms
WHERE username = IIF(@user IS NULL, username, @user)
AND dbname = IIF(@database IS NULL, dbname, @database)
ORDER BY dbname, username, state_desc



--need to fix this section to work with  my script 

/*********************************************/
/*********    MAP ORPHANED USERS     *********/
/*********************************************/

/*SELECT '-- [-- ORPHANED USERS --] --' AS [-- SQL STATEMENTS --],
4 AS [-- RESULT ORDER HOLDER --]
UNION
SELECT 'ALTER USER [' + rm.name + '] WITH LOGIN = [' + rm.name + ']',
4.1 AS [-- RESULT ORDER HOLDER --]
FROM sys.database_principals AS rm
 Inner JOIN sys.server_principals as sp
 ON rm.name = sp.name and rm.sid <> sp.sid
WHERE rm.[type] IN ('U', 'S', 'G') -- windows users, sql users, windows groups
 AND rm.name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys', 'MS_DataCollectorInternalUser')*/
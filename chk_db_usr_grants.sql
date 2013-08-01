--**********************************************
--   Oracle Check DB grants script
--**********************************************

REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REM Preamble: Setting all the necessary settings
REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

set lines 132
set pages 45
set feed off
set trimspool on

col grantee          format a22
col privilege        format a22
col obj_name         format a38
col grantor          format a18
col grantable        format a3
col object_type      format a15
col column_name      format a30

col username         format a20
col tablespace_name  format a30
col used_bytes       format 999,999,999
col max_bytes        format a15

col role_admin       format a3
col priv_admin       format a3

col through_role     format a20
col granted_role     format a20

spool db_user_grants.Log

select
   to_char(sysdate, 'mm/dd/yyyy hh24:mi:ss') 
       curr_timestamp
from
   dual
/

REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REM Section 1
REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt
prompt Roles Granted to Users
prompt ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt

select
   grantee,
   granted_role,
   admin_option,
   default_role
from
   dba_role_privs
where
   grantee not in ('SYS','SYSTEM')
order by
   grantee,
   granted_role
/

REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REM Section 2
REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

prompt
prompt Object Privileges Granted to Roles
prompt ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt

select
   p.grantee,
   p.privilege,
   o.object_type,
   p.owner||'.'||p.table_name obj_name,
   p.grantor,
   p.grantable
from
   dba_tab_privs p,
   dba_objects o
where
   grantee not in ('DBA')
and 
   grantee in 
      (select role from dba_roles)
and 
   o.owner = p.owner
and
   o.object_name = p.table_name
order by 
   p.grantee,
   p.owner,
   p.table_name,
   p.privilege
/   

REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REM Section 3
REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

prompt
prompt System Privileges Granted to Roles
prompt ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt 

select 
    grantee,
    privilege, 
    admin_option 
from 
    dba_sys_privs
where
    grantee not in ('DBA')
and
    grantee in 
      (select role from dba_roles)
order by
    grantee,
    privilege
/

REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REM Section 4
REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

prompt
prompt Object Privileges Directly Granted to Users
prompt ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt

select
   p.grantee,
   p.privilege,
   o.object_type,
   p.owner||'.'||p.table_name obj_name,
   p.grantor,
   p.grantable
from
   dba_tab_privs p,
   dba_objects o
where
   grantee not in ('SYS','SYSTEM')
and 
   grantee in 
      (select username from dba_users)
and 
   o.owner = p.owner
and
   o.object_name = p.table_name
order by 
   p.grantee,
   p.owner,
   p.table_name,
   p.privilege
/   

REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REM Section 5
REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt
prompt Object Privileges Granted to Users Through Roles
prompt ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt

select distinct
   drp.grantee                     grantee,
   rtp.privilege                   privilege,
   rtp.owner||'.'||rtp.table_name  obj_name,
   rtp.role                        through_role,
   drp.admin_option                admin_option,
   drp.default_role                defult_role
from
    role_tab_privs  rtp,
    dba_role_privs  drp,
    role_role_privs rrp
where
    drp.grantee in (select username from dba_users)
and
    drp.grantee not in ('SYS','SYSTEM')
and
(
    rtp.role = drp.granted_role
    or
    (
        rtp.role = rrp.granted_role
        and
        rrp.role = drp.granted_role
    )
   or
    (
        rtp.role = rrp.granted_role
        and 
        rrp.role = drp.granted_role
    )
)
and rtp.role not in
    (
       'SELECT_CATALOG_ROLE',
       'IMP_FULL_DATABASE',
       'EXP_FULL_DATABASE',
       'DBA',
       'XDBADMIN',
       'EXECUTE_CATALOG_ROLE'
    )
/

REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REM Section 6
REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt
prompt Privileges on Columns of Tables Granted
prompt ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt 

select
   grantee,
   owner||'.'||table_name obj_name, 
   column_name, 
   grantor, 
   privilege, 
   grantable
from 
   dba_col_privs
where
   grantee not in ('SYS','SYSTEM')
order by 
   grantee,
   owner,
   table_name,
   column_name,
   privilege
/

REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REM Section 7
REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt
prompt System Privileges Granted to Users 
prompt ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt 

select 
    grantee,
    privilege, 
    admin_option 
from 
    dba_sys_privs
where
    grantee not in ('SYS','SYSTEM')
and
    grantee in 
      (select username from dba_users)
order by
    grantee,
    privilege
/

REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REM Section 8
REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt
prompt System Privileges Granted to Users Through Roles
prompt ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt

select distinct 
    d.grantee         grantee,
    p.role            through_role,
    p.privilege       privilege,
    d.admin_option,
    d.default_role
from
    role_sys_privs p,
    dba_role_privs d,
    role_role_privs r
where
    d.grantee in
       (select username from dba_users)
and
    d.grantee not in ('SYS','SYSTEM')
and
(
    p.role = d.granted_role
    or
    (
        p.role = r.granted_role
        and
        r.role = d.granted_role
    )
)
and p.role not in
    (
       'SELECT_CATALOG_ROLE',
       'IMP_FULL_DATABASE',
       'EXP_FULL_DATABASE',
       'DBA',
       'XDBADMIN',
       'EXECUTE_CATALOG_ROLE'
    )
/

REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REM Section 9
REM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt
prompt Quota on Tablespaces Granted to Users 
prompt ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
prompt 

select
   username,
   tablespace_name,
   bytes used_bytes,
   decode(max_bytes,-1,'UNLIMITED',
      to_char(max_bytes,'999,999,999.999')) 
          max_bytes
from
   dba_ts_quotas
where
   username not in ('SYS','SYSTEM')
order
   by username,
   tablespace_name
/

spool off

set linesize 130
set pagesize 56
set feedback on

select 'Audit_2010_db_' || name || '_' || to_char(sysdate,'DDMonYYYY_hh24_mi') || '.log' as sqlfile
from v$database;

spool &&sqlfile

select instance_name from v$instance
;

column owner format a12
column object_name format a50
alter session set nls_date_format = 'MM/DD/YYYY HH24:MI';

column username format a15
column password format a20
column profile format a17
column status format a10
column default_tablespace format a20
column temporary_tablespace format a20

select username,password,profile,account_status "Status",created,default_tablespace,temporary_tablespace
from dba_users;

select * from dba_roles;

select * from dba_profiles order by 1;

select * from dba_users;

spool off

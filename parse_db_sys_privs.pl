#===========================================
#Parse output from db_user_grants SQL script
#===========================================
use warnings;
use strict;

#=========================================
my $out_dir = "E:\\Portable Apps\\Documents\\Code\\Liz_Oracle\\output\\";
my $file = "E:\\Portable Apps\\Documents\\code\\Liz_Oracle\\files\\chk_db_usr_grants_RAMSPRD_21Jul2011_11_27.log";
my $db = "RAMSPRD";
#=========================================
my $rpt = 0;
my %object_privs;
my %system_privs;
my %role_members;
my %role_obj_privs;
my %role_sys_privs;
my %objp_access;
my %sysp_access;
my %priveleges_on_columns_of_tables_granted;
my %objects;

my($sec,$min,$hr,$day,$mon,$yr,$wkday,$dayofyr,$isdst) = localtime(time);
$mon += 1;
$yr += 1900;
my $ts = "$mon" . "." . "$day" . "." . "$yr" . "." . "$hr" . "." . "$min" . "." . "$sec";

open LOG, ">" . $out_dir . "LOG_parse_db_user_grants_" . $ts . ".log"
	or die "Can't open the log file: $!\n";
	
open FILE, $file or die "Can't open the file: $!\n";
while (<FILE>)
{
	chomp;
	my $line = $_;
	next if $line =~ /^(\s)*$/;
	$line =~ s/^\s+//;
	$line =~ s/\s+$//;
	
	#set the flag for report type when report headers are encountered
	#see the SQL script to see the references to the numbered sections (1-8)
	if ($line eq "Roles Granted to Users")
	{
		$rpt = 1;
	}
	elsif ($line eq "Object Privileges Granted to Roles")
	{
		$rpt = 2;
	}
	elsif ($line eq "System Privileges Granted to Roles")
	{
		$rpt = 3;
	}
	elsif ($line eq "Object Privileges Directly Granted to Users")
	{
		$rpt = 4;
	}
	elsif ($line eq "Object Privileges Granted to Users Through Roles")
	{
		$rpt = 5;
	}
	elsif ($line eq "Privileges on Columns of Tables Granted")
	{
		$rpt = 6;
	}
	elsif ($line eq "System Privileges Granted to Users")
	{
		$rpt = 7;
	}
	elsif ($line eq "System Privileges Granted to Users Through Roles") 
	{
		$rpt = 8;		
	}
	
	
	if ($rpt == 4)
	{
		#output from: 
		#Object Privileges Directly Granted to Users
		#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		#select
		#     p.grantee,
		#     p.privilege,
		#     o.object_type,
		#     p.owner||'.'||p.table_name obj_name,
		#     p.grantor,
		#     p.grantable
        #from
		#     dba_tab_privs p,
		#     dba_objects o
		#where
		#     grantee not in ('SYS','SYSTEM') and 
		#     grantee in (select username from dba_users) and 
		#     o.owner = p.owner and
		#     o.object_name = p.table_name
		#order by 
		#     p.grantee,
		#     p.owner,
		#     p.table_name,
		#     p.privilege
		#/   
		next if $line eq "Object Privileges Directly Granted to Users";
		my($grantee,$privilege,$object_type,$obj_name,$grantor,$grantable) = split /\|/, $line;
		next if $grantee =~ /^GRANTEE.*$/;
		next if $grantee =~ /^-+/;
		next if $grantee =~ /^~+/;
	    
		#skip line spill overs
		unless ($grantee && $privilege && $object_type && $obj_name && $grantor && $grantable)
		{
			print LOG "$.: $line\n";
			next;
		}
		
		$grantee =~ s/^\s+//;
		$grantee =~ s/\s+$//;
		$privilege =~ s/^\s+//;
		$privilege =~ s/\s+$//;
		$object_type =~ s/^\s+//;
		$object_type =~ s/\s+$//;
		$obj_name =~ s/^\s+//;
		$obj_name =~ s/\s+$//;
		$grantor =~ s/^\s+//;
		$grantor =~ s/\s+$//;
		$grantable =~ s/^\s+//;
		$grantable =~ s/\s+$//;
		
		#filter
		next if ($obj_name =~ /^DEVELOPER.*$/i) ;
		next if ($privilege =~ /SELECT/i);
		
		#store
		$objp_access{$grantee}->{$obj_name}->{$privilege}->{through_user} = "$grantor|$grantable";
		$objp_access{$grantee}->{$obj_name}->{$privilege}->{through_role} = "no";
		
		#obj type storages
		$objects{$obj_name}->{type} = $object_type;
	}
	elsif ($rpt == 5)
	{
		#output from: 
		#Object Privileges Granted to Users Through Roles
		#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		#select distinct
		#     drp.grantee  grantee,
		#     rtp.privilege privilege,
        #     rtp.owner||'.'||rtp.table_name  obj_name,
        #     rtp.role  through_role,
        #     drp.admin_option  admin_option,
        #     drp.default_role  defult_role
        #from
        #     role_tab_privs  rtp,
        #     dba_role_privs  drp,
        #     role_role_privs rrp
        #where
        #     drp.grantee in (select username from dba_users) and
        #     drp.grantee not in ('SYS','SYSTEM') and
        #     (rtp.role = drp.granted_role or (rtp.role = rrp.granted_role and rrp.role = drp.granted_role) or 
		#     (rtp.role = rrp.granted_role and rrp.role = drp.granted_role)) and 
		#     rtp.role not in (
        #                      'SELECT_CATALOG_ROLE',
        #                      'IMP_FULL_DATABASE',
        #                      'EXP_FULL_DATABASE',
        #                      'DBA',
        #                      'XDBADMIN',
        #                      'EXECUTE_CATALOG_ROLE'
        #                                            )
        #/
		next if $line eq "Object Privileges Granted to Users Through Roles";
		my($grantee,$privilege,$obj_name,$through_role,$adm,$def) = split /\|/, $line;
		next if $grantee =~ /^GRANTEE.*$/;
		next if $grantee =~ /^-+/;
		next if $grantee =~ /^~+/;
	    
		#skip line spill overs
		unless ($grantee && $privilege && $obj_name && $through_role && $adm && $def)
		{
			print LOG "$.: $line\n";
			next;
		}
		
		$grantee =~ s/^\s+//;
		$grantee =~ s/\s+$//;
		$privilege =~ s/^\s+//;
		$privilege =~ s/\s+$//;
		$obj_name =~ s/^\s+//;
		$obj_name =~ s/\s+$//;
		$through_role =~ s/^\s+//;
		$through_role =~ s/\s+$//;
		$adm =~ s/^\s+//;
		$adm =~ s/\s+$//;
		$def =~ s/^\s+//;
		$def =~ s/\s+$//;
		
		#filter
		next if ($obj_name =~ /^DEVELOPER.*$/i) ;
		next if ($privilege =~ /SELECT/i);
				
		#store
		$objp_access{$grantee}->{$obj_name}->{$privilege}->{through_user} = "no";
		$objp_access{$grantee}->{$obj_name}->{$privilege}->{through_role} = "$through_role|$adm|$def";
	}
	elsif ($rpt == 7)
	{
		#output from: 
		#System Privileges Granted to Users 
		#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		#select 
		#     grantee,
        #     privilege, 
		#     admin_option 
		#from 
		#     dba_sys_privs
		#where
		#     grantee not in ('SYS','SYSTEM') and
		#     grantee in (select username from dba_users)
		#order by
		#     grantee,
		#     privilege
		#/
		next if $line eq "System Privileges Granted to Users";
		my($grantee,$privilege,$adm) = split /\|/, $line;
		next if $grantee =~ /^GRANTEE.*$/;
		next if $grantee =~ /^-+/;
		next if $grantee =~ /^~+/;
	    
		#skip line spill overs
		unless ($grantee && $privilege && $adm)
		{
			print LOG "$.: $line\n";
			next;
		}
		
		$grantee =~ s/^\s+//;
		$grantee =~ s/\s+$//;
		$privilege =~ s/^\s+//;
		$privilege =~ s/\s+$//;
		$adm =~ s/^\s+//;
		$adm =~ s/\s+$//;
		
		#store
		$sysp_access{$grantee}->{$privilege}->{through_user} = "$adm";
		$sysp_access{$grantee}->{$privilege}->{through_role} = "no";
	}
	elsif ($rpt == 8)
	{
		#output from: 
		#System Privileges Granted to Users Through Roles
		#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		#select distinct 
        #     d.grantee  grantee,
		#     p.role  through_role,
		#     p.privilege  privilege,
		#     d.admin_option,
		#     d.default_role
		#from
		#     role_sys_privs p,
		#     dba_role_privs d,
		#     role_role_privs r
		#where
		#     d.grantee in (select username from dba_users) and
		#     d.grantee not in ('SYS','SYSTEM') and 
		#     (p.role = d.granted_role or (p.role = r.granted_role and r.role = d.granted_role) ) and 
		#     p.role not in (
        #                    'SELECT_CATALOG_ROLE',
        #                    'IMP_FULL_DATABASE',
        #                    'EXP_FULL_DATABASE',
        #                    'DBA',
        #                    'XDBADMIN',
        #                    'EXECUTE_CATALOG_ROLE'
        #                                           )
        #/
		next if $line eq "System Privileges Granted to Users Through Roles";
		my($grantee,$through_role,$privilege,$adm,$def) = split /\|/, $line;
		next if $grantee =~ /^GRANTEE.*$/;
		next if $grantee =~ /^-+/;
		next if $grantee =~ /^~+/;
	    
		#skip line spill overs
		unless ($grantee && $through_role && $privilege && $adm && $def)
		{
			print LOG "$.: $line\n";
			next;
		}
		
		$grantee =~ s/^\s+//;
		$grantee =~ s/\s+$//;
		$through_role =~ s/^\s+//;
		$through_role =~ s/\s+$//;
		$privilege =~ s/^\s+//;
		$privilege =~ s/\s+$//;
		$adm =~ s/^\s+//;
		$adm =~ s/\s+$//;
		$def =~ s/^\s+//;
		$def =~ s/\s+$//;
		
		#store
		$sysp_access{$grantee}->{$privilege}->{through_user} = "no";
		$sysp_access{$grantee}->{$privilege}->{through_role} = "$through_role|$adm|$def";
	}
}

close FILE;
close LOG;
		
#output system privileges
open OUT, ">$out_dir\\" . $db . "_system_privs.txt" or die "Can't open the output file: $!\n";
print OUT "Database|Grantee|Privilege|Through?|Through Role|Admin|Default\n";
for my $grantee (sort keys %sysp_access)
{
	for my $privilege ( sort keys %{ $sysp_access{$grantee} } )
	{	
		if ( $sysp_access{$grantee}->{$privilege}->{through_role} eq "no" )
		{
			#through user
			print OUT "$db|$grantee|$privilege|through_user|n/a|$sysp_access{$grantee}->{$privilege}->{through_user}|n/a\n";
		}
		elsif ( $sysp_access{$grantee}->{$privilege}->{through_user} eq "no" )
		{
			#through role
			print OUT "$db|$grantee|$privilege|through_role|";
			my($role,$adm,$def) = split/\|/, $sysp_access{$grantee}->{$privilege}->{through_role};
			unless ($role) { $role = "-"; }
			unless ($adm) { $adm = "-"; }
			unless ($def) { $def = "-"; }
			print OUT "$role|$adm|$def\n";
		}
	}
}

close OUT;
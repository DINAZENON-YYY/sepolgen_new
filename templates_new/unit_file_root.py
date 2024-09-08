# Copyright (C) 2012 Red Hat
# see file 'COPYING' for use and warranty information
#
# policygentool is a tool for the initial generation of SELinux policy
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License as
#    published by the Free Software Foundation; either version 2 of
#    the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
#                                        02111-1307  USA
#
#
########################### unit Template File #############################

########################### Type Enforcement File #############################
te_types="""
type CUSTOMTYPE;
systemd_unit_file(CUSTOMTYPE)
"""

te_rules=""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	Execute TEMPLATETYPE server in the TEMPLATETYPE domain.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed to transition.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_systemctl',`
	gen_require(`
		type TEMPLATETYPE_t;
		type CUSTOMTYPE;
	')

	systemd_exec_systemctl($1)
        systemd_read_fifo_file_passwd_run($1)
	allow $1 CUSTOMTYPE:file read_file_perms;
	allow $1 CUSTOMTYPE:service manage_service_perms;

	ps_process_pattern($1, TEMPLATETYPE_t)
')

"""

if_admin_types="""
	type CUSTOMTYPE;"""

if_admin_rules="""
	TEMPLATETYPE_systemctl($1)
	admin_pattern($1, CUSTOMTYPE)
	allow $1 CUSTOMTYPE:service all_service_perms;
"""

########################### File Context ##################################
fc_file="""\
FILENAME		--	gen_context(system_u:object_r:CUSTOMTYPE,s0)
"""

fc_dir=""

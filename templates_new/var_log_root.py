# Copyright (C) 2007-2012 Red Hat
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
########################### var_log Template File #############################

########################### Type Enforcement File #############################
te_types="""
type CUSTOMTYPE;
logging_log_file(CUSTOMTYPE)
"""

te_rules="""
manage_dirs_pattern(TEMPLATETYPE_t, CUSTOMTYPE, CUSTOMTYPE)
manage_files_pattern(TEMPLATETYPE_t, CUSTOMTYPE, CUSTOMTYPE)
manage_lnk_files_pattern(TEMPLATETYPE_t, CUSTOMTYPE, CUSTOMTYPE)
logging_log_filetrans(TEMPLATETYPE_t, CUSTOMTYPE, { dir file lnk_file })
"""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	Read TEMPLATETYPE's log files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <rolecap/>
#
interface(`TEMPLATETYPE_read_log',`
	gen_require(`
		type CUSTOMTYPE;
	')

	logging_search_logs($1)
	read_files_pattern($1, CUSTOMTYPE, CUSTOMTYPE)
')

########################################
## <summary>
##	Append to TEMPLATETYPE log files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_append_log',`
	gen_require(`
		type CUSTOMTYPE;
	')

	logging_search_logs($1)
	append_files_pattern($1, CUSTOMTYPE, CUSTOMTYPE)
')

########################################
## <summary>
##	Manage TEMPLATETYPE log files
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_log',`
	gen_require(`
		type CUSTOMTYPE;
	')

	logging_search_logs($1)
	manage_dirs_pattern($1, CUSTOMTYPE, CUSTOMTYPE)
	manage_files_pattern($1, CUSTOMTYPE, CUSTOMTYPE)
	manage_lnk_files_pattern($1, CUSTOMTYPE, CUSTOMTYPE)
')
"""

if_admin_types="""
		type CUSTOMTYPE;"""

if_admin_rules="""
	logging_search_logs($1)
	admin_pattern($1, CUSTOMTYPE)
"""

########################### File Context ##################################
fc_file="""\
FILENAME		--	gen_context(system_u:object_r:CUSTOMTYPE,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:CUSTOMTYPE,s0)
"""

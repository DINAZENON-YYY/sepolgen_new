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
type event_device_t;
"""

te_rules="""
dev_read_input(TEMPLATETYPE_t)
"""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	Automatic type transition to the type
##	for event device nodes when created in /dev.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <param name="name" optional="true">
##	<summary>
##	The name of the object being created.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_filetrans_input_dev',`
	gen_require(`
		type TEMPLATETYPE_t, event_device_t;
	')

	filetrans_pattern($1, TEMPLATETYPE_t, event_device_t, chr_file, $2)
')

########################################
## <summary>
##	Get the attributes of the event devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_getattr_input_dev',`
	gen_require(`
		type TEMPLATETYPE_t, event_device_t;
	')

	allow $1 TEMPLATETYPE_t:dir list_dir_perms;
	allow $1 event_device_t:chr_file getattr;
')

########################################
## <summary>
##	Set the attributes of the event devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_setattr_input_dev',`
	gen_require(`
		type TEMPLATETYPE_t, event_device_t;
	')

	allow $1 TEMPLATETYPE_t:dir list_dir_perms;
	allow $1 event_device_t:chr_file setattr;
')

########################################
## <summary>
##	Read input event devices (/dev/input).
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_read_input',`
	gen_require(`
		type TEMPLATETYPE_t, event_device_t;
	')

	read_chr_files_pattern($1, TEMPLATETYPE_t, event_device_t)
')

########################################
## <summary>
##	Read and write input event devices (/dev/input).
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_rw_input_dev',`
	gen_require(`
		type TEMPLATETYPE_t, event_device_t;
	')

	rw_chr_files_pattern($1, TEMPLATETYPE_t, event_device_t)
')

########################################
## <summary>
##	Create, read, write, and delete input event devices (/dev/input).
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_input_dev',`
	gen_require(`
		type TEMPLATETYPE_t, event_device_t;
	')

	manage_chr_files_pattern($1, TEMPLATETYPE_t, event_device_t)
')

########################################
## <summary>
##	IOCTL the input event devices (/dev/input).
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_ioctl_input_dev',`
	gen_require(`
		type event_device_t;
	')

	allow $1 event_device_t:chr_file ioctl;
')

"""

if_admin_types="""
		type TEMPLATETYPE_log_t;"""

if_admin_rules="""
	logging_search_logs($1)
	admin_pattern($1, TEMPLATETYPE_log_t)
"""

########################### File Context ##################################
fc_file="""\
FILENAME		--	gen_context(system_u:object_r:event_device_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:event_device_t,s0)
"""

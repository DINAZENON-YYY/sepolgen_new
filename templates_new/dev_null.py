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
########################### dev_null Template File #############################

########################### Type Enforcement File #############################
te_types="""
type null_device_t;
"""

te_rules="""
allow TEMPLATETYPE_t null_device_t:chr_file { getattr open read write };
"""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	Get the attributes of the null device nodes.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_getattr_null_dev',`
	gen_require(`
		type TEMPLATETYPE_t, null_device_t;
	')

	getattr_chr_files_pattern($1, TEMPLATETYPE_t, null_device_t)
')

########################################
## <summary>
##	Set the attributes of the null device nodes.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_setattr_null_dev',`
	gen_require(`
		type TEMPLATETYPE_t, null_device_t;
	')

	setattr_chr_files_pattern($1, TEMPLATETYPE_t, null_device_t)
')

########################################
## <summary>
##	Do not audit attempts to set the attributes of
##	the null device nodes.
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_dontaudit_setattr_null_dev',`
	gen_require(`
		type null_device_t;
	')

	dontaudit $1 null_device_t:chr_file setattr;
')

########################################
## <summary>
##	Delete the null device (/dev/null).
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_delete_null',`
	gen_require(`
		type TEMPLATETYPE_t, null_device_t;
	')

	delete_chr_files_pattern($1, TEMPLATETYPE_t, null_device_t)
')

########################################
## <summary>
##	Read and write to the null device (/dev/null).
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_rw_null',`
	gen_require(`
		type TEMPLATETYPE_t, null_device_t;
	')

	rw_chr_files_pattern($1, TEMPLATETYPE_t, null_device_t)
')

########################################
## <summary>
##	Create the null device (/dev/null).
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_create_null_dev',`
	gen_require(`
		type TEMPLATETYPE_t, null_device_t;
	')

	create_chr_files_pattern($1, TEMPLATETYPE_t, null_device_t)
')

########################################
## <summary>
##     Manage services with script type null_device_t for when
##     /lib/systemd/system/something.service is a link to /dev/null
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_null_service',`
	gen_require(`
		type null_device_t;
		class service { reload start status stop };
	')

	allow $1 null_device_t:service { reload start status stop};
')

"""

if_admin_types="""
		type TEMPLATETYPE_t;"""

if_admin_rules="""
	admin_pattern($1, TEMPLATETYPE_t)
"""

########################### File Context ##################################
fc_file="""\
FILENAME		--	gen_context(system_u:object_r:null_device_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:null_device_t,s0)
"""

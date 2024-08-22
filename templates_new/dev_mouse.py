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
attribute device_node;

type device_t;
type mouse_device_t;
dev_node(mouse_device_t)
"""

te_rules="""
allow device_node device_t:filesystem associate;

fs_associate(device_node)
fs_associate_tmpfs(device_node)

files_associate_tmp(device_node)
"""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	Get the attributes of the mouse devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`dev_getattr_mouse_dev',`
	gen_require(`
		type device_t, mouse_device_t;
	')

	getattr_chr_files_pattern($1, device_t, mouse_device_t)
')

########################################
## <summary>
##	Set the attributes of the mouse devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`dev_setattr_mouse_dev',`
	gen_require(`
		type device_t, mouse_device_t;
	')

	setattr_chr_files_pattern($1, device_t, mouse_device_t)
')

########################################
## <summary>
##	Delete the mouse devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`dev_delete_mouse_dev',`
	gen_require(`
		type device_t, mouse_device_t;
	')

	delete_chr_files_pattern($1, device_t, mouse_device_t)
')

########################################
## <summary>
##	Read the mouse devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`dev_read_mouse',`
	gen_require(`
		type device_t, mouse_device_t;
	')

	read_chr_files_pattern($1, device_t, mouse_device_t)
')

########################################
## <summary>
##	Read and write to mouse devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`dev_rw_mouse',`
	gen_require(`
		type device_t, mouse_device_t;
	')

	rw_chr_files_pattern($1, device_t, mouse_device_t)
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
FILENAME		--	gen_context(system_u:object_r:mouse_device_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:mouse_device_t,s0)
"""

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
type printer_device_t;
"""

te_rules="""
dev_rw_printer(TEMPLATETYPE_t)
kernel_request_load_module(TEMPLATETYPE_t)
"""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	Get the attributes of the printer device nodes.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_getattr_printer_dev',`
	gen_require(`
		type TEMPLATETYPE_t, printer_device_t;
	')

	getattr_chr_files_pattern($1, TEMPLATETYPE_t, printer_device_t)
')

########################################
## <summary>
##	Set the attributes of the printer device nodes.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_setattr_printer_dev',`
	gen_require(`
		type TEMPLATETYPE_t, printer_device_t;
	')

	setattr_chr_files_pattern($1, TEMPLATETYPE_t, printer_device_t)
')

########################################
## <summary>
##	Append the printer device.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
# cjp: added for lpd/checkpc_t
interface(`TEMPLATETYPE_append_printer',`
	gen_require(`
		type TEMPLATETYPE_t, printer_device_t;
	')

	append_chr_files_pattern($1, TEMPLATETYPE_t, printer_device_t)
')

########################################
## <summary>
##	Read and write the printer device.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_rw_printer',`
	gen_require(`
		type TEMPLATETYPE_t, printer_device_t;
	')

	rw_chr_files_pattern($1, TEMPLATETYPE_t, printer_device_t)
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
FILENAME		--	gen_context(system_u:object_r:printer_device_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:printer_device_t,s0)
"""

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
type usb_device_t;
"""

te_rules="""
allow TEMPLATETYPE_t self:netlink_kobject_uevent_socket { bind create getattr read setopt };
dev_list_sysfs(TEMPLATETYPE_t)
dev_read_sysfs(TEMPLATETYPE_t)
dev_rw_generic_usb_dev(TEMPLATETYPE_t)
term_use_ptmx(TEMPLATETYPE_t)
udev_read_db(TEMPLATETYPE_t)
udev_search_pids(TEMPLATETYPE_t)
"""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	Getattr generic the USB devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_getattr_generic_usb_dev',`
	gen_require(`
		type usb_device_t, TEMPLATETYPE_t;
	')

	getattr_chr_files_pattern($1, TEMPLATETYPE_t, usb_device_t)
')

########################################
## <summary>
##	Setattr generic the USB devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_setattr_generic_usb_dev',`
	gen_require(`
		type usb_device_t, TEMPLATETYPE_t;
	')

	setattr_chr_files_pattern($1, TEMPLATETYPE_t, usb_device_t)
')

########################################
## <summary>
##	Read generic the USB devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_read_generic_usb_dev',`
	gen_require(`
		type usb_device_t, TEMPLATETYPE_t;
	')

	read_chr_files_pattern($1, TEMPLATETYPE_t, usb_device_t)
')

########################################
## <summary>
##	Read and write generic the USB devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_rw_generic_usb_dev',`
	gen_require(`
		type TEMPLATETYPE_t, usb_device_t;
	')

	rw_chr_files_pattern($1, TEMPLATETYPE_t, usb_device_t)
')

########################################
## <summary>
##	Delete the generic USB devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_delete_generic_usb_dev',`
	gen_require(`
		type TEMPLATETYPE_t, usb_device_t;
	')

	delete_chr_files_pattern($1, TEMPLATETYPE_t, usb_device_t)
')

########################################
## <summary>
##	Relabel generic the USB devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_relabel_generic_usb_dev',`
	gen_require(`
		type usb_device_t, TEMPLATETYPE_t;
	')

	relabel_chr_files_pattern($1, TEMPLATETYPE_t, usb_device_t)
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
FILENAME		--	gen_context(system_u:object_r:usb_device_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:usb_device_t,s0)
"""
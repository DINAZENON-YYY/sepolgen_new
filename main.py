#!/usr/bin/python3 -Es

import signal
import string
import os
import sys
try:
    import sepolicy
except ValueError as e:
    sys.stderr.write("%s: %s\n" % (e.__class__.__name__, str(e)))
    sys.exit(1)
"""
import sepolicy.sepolicy.generate
import sepolicy.sepolicy.interface
"""

import sepolicy.generate
import sepolicy.interface

try:
    from subprocess import getstatusoutput
except ImportError:
    from commands import getstatusoutput


import re

"""
该函数通过调用getstatusoutput函数执行semodule -l 2>/dev/null命令，获取所有安全模块的列表。
然后对输出结果进行处理，将每行的第0个元素（即模块名称）添加到all_modules列表中。
如果出现异常，则捕获异常并忽略。最后返回all_modules列表。
"""
def get_all_modules():
    try:
        all_modules = []
        rc, output = getstatusoutput("semodule -l 2>/dev/null")
        if rc == 0:
            l = output.split("\n")
            for i in l:
                all_modules.append(i.split()[0])
    except:
        pass

    return all_modules

# 将两个路径添加到Python的系统路径
sys.path.append('/usr/share/system-config-selinux')
sys.path.append('.')

"""
该函数用于遍历模型中的数据。
其中，model为模型对象，path为节点路径，iter为当前节点的迭代器，selected为已选中数据的列表。
函数通过调用model.get_value(iter, 0)方法，将当前节点的第0个值添加到selected列表中。
"""
def foreach(model, path, iter, selected):
    selected.append(model.get_value(iter, 0))

FILE = 1
DIR = 2

class PolGenerator:
    def __init__(self, filename : string):
        """
        # 以下应该不需要
        self.label_dict = {}
        self.tooltip_dict = {}

        #label = xml.get_object("select_label")
        self.label_dict["select_label"] = []

        # label = xml.get_object("select_user_roles_label")
        self.label_dict["select_user_roles_label"] = []

        # label = xml.get_object("select_dir_label")
        self.label_dict["select_dir_label"] = []

        # label = xml.get_object("select_domain_admin_label")
        self.label_dict["select_domain_admin_label"] = []

        # label = xml.get_object("select_in_label")
        self.label_dict["select_in_label"] = []

        # label = xml.get_object("select_out_label")
        self.label_dict["select_out_label"] = []

        # label = xml.get_object("select_common_label")
        self.label_dict["select_common_label"] = []

        # label = xml.get_object("select_manages_label")
        self.label_dict["select_manages_label"] = []

        # label = xml.get_object("select_booleans_label")
        self.label_dict["select_booleans_label"] = []

        # tooltip文本用作辅助功能，可能不需要
        # label = xml.get_object("existing_user_treeview")
        self.tooltip_dict["existing_user_treeview"] = []

        # label = xml.get_object("transition_treeview")
        self.tooltip_dict["transition_treeview"] = []

        # label = xml.get_object("in_tcp_all_checkbutton")
        self.tooltip_dict["in_tcp_all_checkbutton"] = []

        # label = xml.get_object("in_tcp_reserved_checkbutton")
        self.tooltip_dict["in_tcp_reserved_checkbutton"] = []

        # label = xml.get_object("in_tcp_unreserved_checkbutton")
        self.tooltip_dict["in_tcp_unreserved_checkbutton"] = []

        # label = xml.get_object("in_tcp_entry")
        self.tooltip_dict["in_tcp_entry"] = []

        # label = xml.get_object("in_udp_all_checkbutton")
        self.tooltip_dict["in_udp_all_checkbutton"] = []

        # label = xml.get_object("in_udp_reserved_checkbutton")
        self.tooltip_dict["in_udp_reserved_checkbutton"] = []

        # label = xml.get_object("in_udp_unreserved_checkbutton")
        self.tooltip_dict["in_udp_unreserved_checkbutton"] = []

        # label = xml.get_object("in_udp_entry")
        self.tooltip_dict["in_udp_entry"] = []

        # label = xml.get_object("out_tcp_entry")
        self.tooltip_dict["out_tcp_entry"] = []

        # label = xml.get_object("out_udp_entry")
        self.tooltip_dict["out_udp_entry"] = []

        # label = xml.get_object("out_tcp_all_checkbutton")
        self.tooltip_dict["out_tcp_all_checkbutton"] = []

        # label = xml.get_object("out_udp_all_checkbutton")
        self.tooltip_dict["out_udp_all_checkbutton"] = []

        # label = xml.get_object("boolean_treeview")
        self.tooltip_dict["boolean_treeview"] = []

        # label = xml.get_object("write_treeview")
        self.tooltip_dict["write_treeview"] = []
        """

        self.name = ""
        self.exec_path = ""
        self.store = []
        self.file_store = []
        self.dir_store = []
        self.output_path = ""
        self.info = ""

        try:
            self.all_types = sepolicy.generate.get_all_types()
            self.all_modules = get_all_modules()
            self.all_roles = sepolicy.generate.get_all_roles()
            self.all_users = sepolicy.generate.get_all_users()
        except RuntimeError as e:
            self.all_types = []
            self.all_modules = []
            self.all_roles = []
            self.all_users = []
            raise RuntimeError(e)

        """
        模板对应步骤，需要哪些资源
        self.pages = {}
        # USERS = [ XUSER, TUSER, LUSER, AUSER, RUSER]
        for i in sepolicy.generate.USERS:
            self.pages[i] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.TRANSITION_PAGE, self.ROLE_PAGE,
                             self.IN_NET_PAGE, self.OUT_NET_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]
        self.pages[sepolicy.generate.RUSER] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.ADMIN_PAGE,
                                               self.USER_TRANSITION_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]
        self.pages[sepolicy.generate.LUSER] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.TRANSITION_PAGE,
                                               self.IN_NET_PAGE, self.OUT_NET_PAGE, self.BOOLEAN_PAGE,
                                               self.SELECT_DIR_PAGE]
        self.pages[sepolicy.generate.SANDBOX] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.IN_NET_PAGE,
                                                 self.OUT_NET_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]
        self.pages[sepolicy.generate.EUSER] = [self.SELECT_TYPE_PAGE, self.EXISTING_USER_PAGE, self.TRANSITION_PAGE,
                                               self.ROLE_PAGE, self.IN_NET_PAGE, self.OUT_NET_PAGE, self.BOOLEAN_PAGE,
                                               self.SELECT_DIR_PAGE]

        # APPLICATIONS = [ DAEMON, DBUS, INETD, USER, CGI ]
        for i in sepolicy.generate.APPLICATIONS:
            self.pages[i] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.IN_NET_PAGE, self.OUT_NET_PAGE,
                             self.COMMON_APPS_PAGE, self.FILES_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]
        self.pages[sepolicy.generate.USER] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.USER_TRANSITION_PAGE,
                                              self.IN_NET_PAGE, self.OUT_NET_PAGE, self.COMMON_APPS_PAGE,
                                              self.FILES_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]

        self.current_page = 0
        self.back_button.set_sensitive(0)
        """


        """
        网络接口信息,可扩展
        """
        self.network_info = {}

        self.in_tcp_all = False
        self.in_tcp_entry = ""
        self.network_info["in_tcp_info"] = [self.in_tcp_all, self.in_tcp_entry]

        self.out_tcp_all = False
        self.out_tcp_entry = ""
        self.network_info["out_tcp_info"] = [self.out_tcp_all, self.out_tcp_entry]

        self.in_udp_all = False
        self.in_udp_entry = ""
        self.network_info["in_udp_info"] = [self.in_udp_all, self.in_udp_entry]

        self.out_udp_all = False
        self.out_udp_entry = ""
        self.network_info["out_udp_info"] = [self.out_udp_all, self.out_udp_entry]


        """
        转换相关
        
        boolean 两列 name description
        self.boolean_treeview = self.xml.get_object("boolean_treeview")
        self.boolean_store = Gtk.ListStore(GObject.TYPE_STRING, GObject.TYPE_STRING)
        self.boolean_treeview.set_model(self.boolean_store)
        self.boolean_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Name"), Gtk.CellRendererText(), text=0)
        self.boolean_treeview.append_column(col)
        col = Gtk.TreeViewColumn(_("Description"), Gtk.CellRendererText(), text=1)
        self.boolean_treeview.append_column(col)
        
        role 一列 role
        self.role_treeview = self.xml.get_object("role_treeview")
        self.role_store = Gtk.ListStore(GObject.TYPE_STRING)
        self.role_treeview.set_model(self.role_store)
        self.role_treeview.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
        self.role_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Role"), Gtk.CellRendererText(), text=0)
        self.role_treeview.append_column(col)
        
        existing_user 一列 Existing_user
        self.existing_user_treeview = self.xml.get_object("existing_user_treeview")
        self.existing_user_store = Gtk.ListStore(GObject.TYPE_STRING)
        self.existing_user_treeview.set_model(self.existing_user_store)
        self.existing_user_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Existing_User"), Gtk.CellRendererText(), text=0)
        self.existing_user_treeview.append_column(col)

        for i in self.all_roles:
            iter = self.role_store.append()
            self.role_store.set_value(iter, 0, i[:-2])

        self.in_tcp_reserved_checkbutton = xml.get_object("in_tcp_reserved_checkbutton")
        
        transition_store 一列 application
        self.transition_treeview = self.xml.get_object("transition_treeview")
        self.transition_store = Gtk.ListStore(GObject.TYPE_STRING)
        self.transition_treeview.set_model(self.transition_store)
        self.transition_treeview.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
        self.transition_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Application"), Gtk.CellRendererText(), text=0)
        self.transition_treeview.append_column(col)
        
        user_transition_store 一列 application
        self.user_transition_treeview = self.xml.get_object("user_transition_treeview")
        self.user_transition_store = Gtk.ListStore(GObject.TYPE_STRING)
        self.user_transition_treeview.set_model(self.user_transition_store)
        self.user_transition_treeview.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
        self.user_transition_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Application"), Gtk.CellRendererText(), text=0)
        self.user_transition_treeview.append_column(col)

        for i in self.all_users:
            iter = self.user_transition_store.append()
            self.user_transition_store.set_value(iter, 0, i[:-2])
            iter = self.existing_user_store.append()
            self.existing_user_store.set_value(iter, 0, i[:-2])
        
        admin_store 一列 application
        self.admin_treeview = self.xml.get_object("admin_treeview")
        self.admin_store = Gtk.ListStore(GObject.TYPE_STRING)
        self.admin_treeview.set_model(self.admin_store)
        self.admin_treeview.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
        self.admin_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Application"), Gtk.CellRendererText(), text=0)
        self.admin_treeview.append_column(col)
        """

        self.role_store = []
        for i in self.all_roles:
            # iter = self.role_store.append()
            # self.role_store.set_value(iter, 0, i[:-2])
            self.role_store.append(i[:2])

        self.user_transition_store = []
        self.existing_user_store = []
        for i in self.all_users:
            # iter = self.user_transition_store.append()
            # self.user_transition_store.set_value(iter, 0, i[:-2])
            self.user_transition_store.append(i[:-2])
            # iter = self.existing_user_store.append()
            # self.existing_user_store.set_value(iter, 0, i[:-2])
            self.existing_user_store.append(i[:-2])

        self.transition_store = []
        self.admin_store = []
        try:
            for u in sepolicy.interface.get_user():
                # iter = self.transition_store.append()
                # self.transition_store.set_value(iter, 0, u)
                self.transition_store.append(u)

            for a in sepolicy.interface.get_admin():
                # iter = self.admin_store.append()
                # self.admin_store.set_value(iter, 0, a)
                self.admin_store.append(a)
        except ValueError as e:
            raise ValueError(e)


        self.init_file(filename)


    def confine_application(self):
        return self.get_type() in sepolicy.generate.APPLICATIONS

    def pol_generate(self):
        self.generate_policy()

    def get_name(self):
        return self.name

    def get_type(self):
        return sepolicy.generate.USER
        """
        if self.sandbox_radiobutton.get_active():
            return sepolicy.generate.SANDBOX
        if self.cgi_radiobutton.get_active():
            return sepolicy.generate.CGI
        if self.user_radiobutton.get_active():
            return sepolicy.generate.USER
        if self.init_radiobutton.get_active():
            return sepolicy.generate.DAEMON
        if self.dbus_radiobutton.get_active():
            return sepolicy.generate.DBUS
        if self.inetd_radiobutton.get_active():
            return sepolicy.generate.INETD
        if self.login_user_radiobutton.get_active():
            return sepolicy.generate.LUSER
        if self.admin_user_radiobutton.get_active():
            return sepolicy.generate.AUSER
        if self.xwindows_user_radiobutton.get_active():
            return sepolicy.generate.XUSER
        if self.terminal_user_radiobutton.get_active():
            return sepolicy.generate.TUSER
        if self.root_user_radiobutton.get_active():
            return sepolicy.generate.RUSER
        if self.existing_user_radiobutton.get_active():
            return sepolicy.generate.EUSER
        """

    def generate_policy(self, *args):
        """
        额外需要注意的变量：
        self.output_entry-输出文件位置
        self.exec_entry-exec文件所在位置
        self.store-访问文件与目录
        """
        outputdir = self.output_path
        try:
            """
            根据名字和类型，确定策略名字和对应模板（例如沙箱）
            """
            my_policy = sepolicy.generate.policy(self.get_name(), self.get_type())

            """
            bool值选项，暂不需要
            iter = self.boolean_store.get_iter_first()
            while iter:
                my_policy.add_boolean(self.boolean_store.get_value(iter, 0), self.boolean_store.get_value(iter, 1))
                iter = self.boolean_store.iter_next(iter)
            """
            if self.get_type() in sepolicy.generate.APPLICATIONS:
                my_policy.set_program(self.exec_path)
                my_policy.gen_symbols()
                """
                设置一些选项,这里不需要
                my_policy.set_use_syslog(self.syslog_checkbutton.get_active() == 1)
                my_policy.set_use_tmp(self.tmp_checkbutton.get_active() == 1)
                my_policy.set_use_uid(self.uid_checkbutton.get_active() == 1)
                my_policy.set_use_pam(self.pam_checkbutton.get_active() == 1)

                my_policy.set_use_dbus(self.dbus_checkbutton.get_active() == 1)
                my_policy.set_use_audit(self.audit_checkbutton.get_active() == 1)
                my_policy.set_use_terminal(self.terminal_checkbutton.get_active() == 1)
                my_policy.set_use_mail(self.mail_checkbutton.get_active() == 1)
                
                if self.get_type() is sepolicy.generate.DAEMON:
                    my_policy.set_init_script(self.init_script_entry.get_text())
                """
                if self.get_type() == sepolicy.generate.USER:
                    selected = ['user']
                    # self.user_transition_treeview.get_selection().selected_foreach(foreach, selected)

                    my_policy.set_transition_users(selected)
            """
            暂时不需要
            else:
                if self.get_type() == sepolicy.generate.RUSER:
                    selected = []
                    self.admin_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_admin_domains(selected)
                    selected = []
                    self.user_transition_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_transition_users(selected)
                else:
                    selected = []
                    self.transition_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_transition_domains(selected)

                    selected = []
                    self.role_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_admin_roles(selected)
            """

            """
            网络内容
            my_policy.set_in_tcp(self.in_tcp_all_checkbutton.get_active(), self.in_tcp_reserved_checkbutton.get_active(), self.in_tcp_unreserved_checkbutton.get_active(), self.in_tcp_entry.get_text())
            my_policy.set_in_udp(self.in_udp_all_checkbutton.get_active(), self.in_udp_reserved_checkbutton.get_active(), self.in_udp_unreserved_checkbutton.get_active(), self.in_udp_entry.get_text())
            my_policy.set_out_tcp(self.out_tcp_all_checkbutton.get_active(), self.out_tcp_entry.get_text())
            my_policy.set_out_udp(self.out_udp_all_checkbutton.get_active(), self.out_udp_entry.get_text())
            """

            my_policy.set_in_tcp(self.in_tcp_all, False, False, self.in_tcp_entry)
            my_policy.set_in_udp(self.in_udp_all, False, False, self.in_udp_entry)
            my_policy.set_out_tcp(self.out_tcp_all, self.out_tcp_entry)
            my_policy.set_out_udp(self.out_udp_all, self.out_udp_entry)

            for f in self.file_store:
                my_policy.add_file(f)

            for d in self.dir_store:
                my_policy.add_dir(d)

            """
            iter = self.store.get_iter_first()
            while iter:
                if self.store.get_value(iter, 1) == FILE:
                    my_policy.add_file(self.store.get_value(iter, 0))
                else:
                    my_policy.add_dir(self.store.get_value(iter, 0))
                iter = self.store.iter_next(iter)
            """

            self.info = my_policy.generate(outputdir)
            print(self.info)
            return False
        except ValueError as e:
            raise e

    def init_file(self, filename: string):
        with open(filename, 'r') as f:
            current_key = None
            for line in f:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    # print(key)
                    value = value.strip()
                    if key == 'name':
                        self.name = value
                    elif key == 'execpath':
                        self.exec_path = value
                    elif key == 'outputpath':
                        self.output_path = value
                    elif key == 'in_tcp_port':
                        self.in_tcp_entry = value
                        #ports = value.split(",")
                        #for port in ports:
                        #    self.in_tcp_entry.append(port)
                    elif key == "in_tcp_all":
                        value = value.lower()
                        if value == 'n' or value == 'no':
                            self.in_tcp_all = False
                        else:
                            self.in_tcp_all = True
                    elif key == "out_tcp_port":
                        self.out_tcp_entry = value
                        # ports = value.split(",")
                        # for port in ports:
                        #    self.out_tcp_entry.append(port)
                    elif key == "out_tcp_all":
                        value = value.lower()
                        if value == 'n' or value == 'no':
                            self.out_tcp_all = False
                        else:
                            self.out_tcp_all = True
                    elif key == 'in_udp_port':
                        self.in_udp_entry = value
                        # ports = value.split(",")
                        # for port in ports:
                        #     self.in_udp_entry.append(port)
                    elif key == "in_udp_all":
                        value = value.lower()
                        if value == 'n' or value == 'no':
                            self.in_udp_all = False
                        else:
                            self.in_udp_all = True
                    elif key == "out_udp_port":
                        self.out_udp_entry = value
                        #ports = value.split(",")
                        #for port in ports:
                        #    self.out_udp_entry.append(port)
                    elif key == "out_udp_all":
                        value = value.lower()
                        if value == 'n' or value == 'no':
                            self.out_udp_all = False
                        else:
                            self.out_udp_all = True
                    else:
                        current_key = key
                        files = value.split(",")
                        for file in files:
                            self.store.append(file)
                elif current_key == 'file':
                    files = value.split(",")
                    for file in files:
                        self.store.append(file)
        self.check_name()
        self.check_file_and_dir()
        self.check_in_net()
        self.check_out_net()
        self.check_and_process_exec()


    def check_name(self):
        name = self.name
        """
        初步判断
        file = "/etc/rc.d/init.d/" + name
        if os.path.isfile(file) and self.init_script_entry == "":
            self.init_script_entry = file

        file = "/usr/sbin/" + name
        if os.path.isfile(file) and self.exec_entry == "":
            self.exec_entry = file
        """
        return True

    def check_file_and_dir(self):
        for item in self.store:
            self.file_store.append(item)
            continue
            if os.path.exists(item):
                if os.path.isfile(item):
                    self.file_store.append(item)
                else:
                    self.dir_store.append(item)
            else:
                print("File or directory not found: " + item)

    def check_in_net(self):
        sepolicy.generate.verify_ports(self.in_tcp_entry)
        sepolicy.generate.verify_ports(self.in_udp_entry)
        return True

    def check_out_net(self):
        sepolicy.generate.verify_ports(self.out_tcp_entry)
        sepolicy.generate.verify_ports(self.out_udp_entry)
        return True

    def check_and_process_exec(self):
        if self.exec_path == "":
            print("You must enter a executable")
            return True
        policy = sepolicy.generate.policy(self.name, self.get_type())
        policy.set_program(self.exec_path)
        policy.gen_writeable()
        policy.gen_symbols()

        for f in policy.files.keys():
            self.file_store.append(f)

        for d in policy.dirs.keys():
            self.dir_store.append(d)

if __name__ == "__main__":
    generator = PolGenerator(r"/home/kevin/test_for_newtool/test1/info_a.txt")
    generator.pol_generate()
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

import sepolicy.generate_new
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
    def __init__(self, filename: string):

        self.name = ""
        self.exec_path = ""
        self.store = []
        self.file_store = []
        self.dir_store = []
        self.output_path = ""
        self.info = ""
        self.userType = "user"

        try:
            self.all_types = sepolicy.generate_new.get_all_types()
            self.all_modules = get_all_modules()
            self.all_roles = sepolicy.generate_new.get_all_roles()
            self.all_users = sepolicy.generate_new.get_all_users()
        except RuntimeError as e:
            self.all_types = []
            self.all_modules = []
            self.all_roles = []
            self.all_users = []
            raise RuntimeError(e)

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

        self.role_store = []
        for i in self.all_roles:
            self.role_store.append(i[:2])

        self.user_transition_store = []
        self.existing_user_store = []
        for i in self.all_users:
            self.user_transition_store.append(i[:-2])
            self.existing_user_store.append(i[:-2])

        self.transition_store = []
        self.admin_store = []
        try:
            for u in sepolicy.interface.get_user():
                self.transition_store.append(u)

            for a in sepolicy.interface.get_admin():
                self.admin_store.append(a)
        except ValueError as e:
            raise ValueError(e)

        self.init_file(filename)

    def confine_application(self):
        return self.get_type() in sepolicy.generate_new.APPLICATIONS

    def pol_generate(self):
        self.generate_policy()

    def get_name(self):
        return self.name

    def get_type(self):
        return sepolicy.generate_new.USER
        '''
        if self.userType == "DAEMON":
            return sepolicy.generate.DAEMON
        if self.userType == "XUSER":
            return sepolicy.generate.XUSER
        if self.userType == "TUSER":
            return sepolicy.generate.TUSER
        if self.userType == "RUSER":
            return sepolicy.generate.RUSER
        if self.userType == "EUSER":
            return sepolicy.generate.EUSER
        if self.userType == "LUSER":
            return sepolicy.generate.LUSER
        return sepolicy.generate.USER
        '''





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
            my_policy = sepolicy.generate_new.policy(self.get_name(), self.get_type())

            """
            bool值选项，暂不需要
            iter = self.boolean_store.get_iter_first()
            while iter:
                my_policy.add_boolean(self.boolean_store.get_value(iter, 0), self.boolean_store.get_value(iter, 1))
                iter = self.boolean_store.iter_next(iter)
            """
            if self.get_type() in sepolicy.generate_new.APPLICATIONS:
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
                """
                if self.get_type() is sepolicy.generate.DAEMON:
                    my_policy.set_init_script(self.init_script_entry.get_text())

                if self.get_type() == sepolicy.generate_new.USER:
                    selected = [self.userType]
                    my_policy.set_transition_users(selected)
            else:
                if self.get_type() == sepolicy.generate.RUSER:
                    selected = [self.userType]
                    # self.admin_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_admin_domains(selected)
                    selected = [self.userType]
                    # self.user_transition_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_transition_users(selected)
                else:
                    selected = [self.userType]
                    # self.transition_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_transition_domains(selected)

                    selected = [self.userType]
                    # self.role_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_admin_roles(selected)



            my_policy.set_in_tcp(self.in_tcp_all, False, False, self.in_tcp_entry)
            my_policy.set_in_udp(self.in_udp_all, False, False, self.in_udp_entry)
            my_policy.set_out_tcp(self.out_tcp_all, self.out_tcp_entry)
            my_policy.set_out_udp(self.out_udp_all, self.out_udp_entry)

            for f in self.file_store:
                my_policy.add_file(f)

            for d in self.dir_store:
                my_policy.add_dir(d)

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
                    value = value.strip()
                    if key == 'name':
                        self.name = value
                    elif key == 'usertype': # guest,staff,sysadm,unconfined,user,xguest
                        self.userType = value
                    elif key == 'execpath':
                        self.exec_path = value
                    elif key == 'outputpath':
                        self.output_path = value
                    elif key == 'in_tcp_port':
                        self.in_tcp_entry = value
                    elif key == "in_tcp_all":
                        value = value.lower()
                        if value == 'y' or value == 'yes':
                            self.in_tcp_all = True
                        else:
                            self.in_tcp_all = False
                    elif key == "out_tcp_port":
                        self.out_tcp_entry = value
                    elif key == "out_tcp_all":
                        value = value.lower()
                        if value == 'y' or value == 'yes':
                            self.out_tcp_all = True
                        else:
                            self.out_tcp_all = False
                    elif key == 'in_udp_port':
                        self.in_udp_entry = value
                    elif key == "in_udp_all":
                        value = value.lower()
                        if value == 'y' or value == 'yes':
                            self.in_udp_all = True
                        else:
                            self.in_udp_all = False
                    elif key == "out_udp_port":
                        self.out_udp_entry = value
                    elif key == "out_udp_all":
                        value = value.lower()
                        if value == 'y' or value == 'yes':
                            self.out_udp_all = True
                        else:
                            self.out_udp_all = False
                    elif key == 'file':
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
            if os.path.exists(item):
                if os.path.isfile(item):
                    self.file_store.append(item)
                else:
                    self.dir_store.append(item)
            else:
                print("File or directory not found: " + item)

    def check_in_net(self):
        sepolicy.generate_new.verify_ports(self.in_tcp_entry)
        sepolicy.generate_new.verify_ports(self.in_udp_entry)
        return True

    def check_out_net(self):
        sepolicy.generate_new.verify_ports(self.out_tcp_entry)
        sepolicy.generate_new.verify_ports(self.out_udp_entry)
        return True

    def check_and_process_exec(self):
        if self.exec_path == "":
            print("You must enter a executable")
            return True
        policy = sepolicy.generate_new.policy(self.name, self.get_type())
        policy.set_program(self.exec_path)
        policy.gen_writeable()
        policy.gen_symbols()

        for f in policy.files.keys():
            self.file_store.append(f)

        for d in policy.dirs.keys():
            self.dir_store.append(d)


if __name__ == "__main__":
    filename = ""
    if len(sys.argv) != 2:
        print("使用方法：python3 testa.py <filename>")
    else:
        filename = sys.argv[1]  # 命令行中的第一个参数是文件名
    if len(filename) == 0:
        print("文件名不能为空,请重试")
        exit(1)
    generator = PolGenerator(filename)
    generator.pol_generate()
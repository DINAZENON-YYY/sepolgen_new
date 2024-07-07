# sepolgen_new
对传统模板工具进行简单重构

# 命令行工具使用方法
将此文件main.py安装至/usr/bin文件夹中，运行以下命令即可：
```
python3 sepolgen_new filename
```
实际上只是一个py文件，如何命名都可以
通过命令行读取info文件

# sepolicy改进使用方法

强烈建议使用前，先将原sepolicy进行备份，以防破坏

进入对应文件夹
```
cd /usr/lib/python3.6/site-packages/sepolicy
```
将文件generate.py更换为该项目下的generate_backup_customer.py
并在当前目录templates目录中新加文件customer.py

# 注意
按照info格式进行资源配置，目前仍未做鲁棒性测试和更改

# 后续工作
支持更多模板？
对info读取具有鲁棒性

# sepolgen_hw
对传统模板工具进行重构

# 环境准备
```
pip install selinux-policy-devel
```

# 命令行工具使用方法
将此文件sepolgen_hw.py安装至任意位置中（/usr/bin文件夹最佳），运行以下命令即可：
```
python3 sepolgen_hw.py info
```
实际上只是一个py文件，如何命名都可以
通过命令行读取info文件

# sepolicy改进使用方法

**强烈建议使用前，先将原sepolicy进行备份，以防破坏**

进入对应文件夹
```
cd /usr/lib/python3.x/site-packages/sepolicy
```
将该项目下的generate_new.py添加至此文件夹中

然后将改项目下templates_new文件夹同样添加至此文件夹中，无需重新命名

# 配置文件说明

```
banPath : 禁止小标签文件路径
banType : 禁止小标签文件上下文
```

# 注意
按照info格式进行资源配置，目前仍未做鲁棒性测试和更改

# 后续工作
支持更多模板？
对info读取具有鲁棒性
进行策略冲突检测
优化标签规则
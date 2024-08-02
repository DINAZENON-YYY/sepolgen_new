import json


def extract_values_from_json(json_file_path):
    # 读取json文件
    with open(json_file_path, 'r') as file:
        data = json.load(file)

    # 提取key的值
    values = {key for key, value in data.items()}

    return list(values)


# 使用函数
json_file_path = "data.json"  # 替换为你的json文件路径
appFiles = extract_values_from_json(json_file_path)
print(appFiles)


def write_config_to_file(filename, config_data):
    with open(filename, 'w') as file:
        for key, value in config_data.items():
            if isinstance(value, list):
                value = ','.join(value)
            line = f"{key}:{value}\n"
            file.write(line)

appName = "testa"
appExecPath = "/home/kevin/test_for_newtool/test4/testa"
appOutputPath = "/home/kevin/test_for_newtool/test4/"

# 使用示例
config_data = {
    'name': appName,
    'execpath': appExecPath,
    'file': appFiles,
    'in_tcp_port': '',
    'in_tcp_all': 'n',
    'out_tcp_port': '',
    'out_tcp_all': 'n',
    'in_udp_port': '',
    'in_udp_all': 'n',
    'out_udp_port': '',
    'out_udp_all': 'n',
    'outputpath': appOutputPath
}

write_config_to_file('config_test.txt', config_data)


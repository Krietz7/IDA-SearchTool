# IDA-Search Tool
一个用于查找IDA数据库中不同类型数据的插件，支持搜索字节、注释、代码等不同类型的数据、支持搜索结果的复制导出。

# 安装
将`SearchTool.py`拷贝到IDA的插件文件夹即可。

- IDA版本 >= 7.5(仅在IDA Pro 7.7版本完整测试过)
- Python版本 >= 3.8
- Python中需安装PyQt5模块

# 使用方法
使用快捷键`Shift+F`打开插件窗口，或从工具栏的`Search/Search Tool`选项打开。

### 数据搜索
搜索字符串字面量
![](https://github.com/user-attachments/assets/058aee2c-0ec0-4915-bf87-79b04bcfef5d)

#### 字节搜索模式
搜索特定字节序列
![](https://github.com/user-attachments/assets/f9c846fe-52e3-4389-bb37-a1a2bb8098a7)

该模式使用了ida_bytes.bin_search()接口，以下为参考格式
```python
# 截取自ida_bytes.py parse_binpat_str() 注释文档
'''
CD 21          - bytes 0xCD, 0x21
21CD           - bytes 0xCD, 0x21 (little endian ) or 0x21, 0xCD (big-endian)
"Hello", 0     - the null terminated string "Hello"
L"Hello"       - 'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0
B8 ? ? ? ? 90  - byte 0xB8, 4 bytes with any value, byte 0x90
'''
```

### 注释搜索

![](https://github.com/user-attachments/assets/3b53ee46-a3bd-4dc8-aed7-e81d216299f4)

### 地址名称搜索

![](https://github.com/user-attachments/assets/4eb836a7-887f-4d27-a47e-8dd560a3cc86)

### 代码搜索
进行代码搜索时将打开一个独立的指令填写界面，可以正常填写指令，也可以在某些操作数位置上留空，以搜索其余位置操作数符号条件的代码
![](https://github.com/user-attachments/assets/183f7e9c-0a99-43ae-ab89-15b41f49985d)
![](https://github.com/user-attachments/assets/5df3324c-7d2f-42f1-899e-79535b786a35)

搜索代码片段
![](https://github.com/user-attachments/assets/9fb11566-a948-4369-b512-2c6349e36238)

# IDA-Search Tool
[中文](README.zh_CN.md)

a IDA python plugin to search different types of data in IDA databases, supports searching for different types of data such as bytes, comments, codes, etc., and supports copying and export of search results.


# Installation
Copy `SearchTool.py` to IDA plugins directory.

- IDA version >= 7.5(Only fully tested in IDA Pro 7.7)
- Python version >= 3.8
- PyQt5 module needs to be installed in Python

# Usage
Use the hotkey `Shift+F` to open the plugin window, or open it from the `Search/Search Tool` option in the toolbar.

### Data Search
Searching string literals
![](https://github.com/user-attachments/assets/058aee2c-0ec0-4915-bf87-79b04bcfef5d)

#### Byte search model
Search for a specific sequence of bytes
![](https://github.com/user-attachments/assets/f9c846fe-52e3-4389-bb37-a1a2bb8098a7)

This model uses the ida_bytes.bin_search() interface, the following is the reference format
```python
# Intercepted from ida_bytes.py parse_binpat_str() Commented Document
'''
CD 21          - bytes 0xCD, 0x21
21CD           - bytes 0xCD, 0x21 (little endian ) or 0x21, 0xCD (big-endian)
"Hello", 0     - the null terminated string "Hello"
L"Hello"       - 'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0
B8 ? ? ? ? 90  - byte 0xB8, 4 bytes with any value, byte 0x90
'''
```

### Comments Search
![](https://github.com/user-attachments/assets/3b53ee46-a3bd-4dc8-aed7-e81d216299f4)

### Named Address Search
![](https://github.com/user-attachments/assets/4eb836a7-887f-4d27-a47e-8dd560a3cc86)

### Code Search
When searching for code, an independent instruction filling interface will be opened. You can fill in instructions normally or leave blanks in certain operand positions.
![](https://github.com/user-attachments/assets/183f7e9c-0a99-43ae-ab89-15b41f49985d)
![](https://github.com/user-attachments/assets/5df3324c-7d2f-42f1-899e-79535b786a35)

#### Search for code snippet
![](https://github.com/user-attachments/assets/9fb11566-a948-4369-b512-2c6349e36238)















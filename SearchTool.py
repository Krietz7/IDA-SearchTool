import bisect

import idc
import idaapi
import ida_ida
import ida_lines
import idautils
import ida_bytes
import ida_strlist
import ida_kernwin

from PyQt5 import QtWidgets,QtCore
from PyQt5.QtGui import QFont

try:
    from fuzzywuzzy import fuzz
except ImportError:
    fuzz = None
try:
    import yara
except:
    yara = None


VERSION = "1.2.4"

TEXTEDIT_FONT = "Consolas"
TEXTEDIT_FONT_SIZE = 10

class search_config_base():
    def __init__(self):
        self._start = -1
        self._end = -1
        self._search_once = False
        self._search_direction = ida_bytes.BIN_SEARCH_FORWARD
        self._current_addr = -1

    def set_range(self, start:int, end:int):
        if start > end or start < ida_ida.inf_get_min_ea() or end > ida_ida.inf_get_max_ea():
            return
        self._start = start
        self._end = end

    '''
    search_direction: 
    ida_bytes.BIN_SEARCH_FORWARD or ida_bytes.BIN_SEARCH_BACKWARD
    '''
    def set_search_once(self, current_addr:int, search_direction:int):
        if current_addr >= ida_ida.inf_get_max_ea() or current_addr <= ida_ida.inf_get_min_ea():
            return
        self._search_once = True
        if current_addr < self._start:
            self._current_addr = self._start
        elif current_addr > self._end:
            self._current_addr = self._end
        self._current_addr = current_addr
        self._search_direction = search_direction

    def get_range(self):
        return self._start, self._end

    def is_search_once(self):
        return self._search_once

    def get_current_addr(self):
        return self._current_addr

    def get_search_direction(self):
        return self._search_direction


'''
Data search configuration
- Range: start, end
- Keyword: keyword
- Config: case sensitive,Fuzzy
'''
class data_search_config(search_config_base):
    def __init__(self):
        super().__init__()
        self._keyword = None

        self._case_sensitive = ida_bytes.BIN_SEARCH_CASE
        self._is_fuzzy = False
        self._fuzzy_score = 0
        self._bytes_search = False


    def set_keyword(self, keyword: str):
        if not isinstance(keyword,str):
            return
        self._keyword = keyword

    def get_keyword(self):
        return self._keyword

    def set_case_sensitive(self, case_sensitive: bool):
        self._case_sensitive = ida_bytes.BIN_SEARCH_CASE if case_sensitive else ida_bytes.BIN_SEARCH_NOCASE

    def set_bytes_search(self, bytes_search: bool):
        self._bytes_search = bytes_search

    def get_bytes_search(self):
        return self._bytes_search

    def get_flag(self):
        return self._search_direction | self._case_sensitive | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW

    def set_fuzzy(self, is_fuzzy: bool, fuzzy_score: int):
        self._is_fuzzy = is_fuzzy
        self._fuzzy_score = fuzzy_score

    def is_fuzzy(self):
        return self._is_fuzzy

    def get_fuzzy_score(self):
        return self._fuzzy_score

'''
Symbol search configuration
- Range: start, end
- Keyword: keyword
'''
class comments_search_config(search_config_base):
    def __init__(self):
        super().__init__()
        self._keyword = None
        self._is_fuzzy = False
        self._fuzzy_score = 0

    def set_keyword(self, keyword: str):
        if not isinstance(keyword, str):
            return
        self._keyword = keyword

    def get_keyword(self):
        return self._keyword

    def set_fuzzy(self, is_fuzzy: bool, fuzzy_score: int):
        self._is_fuzzy = is_fuzzy
        self._fuzzy_score = fuzzy_score

    def is_fuzzy(self):
        return self._is_fuzzy

    def get_fuzzy_score(self):
        return self._fuzzy_score


class names_search_config(search_config_base):
    def __init__(self):
        super().__init__()
        self._keyword = None
        self._is_fuzzy = False
        self._fuzzy_score = 0

    def set_keyword(self, keyword: str):
        if not isinstance(keyword, str):
            return
        self._keyword = keyword

    def get_keyword(self):
        return self._keyword

    def set_fuzzy(self, is_fuzzy: bool, fuzzy_score: int):
        self._is_fuzzy = is_fuzzy
        self._fuzzy_score = fuzzy_score

    def is_fuzzy(self):
        return self._is_fuzzy

    def get_fuzzy_score(self):
        return self._fuzzy_score

class assembly_code_line():
    def __init__(self, insn_mnen = None, operand1 = None, operand2 = None, operand3 = None):
        self.insn_mnen = insn_mnen
        self.operand1 = operand1
        self.operand2 = operand2
        self.operand3 = operand3

class code_search_config(search_config_base):
    def __init__(self):
        super().__init__()
        self._code_search_targets = []

    def set_code_search_target(self, code_list):
        if not all(isinstance(x, assembly_code_line) for x in code_list):
            return
        self._code_search_targets = code_list

    def get_code_search_targets(self):
        return self._code_search_targets


class yara_search_config(search_config_base):
    def __init__(self):
        super().__init__()
        self._yara_search_rules = None

    def set_rules_by_str(self, rules):
        self._yara_search_rules = yara.compile(source=rules)

    def set_rules_by_filepath(self, filepath):
        self._yara_search_rules = yara.compile(filepath)

    def get_rules(self):
        return self._yara_search_rules


class search_result_base:
    def __init__(self):
        self.icon = ""
        self.address = -1
        self.type = -1
        self.detail = None

class hex_data_result(search_result_base):
    def __init__(self, address:int):
        super().__init__()
        self.address = address
        self._set_type()
        self._length = 5
        self._set_detail()

    def _set_detail(self):
        disasm = idc.generate_disasm_line(self.address,0)
        data_byte = idc.get_bytes(self.address,5)
        self.detail = ' '.join([f"{i:02X}" for i in bytearray(data_byte)]) + "...   (" + disasm + ")"

    def _set_type(self):
        checks = [
            (idc.is_byte, "hex"),
            (idc.is_word, "hex"),
            (idc.is_dword, "hex"),
            (idc.is_qword, "hex"),
            (idc.is_strlit, "string"),
            (idc.is_code, "code")
        ]
        data_type_flag = ida_bytes.get_flags(ida_bytes.get_item_head(self.address))
        self.type = next((key for func, key in checks if func(data_type_flag)), "hex")

class comment_result(search_result_base):
    def __init__(self, address:int, comment:str, type = None):
        super().__init__()
        self.address = address
        self._set_type(type)
        self.detail = ''.join([char for char in comment if char.isprintable() and not char.isspace() or char == ' '])

    def _set_type(self,type):
        type_dict = {
                ida_lines.SCOLOR_REGCMT : "regular comment",
                ida_lines.SCOLOR_RPTCMT : "repeatable comment",
                ida_lines.SCOLOR_AUTOCMT : "auto comment"
            }
        if type in type_dict.keys(): 

            self.type = type_dict[type]

        else:
            if ida_bytes.get_cmt(self.address,True) is not None:
                self.type = "repeatable comment"
            elif ida_bytes.get_cmt(self.address,False) is not None:
                self.type = "regular comment"
            else:
                self.type = "auto comment"

class name_result(search_result_base):
    def __init__(self, address:int, name:str):
        super().__init__()
        self.address = address
        self._set_type()
        self.detail = name




    def _set_type(self):
        flag = ida_bytes.get_full_flags(self.address)
        if ida_bytes.is_func(flag):
            self.type = "function name"
        elif ida_bytes.is_strlit(flag):
            self.type = "string name"
        elif ida_bytes.is_data(flag):
            self.type = "data name"
        elif ida_bytes.is_code(flag):
            self.type = "code name"
        else:
            self.type = "name"




class code_result(search_result_base):
    def __init__(self, address:int):
        super().__init__()
        self.address = address
        self._set_type()
        self.detail = idc.generate_disasm_line(address,0)

    def _set_type(self):
        func_name = idc.get_func_name(self.address)
        if func_name is not None and func_name != "":
            self.type = f"code from {func_name}"
        else:
            self.type = "code"

class yara_result(search_result_base):
    def __init__(self, match_rule:str, address:int, identifier:str, matched_data:str):
        super().__init__()
        self.match_rule = match_rule
        self.address = address
        self.identifier = identifier
        self.matched_data = matched_data
        self.detail = idc.generate_disasm_line(address,0)






class SearchManager():
    def __init__(self):
        pass

    @classmethod
    def bytes_search(cls,_data_search_config):
        # keyword format: see ida_bytes.parse_binpat_str()
        start, end = _data_search_config.get_range()
        if _data_search_config.get_bytes_search() is True:
            keyword = _data_search_config.get_keyword()
        else:
            keyword = "\"" + _data_search_config.get_keyword() + "\""

        flag = _data_search_config.get_flag()
        if keyword is None or flag is None:
            return []

        patterns = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(patterns, 0, keyword, 16)
        if err:
            return []

        current_addr = _data_search_config.get_current_addr()
        if _data_search_config.is_search_once():
            if current_addr > end or current_addr < start  or current_addr == -1:
                return []
            elif _data_search_config.get_search_direction() == ida_bytes.BIN_SEARCH_FORWARD:
                start = current_addr
            else:
                end = current_addr

            addr = ida_bytes.bin_search(start, end, patterns, flag)
            if addr == idaapi.BADADDR:
                return []
            return [hex_data_result(addr)]

        if start == -1 or end == -1:
            return []
        ea = start
        search_result_list = []
        while ea < end:
            if ida_kernwin.user_cancelled():
                break

            ea = ida_bytes.bin_search(ea, end, patterns, flag)
            if ea == idaapi.BADADDR:
                break
            search_result_list.append(hex_data_result(ea))
            ea = idc.next_head(ea,end)

        if _data_search_config.is_fuzzy() and fuzz != None:
            n = ida_strlist.get_strlist_qty()
            fuzzy_score = _data_search_config.get_fuzzy_score()

            for i in range(n):
                strinfo = ida_strlist.string_info_t()
                ida_strlist.get_strlist_item(strinfo,i)
                extracted_str = str(idc.get_bytes(strinfo.ea, idc.get_item_size(strinfo.ea)))[2:-1]
                score = fuzz.partial_ratio(keyword[1:-1],extracted_str)

                if score > fuzzy_score and score < 100: # less than 100 to avoid repeat match
                    search_result_list.append(hex_data_result(strinfo.ea))

        return search_result_list



    @classmethod
    def comments_search(cls,_comments_search_config):
        start, end = _comments_search_config.get_range()
        keyword = _comments_search_config.get_keyword()
        if keyword is None or keyword == "":
            return []

        def find_comment(line):
            for cmt_type in [
                    ida_lines.SCOLOR_REGCMT,
                    ida_lines.SCOLOR_RPTCMT,
                    ida_lines.SCOLOR_AUTOCMT]:
                cmt_idx = line.find(ida_lines.SCOLOR_ON + cmt_type)
                if cmt_idx > -1:
                    return cmt_idx, cmt_type
            return -1, -1
        
        def fuzzy_match(str_1, str_2, fuzzy_score):
            score = fuzz.partial_ratio(str_1, str_2)
            if score > fuzzy_score and score < 100:
                return True

        is_fuzzy =  _comments_search_config.is_fuzzy()
        fuzzy_score = _comments_search_config.get_fuzzy_score()


        current_addr = _comments_search_config.get_current_addr()
        if _comments_search_config.is_search_once():
            if current_addr > end or current_addr < start or current_addr == -1:
                return []
            step_function = ida_bytes.next_head if _comments_search_config.get_search_direction() == ida_bytes.BIN_SEARCH_FORWARD else ida_bytes.prev_head
            boundary_condition = lambda ea: ea < end if _comments_search_config.get_search_direction() == ida_bytes.BIN_SEARCH_FORWARD else ea >= start

            ea = current_addr
            while boundary_condition(ea):
                line = ida_lines.generate_disasm_line(ea)
                cmt_idx, cmt_type = find_comment(line)
                if cmt_idx != -1 and (keyword in line[cmt_idx:] or (is_fuzzy and fuzzy_match(line[cmt_idx:], keyword, fuzzy_score))):
                    return [comment_result(ea, line[cmt_idx:], cmt_type)]
                ea = step_function(ea, end if _comments_search_config.get_search_direction() == ida_bytes.BIN_SEARCH_FORWARD else start)
                if ea == idaapi.BADADDR:
                    break
            return []

        search_result_list = []
        ea = start
        while ea < end:
            if ida_kernwin.user_cancelled():
                break

            line = ida_lines.generate_disasm_line(ea,ida_lines.GENDSM_FORCE_CODE)
            cmt_idx, cmt_type = find_comment(line)
            if cmt_idx != -1:
                if keyword in line[cmt_idx:] or (is_fuzzy and fuzzy_match(line[cmt_idx:], keyword, fuzzy_score)):
                    search_result_list.append(comment_result(ea, line[cmt_idx:], cmt_type))
            ea = ida_bytes.next_head(ea, end)
            if ea == idaapi.BADADDR:
                break
        return search_result_list

    @classmethod
    def names_search(cls, _names_search_config):
        start, end = _names_search_config.get_range()
        keyword = _names_search_config.get_keyword()

        if keyword is None or keyword == "":
            return []

        def fuzzy_match(str_1, str_2, fuzzy_score):
            score = fuzz.partial_ratio(str_1, str_2)
            if score > fuzzy_score and score < 100:
                return True
        is_fuzzy =  _names_search_config.is_fuzzy()
        fuzzy_score = _names_search_config.get_fuzzy_score()

        addr_name_dict = sorted(
            [(address, name) for address, name in idautils.Names()
             if (keyword in name or (is_fuzzy and fuzzy_match(keyword, name, fuzzy_score))) and start <= address <= end],
            key=lambda x: x[0]
        )

        current_addr = _names_search_config.get_current_addr()
        search_direction = _names_search_config.get_search_direction()

        if _names_search_config.is_search_once():
            if current_addr > end or current_addr < start or current_addr == -1:
                return []

            addresses = [item[0] for item in addr_name_dict]
            index = bisect.bisect_left(addresses, current_addr)

            if search_direction == ida_bytes.BIN_SEARCH_FORWARD:
                if index < len(addresses) and addresses[index] == current_addr:
                    index += 1
                if index < len(addresses):
                    return [name_result(addr_name_dict[index][0], addr_name_dict[index][1])]
            elif search_direction == ida_bytes.BIN_SEARCH_BACKWARD:
                if index > 0 and addresses[index - 1] == current_addr:
                    index -= 1
                if index > 0:
                    return [name_result(addr_name_dict[index - 1][0], addr_name_dict[index - 1][1])]

            return []
        return [name_result(item[0], item[1]) for item in addr_name_dict]


    @classmethod
    def assembly_code_search(cls, assembly_search_config):
        start, end = assembly_search_config.get_range()
        code_search_targets = assembly_search_config.get_code_search_targets()
        if not code_search_targets:
            return []

        def find_code_a_line(ea,line: assembly_code_line):
            if not idaapi.is_loaded(ea):
                return False
            if line.insn_mnen is not None and line.insn_mnen != idc.print_insn_mnem(ea):
                return False
            if line.operand1 is not None and line.operand1 != idc.print_operand(ea, 0):
                return False
            if line.operand2 is not None and line.operand2 != idc.print_operand(ea, 1):
                return False
            if line.operand3 is not None and line.operand3 != idc.print_operand(ea, 2):
                return False
            return True

        def find_code_snippet(ea, code_search_targets:list,end):
            for code_search_target in code_search_targets:
                if not find_code_a_line(ea, code_search_target):
                    return False
                ea = ida_bytes.next_head(ea, end)
                if ea == idaapi.BADADDR or ea >= end:  # 检查无效地址
                    return False
            return True

        current_addr = assembly_search_config.get_current_addr()
        if assembly_search_config.is_search_once():
            if current_addr > end or current_addr < start or current_addr == -1:
                return []
            if assembly_search_config.get_search_direction() == ida_bytes.BIN_SEARCH_FORWARD:
                while current_addr < end:
                    if find_code_snippet(current_addr, code_search_targets,end):
                        return [code_result(current_addr)]
                    current_addr = ida_bytes.next_head(current_addr, end)
                    if current_addr == idaapi.BADADDR or current_addr >= end:
                        break
            elif assembly_search_config.get_search_direction() == ida_bytes.BIN_SEARCH_BACKWARD:
                while current_addr > start:
                    if find_code_snippet(current_addr, code_search_targets, end):
                        return [code_result(current_addr)]

                    current_addr = ida_bytes.prev_head(current_addr, start)
                    if current_addr == idaapi.BADADDR or current_addr < start:

                        break
            return []

        ea = start
        search_result_list = []
        while ea < end:
            if ida_kernwin.user_cancelled():
                break

            if find_code_snippet(ea, code_search_targets, end):
                search_result_list.append(code_result(ea))
            ea = ida_bytes.next_head(ea, end)
            if ea == idaapi.BADADDR or ea >= end:
                break
        return search_result_list


    @classmethod
    def yara_search(cls, yara_search_config):
        start, end = yara_search_config.get_range()
    
        def get_segment_list(start, end):
            segment_list = []
            current_addr = start
            while(current_addr < end):
                segment_end = idc.get_segm_attr(current_addr, idc.SEGATTR_END)
                if(segment_end < end):
                    segment_list.append((current_addr, segment_end))
                else:
                    segment_list.append((current_addr, end))
                current_addr = ida_bytes.next_head(segment_end, end)
            return segment_list
        
        yara_result_list = []

        for segment in get_segment_list(start, end):
            memory = idc.get_bytes(segment[0], segment[1] - segment[0])
            rules = yara_search_config.get_rules()
            matches = rules.match(data=memory)
            if matches:
                for match in matches:
                    for string in match.strings:
                        # for yara-python version < 4.0
                        if isinstance(string, tuple):
                            address = segment[0] + string[0]
                            identifier = string[1]
                            matched_data = string[2]

                            yara_result_list.append(yara_result(match.rule, address, identifier, str(matched_data)))

                        # for yara-python version >= 4.0
                        elif isinstance(string, yara.StringMatch):
                            instances = string.instances
                            for instance in instances:
                                address = segment[0] + instance.offset
                                identifier = string.identifier
                                matched_data = instance.matched_data
                                yara_result_list.append(yara_result(match.rule, address, identifier, str(matched_data)))

        return yara_result_list



class SearchForm(idaapi.PluginForm):
    search_type = {
        "Data": 0,
        "Comments": 1,
        "Names": 2,
        "Assembly Code": 3,
    }
    if(yara != None):
        search_type["YARA Rule"] = 4
    search_range_start = 0
    search_range_end = 0


    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        search_range_start = ida_ida.inf_get_min_ea()
        search_range_end = ida_ida.inf_get_max_ea()
        self.InitUi()

        self._set_search_range(search_range_start,search_range_end)

    def InitUi(self):
        self.layout = QtWidgets.QVBoxLayout()

        self.search_result_box = self._search_result_box_init()
        self.search_configure_box = self._search_configure_box_init()

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter.addWidget(self.search_configure_box)
        splitter.addWidget(self.search_result_box)

        self.layout.addWidget(splitter)
        self.parent.setLayout(self.layout)
        return

    def OnClose(self, form):
        pass


    def _search_configure_box_init(self):
        self.SearchConfigureBox = QtWidgets.QWidget()
        SearchConfigureLayout = QtWidgets.QVBoxLayout()

        """Search Type Select"""
        search_type_box = QtWidgets.QGroupBox("Search Type:")
        search_type_layout = QtWidgets.QVBoxLayout()

        self.search_type_comboBox = QtWidgets.QComboBox()
        self.search_type_comboBox.setMaximumWidth(200)
        for key in self.search_type:
            self.search_type_comboBox.addItem(key)
        search_type_layout.addWidget(self.search_type_comboBox)
        search_type_box.setLayout(search_type_layout)
        SearchConfigureLayout.addWidget(search_type_box)

        """Search Range Configure"""
        search_range_box = QtWidgets.QGroupBox("Search Range:")
        search_range_box.setMaximumHeight(200)
        search_range_layout = QtWidgets.QVBoxLayout()

        # search range address
        address_range_layout = QtWidgets.QHBoxLayout()
        address_range_layout.addWidget(QtWidgets.QLabel("From Address:"))
        self.search_range_start_edit = QtWidgets.QLineEdit()
        self.search_range_start_edit.setText(hex(self.search_range_start))
        address_range_layout.addWidget(self.search_range_start_edit)
        address_range_layout.addWidget(QtWidgets.QLabel("To Address:"))
        self.search_range_end_edit = QtWidgets.QLineEdit()
        self.search_range_end_edit.setText(hex(self.search_range_end))
        address_range_layout.addWidget(self.search_range_end_edit)
        search_range_layout.addLayout(address_range_layout)

        # search range buttons
        search_range_button_layout = QtWidgets.QHBoxLayout()

        reset_range_button = QtWidgets.QPushButton("Reset Range")
        reset_range_button.clicked.connect(self._reset_range_button_clicked)
        reset_range_button.setMinimumWidth(200)
        search_range_button_layout.addWidget(reset_range_button)

        search_function_button = QtWidgets.QPushButton("Select Function")
        search_function_button.clicked.connect(self._open_select_function_dialog)
        search_function_button.setMinimumWidth(200)
        search_range_button_layout.addWidget(search_function_button)


        select_segment_button = QtWidgets.QPushButton("Select Segment")
        select_segment_button.clicked.connect(self._open_select_segment_dialog)
        select_segment_button.setMinimumWidth(200)
        search_range_button_layout.addWidget(select_segment_button)

        search_range_button_layout.addStretch(1)
        search_range_layout.addLayout(search_range_button_layout)


        search_range_box.setLayout(search_range_layout)
        SearchConfigureLayout.addWidget(search_range_box)


        """Search Keyword Configure"""
        '''str input box'''
        self.search_keyword_box = QtWidgets.QGroupBox("Search Keyword:")
        search_keyword_layout = QtWidgets.QVBoxLayout()

        self.search_keyword_edit = QtWidgets.QTextEdit()
        self.search_keyword_edit.setFont(QFont(TEXTEDIT_FONT, TEXTEDIT_FONT_SIZE))
        self.search_keyword_edit.setAcceptRichText(False)
        search_keyword_layout.addWidget(self.search_keyword_edit)

        self.search_keyword_box.setLayout(search_keyword_layout)
        SearchConfigureLayout.addWidget(self.search_keyword_box)

        '''code input box'''
        self.search_code_box = QtWidgets.QGroupBox("Search Code:")
        search_code_layout = QtWidgets.QVBoxLayout()

        self.search_code_tree = QtWidgets.QTreeWidget()
        self.search_code_tree.setHeaderLabels(["Code","insn", "op 1", "op 2", "op 3"])
        self.search_code_tree.setColumnWidth(0, 550)
        self.search_code_tree.setColumnWidth(1, 80)
        self.search_code_tree.setColumnWidth(2, 80)
        self.search_code_tree.setColumnWidth(3, 80)
        self.search_code_tree.setColumnWidth(4, 80)
        self.search_code_tree.setIndentation(5)
        search_code_layout.addWidget(self.search_code_tree)

        add_code_button_layout = QtWidgets.QHBoxLayout()
        add_code_button_layout.addStretch(1)
        self.add_code_button = QtWidgets.QPushButton("Add Code")
        self.add_code_button.setMaximumWidth(300)
        self.add_code_button.setMinimumWidth(200)
        self.add_code_button.clicked.connect(self._add_code_line)
        add_code_button_layout.addWidget(self.add_code_button)

        self.clear_code_button = QtWidgets.QPushButton("Clear Code")
        self.clear_code_button.setMaximumWidth(300)
        self.clear_code_button.setMinimumWidth(200)
        self.clear_code_button.clicked.connect(self.search_code_tree.clear)
        add_code_button_layout.addWidget(self.clear_code_button)



        add_code_button_layout.addStretch(1)
        search_code_layout.addLayout(add_code_button_layout)

        self.search_code_box.setLayout(search_code_layout)
        SearchConfigureLayout.addWidget(self.search_code_box)

        '''YARA rule box'''
        self.yara_rule_box = QtWidgets.QGroupBox("YARA Rule")
        yara_rule_layout = QtWidgets.QVBoxLayout()

        self.yara_rule_edit = QtWidgets.QTextEdit()
        self.yara_rule_edit.setFont(QFont(TEXTEDIT_FONT, TEXTEDIT_FONT_SIZE))

        self.yara_rule_edit.setAcceptRichText(False)
        yara_rule_layout.addWidget(self.yara_rule_edit)




        yara_rule_buttom_layout = QtWidgets.QHBoxLayout()
        yara_rule_buttom_layout.addStretch(1)
    
        self.select_yara_rule_file_button = QtWidgets.QPushButton("Select YARA Rule File")
        self.select_yara_rule_file_button.setMaximumWidth(400)
        self.select_yara_rule_file_button.setMinimumWidth(200)
        self.select_yara_rule_file_button.clicked.connect(self._select_yara_rule_file)
        yara_rule_buttom_layout.addWidget(self.select_yara_rule_file_button)

        self.clear_yara_rule_button = QtWidgets.QPushButton("Clear YARA Rule")
        self.clear_yara_rule_button.setMaximumWidth(400)
        self.clear_yara_rule_button.setMinimumWidth(200)
        self.clear_yara_rule_button.clicked.connect(self.yara_rule_edit.clear)
        yara_rule_buttom_layout.addWidget(self.clear_yara_rule_button)


        yara_rule_buttom_layout.addStretch(1)
        yara_rule_layout.addLayout(yara_rule_buttom_layout)



        self.yara_rule_box.setLayout(yara_rule_layout)
        SearchConfigureLayout.addWidget(self.yara_rule_box)









        """Configure"""
        self.advanced_configure_box = QtWidgets.QGroupBox("Advanced Configure:")
        advanced_configure_layout = QtWidgets.QVBoxLayout()

        '''Data configure section'''
        self.case_sensitive_config = QtWidgets.QCheckBox("Case sensitive")
        advanced_configure_layout.addWidget(self.case_sensitive_config)
        self.bytes_search_config = QtWidgets.QCheckBox("Bytes Search")
        advanced_configure_layout.addWidget(self.bytes_search_config)
        self.addr_search_config = QtWidgets.QCheckBox("Addr Search")
        advanced_configure_layout.addWidget(self.addr_search_config)
        self.fuzzy_search_config = QtWidgets.QCheckBox("Fuzzy Search")
        advanced_configure_layout.addWidget(self.fuzzy_search_config)
        if(fuzz == None):
            self.fuzzy_search_config.hide()

        fuzzy_search_slider_label = QtWidgets.QLabel("fuzzy search match level:")
        fuzzy_search_slider_label.setVisible(False) 
        advanced_configure_layout.addWidget(fuzzy_search_slider_label)

        self.fuzzy_search_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.fuzzy_search_slider.setRange(1, 100)
        self.fuzzy_search_slider.setValue(50)
        self.fuzzy_search_slider.setVisible(False)
        self.fuzzy_search_slider.setMaximumWidth(300)
        advanced_configure_layout.addWidget(self.fuzzy_search_slider)

        self.advanced_configure_box.setLayout(advanced_configure_layout)
        SearchConfigureLayout.addWidget(self.advanced_configure_box)






        """Search Start Button"""

        search_button_box = QtWidgets.QGroupBox()
        search_button_layout = QtWidgets.QHBoxLayout()
        search_button_layout.addStretch(1)

        search_all_button = QtWidgets.QPushButton("Search All")
        search_all_button.clicked.connect(lambda: self._start_search(0))
        search_all_button.setMinimumWidth(200)
        search_button_layout.addWidget(search_all_button)

        search_previous_button = QtWidgets.QPushButton("Search Previous")
        search_previous_button.clicked.connect(lambda: self._start_search(1))
        search_previous_button.setMinimumWidth(200)
        search_button_layout.addWidget(search_previous_button)


        search_next_button = QtWidgets.QPushButton("Search Next")
        search_next_button.clicked.connect(lambda: self._start_search(2))
        search_next_button.setMinimumWidth(200)
        search_button_layout.addWidget(search_next_button)

        search_button_layout.addStretch(1)
        search_button_box.setLayout(search_button_layout)
        SearchConfigureLayout.addWidget(search_button_box)

        # connect select_type_comboBox to self._on_search_type_changed after initialization
        self.search_type_comboBox.currentIndexChanged.connect(self._on_search_type_changed)
        self._on_search_type_changed(0)
        self.SearchConfigureBox.setLayout(SearchConfigureLayout)


        def addr_search_set_checkbox(set_enable):
            if not self.addr_search_config.isChecked() or set_enable:
                self.case_sensitive_config.setDisabled(False)
                self.bytes_search_config.setDisabled(False)
                self.fuzzy_search_config.setDisabled(False)
            else:
                self.case_sensitive_config.setDisabled(True)
                self.case_sensitive_config.setChecked(False)
                self.bytes_search_config.setDisabled(True)
                self.bytes_search_config.setChecked(False)
                self.fuzzy_search_config.setDisabled(True)
                self.fuzzy_search_config.setChecked(False)


        self.addr_search_config.stateChanged.connect(
            lambda : addr_search_set_checkbox(False))
        self.search_type_comboBox.currentIndexChanged.connect(
            lambda : addr_search_set_checkbox(
                self.search_type_comboBox.currentIndex() != self.search_type["Data"]))

        def fuzzy_search_set_button(set_enable):
            if not self.fuzzy_search_config.isChecked() or set_enable:
                search_previous_button.setDisabled(False)
                search_next_button.setDisabled(False)
            else:
                search_previous_button.setDisabled(True)
                search_next_button.setDisabled(True)

        self.fuzzy_search_config.stateChanged.connect(
            lambda state: fuzzy_search_slider_label.setVisible(state == QtCore.Qt.Checked))
        self.fuzzy_search_config.stateChanged.connect(
            lambda state: self.fuzzy_search_slider.setVisible(state == QtCore.Qt.Checked))

        self.fuzzy_search_config.stateChanged.connect(
            lambda : fuzzy_search_set_button(
                self.search_type_comboBox.currentIndex() != self.search_type["Data"]))
        self.search_type_comboBox.currentIndexChanged.connect(
            lambda : fuzzy_search_set_button(
                self.search_type_comboBox.currentIndex() != self.search_type["Data"]))



        return self.SearchConfigureBox

    def _search_result_box_init(self):
        self.SearchResultBox = QtWidgets.QWidget()
        self.SearchResultLayout = QtWidgets.QVBoxLayout()

        search_result_box = QtWidgets.QGroupBox("Search Result")
        search_result_box.setMinimumWidth(750)
        search_result_layout = QtWidgets.QVBoxLayout()

        class SearchResultTree(QtWidgets.QTreeWidget):
            def __init__(self, parent = None):
                super().__init__(parent)
                self.set_default_header_labels()
                self.setSelectionMode(QtWidgets.QTreeWidget.ExtendedSelection)
                self.setIndentation(0)
                self.setSortingEnabled(True)
                self.itemDoubleClicked.connect(self._on_item_double_click)

            def _on_item_double_click(self, item):
                address = item.text(1)
                try:
                    address = int(address,16)
                    idaapi.jumpto(address)
                except ValueError:
                    pass

            def contextMenuEvent(self, event):
                menu = QtWidgets.QMenu(self)

                select_all_action = QtWidgets.QAction("Select All Items", self)
                select_all_action.triggered.connect(self.select_all_items)
                menu.addAction(select_all_action)
                menu.addSeparator()

                copy_menu = QtWidgets.QMenu("Copy Selected Item Content", self)
                copy_actions = [
                    ("Address", 1),
                    ("Detail", 3)
                ]
                for label, column in copy_actions:
                    action = QtWidgets.QAction(label, self)
                    action.triggered.connect(lambda checked, col=column: self.copy_selected_column(col))
                    copy_menu.addAction(action)

                menu.addMenu(copy_menu)

                copy_as_list_menu = QtWidgets.QMenu("Copy Selected Item Content as List", self)
                for label, column in copy_actions:
                    action = QtWidgets.QAction(label, self)
                    action.triggered.connect(lambda checked, col=column: self.copy_selected_column_as_list(col))
                    copy_as_list_menu.addAction(action)
                menu.addMenu(copy_as_list_menu)
                selected_items = self.selectedItems()
                if not selected_items:
                    copy_menu.setVisible(False)
                    copy_as_list_menu.setVisible(False)
                    return
                menu.exec_(event.globalPos())

            def set_default_header_labels(self):
                self.setHeaderLabels(["","Address","Type","Detail"])
                self.setColumnHidden(0,True)
                self.setColumnHidden(4,True)

            def set_yara_header_labels(self):
                self.setHeaderLabels(["Rule","Address","Identifier","Detail","matched_data"])
                self.setColumnHidden(0,False)
                self.setColumnHidden(4,False)

            def select_all_items(self):
                self.selectAll()

            def copy_selected_column(self, column):
                clipboard = QtWidgets.QApplication.clipboard()
                selected_items = self.selectedItems()
                text_to_copy = "\n".join(item.text(column) for item in selected_items)
                clipboard.setText(text_to_copy)

            def copy_selected_column_as_list(self, column):
                clipboard = QtWidgets.QApplication.clipboard()
                selected_items = self.selectedItems()
                if column == 1:  # Assuming "Address" is the second column and has index 1
                    items_content = [item.text(column) for item in selected_items]
                else:
                    items_content = [f'"{item.text(column)}"' for item in selected_items]
                text_to_copy = f"[{', '.join(items_content)}]"
                clipboard.setText(text_to_copy)

        self.search_result_tree = SearchResultTree()
        search_result_layout.addWidget(self.search_result_tree)
        search_result_box.setLayout(search_result_layout)

        self.SearchResultLayout.addWidget(search_result_box)
        self.SearchResultBox.setLayout(self.SearchResultLayout)
        return self.SearchResultBox


    def _on_search_type_changed(self, index):
        current_text = self.search_type_comboBox.itemText(index)
        self.search_result_tree.clear()

        if self.search_type[current_text] == 0:
            self.search_keyword_box.show()
            self.advanced_configure_box.show()
            self.case_sensitive_config.show()
            self.bytes_search_config.show()
            self.addr_search_config.show()
            self.search_code_box.hide()
            self.yara_rule_box.hide()
            self.search_result_tree.set_default_header_labels()

        elif self.search_type[current_text] == 1:
            self.search_keyword_box.show()
            self.advanced_configure_box.show()
            self.case_sensitive_config.hide()
            self.bytes_search_config.hide()
            self.addr_search_config.hide()
            self.search_code_box.hide()
            self.yara_rule_box.hide()
            self.search_result_tree.set_default_header_labels()


        elif self.search_type[current_text] == 2:
            self.search_keyword_box.show()
            self.advanced_configure_box.show()
            self.case_sensitive_config.hide()
            self.bytes_search_config.hide()
            self.addr_search_config.hide()
            self.search_code_box.hide()
            self.yara_rule_box.hide()
            self.search_result_tree.set_default_header_labels()


        elif self.search_type[current_text] == 3:
            self.search_keyword_box.hide()
            self.advanced_configure_box.hide()
            self.search_code_box.show()
            self.yara_rule_box.hide()
            self.search_result_tree.set_default_header_labels()


        elif self.search_type[current_text] == 4:
            self.search_keyword_box.hide()
            self.advanced_configure_box.hide()
            self.search_code_box.hide()
            self.yara_rule_box.show()
            self.search_result_tree.set_yara_header_labels()


    def _set_search_range(self, start: int = -1, end: int = -1):
        # set search range by parameters
        if start != -1 and end != -1:
            start_t = start
            end_t = end
        # set search range by edit input
        else:
            try:
                start_t =  int(self.search_range_start_edit.text(), 16)
                end_t =  int(self.search_range_end_edit.text(), 16)
            except ValueError:
                QtWidgets.QMessageBox.warning(None, "Invalid Input", "Please enter valid hexadecimal addresses.")
                return

        if start_t > end_t:
            QtWidgets.QMessageBox.warning(None, "Invalid Range", "Start address must be less than or equal to end address.")
        elif start_t < ida_ida.inf_get_min_ea() or end_t > ida_ida.inf_get_max_ea():
            QtWidgets.QMessageBox.warning(None, "Invalid Range", "Address out of range.")

        self.search_range_start = start_t
        self.search_range_end = end_t

        if start != -1 and end != -1:
            self.search_range_start_edit.setText(hex(start))
            self.search_range_end_edit.setText(hex(end))

    def _reset_range_button_clicked(self):
        search_range_start = ida_ida.inf_get_min_ea()
        search_range_end = ida_ida.inf_get_max_ea()
        self._set_search_range(search_range_start,search_range_end)


    def _open_select_function_dialog(self):
        target_func =  ida_kernwin.choose_func("Select target function",1)
        if not target_func:
            return

        self._set_search_range(target_func.start_ea, target_func.end_ea)

    def _open_select_segment_dialog(self):
        target_segm = ida_kernwin.choose_segm("Select target segment", 1)
        if not target_segm:
            return

        self._set_search_range(target_segm.start_ea, target_segm.end_ea)

    def _select_yara_rule_file(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(None, "Select YARA Rule File", "", "YARA Rule Files (*.yar);; All files (*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    rule_file_str = file.read()
                    self.yara_rule_edit.setText(rule_file_str)
            except Exception as e:
                QtWidgets.QMessageBox.warning(None, "Error", f"Failed to open file: {str(e)}")




    def _add_code_line(self):
        class add_code_form(idaapi.Form):
            def __init__(self):
                self.insn_mnen = ""
                self.operand1 = ""
                self.operand2 = ""
                self.operand3 = ""
                self.input_code = ""
                super(add_code_form, self).__init__(
                r'''STARTITEM 0
BUTTON YES* OK
Search: Add code

                {FormChangeCb}
                <Input target code: {_target_code}>

                Code part:
                <##- insn_mnen  :{_insn_mnen}>
                <##- operand1   :{_operand1}>
                <##- operand2   :{_operand2}>
                <##- operand3   :{_operand3}>
                ''',
                {
                "FormChangeCb": self.FormChangeCb(self.OnFormChange),

                "_target_code":self.StringInput(),

                "_insn_mnen": self.StringInput(value = self.insn_mnen,swidth = 20),
                "_operand1": self.StringInput(value = self.operand1,swidth = 20),
                "_operand2": self.StringInput(value = self.operand2,swidth = 20),
                "_operand3": self.StringInput(value = self.operand3,swidth = 20),
                }
                )
                self.Compile()

            def OnFormChange(self,fid):
                if fid == self._target_code.id:
                    target_code = self.GetControlValue(self._target_code)
                    target_code = target_code.replace(' ', ',', 1)
                    parts = target_code.split(',')
                    while len(parts) < 4:
                        parts.append("")

                    self.SetControlValue(self._insn_mnen, parts[0])
                    self.insn_mnen = parts[0]
                    for i, part in enumerate(parts[1:4], start=1):
                        if i < len(parts):
                            self.SetControlValue(getattr(self, f'_operand{i}'), part.strip())
                            if i == 1:
                                self.operand1 = part
                            elif i == 2:
                                self.operand2 = part
                            elif i == 3:
                                self.operand3 = part

                self.insn_mnen = self.GetControlValue(self._insn_mnen).strip()
                self.operand1 = self.GetControlValue(self._operand1).strip()
                self.operand2 = self.GetControlValue(self._operand2).strip()
                self.operand3 = self.GetControlValue(self._operand3).strip()

                if fid in [self._insn_mnen.id, self._operand1.id, self._operand2.id, self._operand3.id]:
                    self.SetControlValue(self._target_code, self.generate_input_code())


                return 1

            def generate_input_code(self):
                self.input_code = ""
                insn_mnen = self.insn_mnen.strip()
                operand1 = self.operand1.strip()
                operand2 = self.operand2.strip()
                operand3 = self.operand3.strip()
                if operand3 != "":
                    self.input_code = operand3

                if operand2 != "" and self.input_code != "":
                    self.input_code = operand2 + ", " + self.input_code
                elif operand2 == "" and self.input_code != "":
                    self.input_code = "??" + ", " + self.input_code
                else:
                    self.input_code = operand2

                if operand1 != "" and self.input_code != "":
                    self.input_code = operand1 + ", " + self.input_code
                elif operand1 == "" and self.input_code != "":
                    self.input_code = "??" + ", " + self.input_code
                else:
                    self.input_code = operand1

                if insn_mnen != "" and self.input_code != "":
                    self.input_code = insn_mnen + " " + self.input_code
                elif insn_mnen == "" and self.input_code != "":
                    self.input_code = "??" + " " + self.input_code
                else:
                    self.input_code = insn_mnen

                return self.input_code


            def get_assembly_code_line(self):
                self.insn_mnen = self.insn_mnen.strip() if self.insn_mnen is not None else None
                self.operand1 = self.operand1.strip() if self.operand1 is not None else None
                self.operand2 = self.operand2.strip() if self.operand2 is not None else None
                self.operand3 = self.operand3.strip() if self.operand3 is not None else None
                return assembly_code_line(self.insn_mnen, self.operand1, self.operand2, self.operand3)


        form = add_code_form()
        Is_add_code = form.Execute()
        if Is_add_code:
            asm_line = form.get_assembly_code_line()
            item = QtWidgets.QTreeWidgetItem([
                form.generate_input_code(),
                asm_line.insn_mnen,
                asm_line.operand1,
                asm_line.operand2,
                asm_line.operand3
            ])
            self.search_code_tree.addTopLevelItem(item)
        form.Free()



    def extract_assembly_code_lines(self):
        assembly_codes = []
        for index in range(self.search_code_tree.topLevelItemCount()):
            item = self.search_code_tree.topLevelItem(index)

            insn_mnen = item.text(1)
            operand1 = item.text(2)
            operand2 = item.text(3)
            operand3 = item.text(4)

            asm_line = assembly_code_line(insn_mnen if insn_mnen else None,
                                        operand1 if operand1 else None,
                                        operand2 if operand2 else None,
                                        operand3 if operand3 else None)
            assembly_codes.append(asm_line)

        return assembly_codes

    @staticmethod
    def _string_to_address(s):
        try:
            s = s.strip()
            s_lower = s.lower()
            if s_lower.startswith('0x'):
                num = int(s, 16)
            else:
                has_hex = any(c in 'abcdef' for c in s_lower)
                if has_hex:
                    num = int(s, 16)
                else:
                    num = int(s)
        except ValueError:
            return ''

        inf = idaapi.get_inf_structure()
        if inf.is_64bit():
            max_val = 0xFFFFFFFFFFFFFFFF
            byte_len = 8
        elif inf.is_32bit():
            max_val = 0xFFFFFFFF
            byte_len = 4
        else:
            return ''

        if num < 0 or num > max_val:
            return ''
        byteorder = 'big' if inf.is_be() else 'little'
        
        addr_bytes = num.to_bytes(byte_len, byteorder)
        s = ""
        for byte in addr_bytes:
            s += hex(byte)[2:] + " "
        return s

    """
    Search Function
    model: int
    0: Search All
    1: Search Next
    2: Search Previous
    """
    def _start_search(self,model:int):
        self._set_search_range(-1,-1)
        search_results =[]
        ea = idaapi.get_screen_ea()

        if model == 0 and self.search_type_comboBox.currentIndex() in [0,1,3]:
            idaapi.show_wait_box("Searching, Please Wait...")
        try:

            if self.search_type_comboBox.currentIndex() == 0:
                search_config = data_search_config()
                search_config.set_range(self.search_range_start, self.search_range_end)
                if model == 1:
                    search_config.set_search_once(idc.prev_head(ea,self.search_range_start),ida_bytes.BIN_SEARCH_BACKWARD)
                elif model == 2:
                    search_config.set_search_once(idc.next_head(ea,self.search_range_end),ida_bytes.BIN_SEARCH_FORWARD)
                if self.addr_search_config.isChecked():
                    search_addr = self.search_keyword_edit.toPlainText()
                    search_config.set_keyword(self._string_to_address(search_addr))
                    search_config.set_case_sensitive(True)
                    search_config.set_bytes_search(True)
                else:
                    search_config.set_keyword(self.search_keyword_edit.toPlainText())
                    search_config.set_case_sensitive( self.case_sensitive_config.isChecked())
                    search_config.set_bytes_search( self.bytes_search_config.isChecked())
                search_config.set_fuzzy(self.fuzzy_search_config.isChecked(), self.fuzzy_search_slider.value())
                search_results = SearchManager().bytes_search(search_config)


            elif self.search_type_comboBox.currentIndex() == 1:
                search_config = comments_search_config()
                search_config.set_range(self.search_range_start, self.search_range_end)
                if model == 1:
                    search_config.set_search_once(idc.prev_head(ea,self.search_range_start),ida_bytes.BIN_SEARCH_BACKWARD)
                elif model == 2:
                    search_config.set_search_once(idc.next_head(ea,self.search_range_end),ida_bytes.BIN_SEARCH_FORWARD)
                search_config.set_keyword(self.search_keyword_edit.toPlainText())
                search_config.set_fuzzy(self.fuzzy_search_config.isChecked(), self.fuzzy_search_slider.value())
                search_results = SearchManager().comments_search(search_config)


            elif self.search_type_comboBox.currentIndex() == 2:
                search_config = names_search_config()
                search_config.set_range(self.search_range_start, self.search_range_end)
                if model == 1:
                    search_config.set_search_once(idc.prev_head(ea,self.search_range_start),ida_bytes.BIN_SEARCH_BACKWARD)
                elif model == 2:
                    search_config.set_search_once(idc.next_head(ea,self.search_range_end),ida_bytes.BIN_SEARCH_FORWARD)
                search_config.set_keyword(self.search_keyword_edit.toPlainText())
                search_config.set_fuzzy(self.fuzzy_search_config.isChecked(), self.fuzzy_search_slider.value())
                search_results = SearchManager().names_search(search_config)


            elif self.search_type_comboBox.currentIndex() == 3:
                search_config = code_search_config()
                search_config.set_range(self.search_range_start, self.search_range_end)
                if model == 1:
                    search_config.set_search_once(idc.prev_head(ea,self.search_range_start),ida_bytes.BIN_SEARCH_BACKWARD)
                elif model == 2:
                    search_config.set_search_once(idc.next_head(ea,self.search_range_end),ida_bytes.BIN_SEARCH_FORWARD)
                search_config.set_code_search_target(self.extract_assembly_code_lines())
                search_results = SearchManager().assembly_code_search(search_config)


            elif self.search_type_comboBox.currentIndex() == 4:
                search_config = yara_search_config()
                search_config.set_range(self.search_range_start, self.search_range_end)
                try:
                    search_config.set_rules_by_str(self.yara_rule_edit.toPlainText())
                except Exception as e:
                    QtWidgets.QMessageBox.warning(None, "Error", f"Failed to compile rule: {str(e)}")
                    return
                search_results = SearchManager().yara_search(search_config)

        finally:
            idaapi.hide_wait_box()



        if model == 0:
            if self.search_type_comboBox.currentIndex() in [0,1,2,3]:
                self.search_result_tree.clear()
                for result in search_results:
                    item = QtWidgets.QTreeWidgetItem([
                        None,
                        hex(result.address),
                        result.type,
                        result.detail
                    ])
                    self.search_result_tree.addTopLevelItem(item)
            elif self.search_type_comboBox.currentIndex() == 4:
                self.search_result_tree.clear()
                for result in search_results:
                    item = QtWidgets.QTreeWidgetItem([
                        result.match_rule,
                        hex(result.address),
                        result.identifier,
                        result.detail,
                        result.matched_data
                    ])
                    self.search_result_tree.addTopLevelItem(item)

        else:
            if self.search_type_comboBox.currentIndex() in [0,1,2,3] and search_results:
                target_addr = search_results[0].address
                idaapi.jumpto(target_addr)
            else:
                target_addr = 0;
                current_addr = idc.get_screen_ea()
                if model == 1:
                    for result in search_results:
                        if result.address >= current_addr:
                            break
                        target_addr = result.address
                elif model == 2:
                    for result in search_results:
                        if result.address >= current_addr + idc.get_item_size(current_addr):
                            target_addr = result.address
                            break
                idaapi.jumpto(target_addr)



class SearchMenuHandler(idaapi.action_handler_t):
    @classmethod
    def get_name(cls):
        return cls.__name__

    @classmethod
    def get_label(cls):
        return cls.label

    @classmethod
    def register(cls, plugin, label, hotkey):
        cls.plugin = plugin
        cls.label = label
        instance = cls()
        return idaapi.register_action(idaapi.action_desc_t(cls.get_name(),instance.get_label(),instance,hotkey))

    @classmethod
    def unregister(cls):
        idaapi.unregister_action(cls.get_name())

    @classmethod
    def activate(cls,ctx):
        form = SearchForm()
        form.Show("SearchTool")


    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class SearchTool(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "SearchTool"
    wanted_hotkey = "Shift-F"


    def __init__(self):
        super(SearchTool, self).__init__()
        self.name = "SearchTool"
        self.version = VERSION
        self.description = "A plugin for searching data in IDA"


    def term(self):
        pass

    def init(self):
        SearchMenuHandler.register(self, "Search Tool", "")
        idaapi.attach_action_to_menu("Search/Search Tool", SearchMenuHandler.get_name(), idaapi.SETMENU_APP)
        return idaapi.PLUGIN_OK

    def run(self, arg):
        form = SearchForm()
        form.Show("SearchTool")


def PLUGIN_ENTRY():
    return SearchTool()

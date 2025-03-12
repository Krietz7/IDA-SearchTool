import bisect

import idc
import idaapi
import ida_ida
import ida_lines
import idautils
import ida_bytes
import ida_kernwin

from PyQt5 import QtWidgets,QtCore

try:
    # import fuzzywuzzy
    pass
except:
    fuzzywuzzy = None
try:
    # import yara
    pass
except:
    yara = None







class search_config_base():
    def __init__(self):
        self.start = -1
        self.end = -1
        self.search_once = False
        self.search_direction = ida_bytes.BIN_SEARCH_FORWARD
        self.current_addr = -1

    def set_range(self, start:int, end:int):
        if start > end or start < ida_ida.inf_get_min_ea() or end > ida_ida.inf_get_max_ea():
            return
        self.start = start
        self.end = end

    '''
    search_direction: 
    ida_bytes.BIN_SEARCH_FORWARD or ida_bytes.BIN_SEARCH_BACKWARD
    '''
    def set_search_once(self, current_addr:int, search_direction:int):
        if current_addr >= ida_ida.inf_get_max_ea() or current_addr <= ida_ida.inf_get_min_ea():
            return
        self.search_once = True
        if current_addr < self.start:
            self.current_addr = self.start
        elif current_addr > self.end:
            self.current_addr = self.end
        self.current_addr = current_addr
        self.search_direction = search_direction

    def get_range(self):
        return self.start, self.end

    def is_search_once(self):
        return self.search_once

    def get_current_addr(self):
        return self.current_addr
    
    def get_search_direction(self):
        return self.search_direction


'''
Data search configuration
- Range: start, end
- Keyword: keyword
- Config: case sensitive,Fuzzy
'''
class data_search_config(search_config_base):
    def __init__(self):
        super().__init__()
        self.keyword = None

        self.case_sensitive = ida_bytes.BIN_SEARCH_CASE
        self.is_fuzzy = False


    def set_keyword(self, keyword: str):
        if not type(keyword) is str:
            return
        self.keyword = keyword

    def get_keyword(self):
        return self.keyword

    def set_case_sensitive(self, case_sensitive: bool):
        self.case_sensitive = ida_bytes.BIN_SEARCH_CASE if case_sensitive else ida_bytes.BIN_SEARCH_NOCASE

    def get_flag(self):
        return self.search_direction | self.case_sensitive | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW



'''
Symbol search configuration
- Range: start, end
- Keyword: keyword
'''
class comments_search_config(search_config_base):
    def __init__(self):
        super().__init__()
        self.keyword = None

    def set_keyword(self, keyword: str):
        if not type(keyword) is str:
            return
        self.keyword = keyword

    def get_keyword(self):
        return self.keyword


class names_search_config(search_config_base):
    def __init__(self):
        super().__init__()
        self.keyword = None
        self.is_search_comments = True
        self.is_search_names = True

    def set_keyword(self, keyword: str):
        if not type(keyword) is str:
            return
        self.keyword = keyword

    def get_keyword(self):
        return self.keyword

class search_result_base:
    def __init__(self):
        self.address = -1
        self.type = -1
        self.detail = None


'''Search Result Type'''
HEX_DATA = 1
COMMENT = 2
NAME = 3
CODE = 4 

type_str_dict = {
    HEX_DATA : "address",
    COMMENT : "Comment",
    NAME : "Name",
    CODE : "Code",
}


class search_result_base:
    def __init__(self):
        self.icon = ""
        self.address = -1
        self.type = -1
        self.detail = None

class hex_data_result(search_result_base):
    def __init__(self, address:int, length:int):
        super().__init__()
        self.address = address
        self.type = HEX_DATA


        disasm = idc.generate_disasm_line(address,0)
        if(length <= 5):
            data_byte = idc.get_bytes(address,length)
            self.detail = ' '.join([f"{i:02X}" for i in bytearray(data_byte)]) + "  (" + disasm + ")"
        else:
            data_byte = idc.get_bytes(address,5)
            self.detail = ' '.join([f"{i:02X}" for i in bytearray(data_byte)]) + "...   (" + disasm + ")"

class comment_result(search_result_base):
    def __init__(self, address:int, comment:str):
        super().__init__()
        self.address = address
        self.type = COMMENT
        self.detail = ''.join([char for char in comment if char.isprintable() and not char.isspace() or char == ' '])

class name_result(search_result_base):
    def __init__(self, address:int, name:str):
        super().__init__()
        self.address = address
        self.type = NAME
        self.detail = name

class code_result(search_result_base):
    def __init__(self, address:int):
        super().__init__()
        self.address = address
        self.type = CODE
        self.detail = idc.generate_disasm_line(address,0)





class assembly_code_line():
    def __init__(self, insn_mnen:str = None, operand1:str = None, operand2:str = None, operand3:str = None):
        self.insn_mnen = insn_mnen
        self.operand1 = operand1
        self.operand2 = operand2
        self.operand3 = operand3

class code_search_config(search_config_base):
    def __init__(self):
        super().__init__()
        self.code_search_targets = []

    def set_code_search_target(self, list):
        if not all(isinstance(x, assembly_code_line) for x in list):
            return 
        self.code_search_targets = list
    
    def get_code_search_targets(self):
        return self.code_search_targets

class SearchManager():
    def __init__(self):
        pass

    @classmethod
    def bytes_search(cls,data_search_config):
        # keyword format: see ida_bytes.parse_binpat_str()
        start, end = data_search_config.get_range()
        keyword = data_search_config.get_keyword()
        flag = data_search_config.get_flag()
        if keyword is None or flag is None:
            return []

        patterns = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(patterns, 0, keyword, 16)
        if err:
            return []
            
        current_addr = data_search_config.get_current_addr()
        if data_search_config.is_search_once():
            if current_addr > end or current_addr < start  or current_addr == -1:
                return []
            elif data_search_config.get_search_direction() == ida_bytes.BIN_SEARCH_FORWARD:
                start = current_addr
            else:
                end = current_addr

            addr = ida_bytes.bin_search(start, end, patterns, flag)
            if(addr == idaapi.BADADDR):
                return []
            return [hex_data_result(addr, len(patterns))]

        if start == -1 or end == -1:
            return []
        ea = start
        search_result_list = []
        while ea < end:
            ea = ida_bytes.bin_search(ea, end, patterns, flag)
            if(ea == idaapi.BADADDR):
                break
            search_result_list.append(hex_data_result(ea, len(patterns)))
            ea = idc.next_head(ea,end)
        return search_result_list



    @classmethod
    def comments_search(cls,comments_search_config):
        start, end = comments_search_config.get_range()
        keyword = comments_search_config.get_keyword()
        if keyword is None or keyword == "":
            return []
    
        def find_comment(line):
            for cmt_type in [
                    ida_lines.SCOLOR_REGCMT,
                    ida_lines.SCOLOR_RPTCMT,
                    ida_lines.SCOLOR_AUTOCMT]:
                cmt_idx = line.find(ida_lines.SCOLOR_ON + cmt_type)
                if cmt_idx > -1:
                    return cmt_idx
            return -1

        current_addr = comments_search_config.get_current_addr()
        if comments_search_config.is_search_once():
            if current_addr > end or current_addr < start or current_addr == -1:
                return []
            step_function = ida_bytes.next_head if comments_search_config.get_search_direction() == ida_bytes.BIN_SEARCH_FORWARD else ida_bytes.prev_head
            boundary_condition = lambda ea: ea < end if comments_search_config.get_search_direction() == ida_bytes.BIN_SEARCH_FORWARD else ea >= start

            ea = current_addr
            while boundary_condition(ea):
                line = ida_lines.generate_disasm_line(ea)
                cmt_idx = find_comment(line)
                if cmt_idx != -1 and keyword in line[cmt_idx:]:
                    return [comment_result(ea, line[cmt_idx:])]
                ea = step_function(ea, end if comments_search_config.get_search_direction() == ida_bytes.BIN_SEARCH_FORWARD else start)
                if ea == idaapi.BADADDR:
                    break
            return []

        search_result_list = []
        ea = start
        while ea < end:
            line = ida_lines.generate_disasm_line(ea,ida_lines.GENDSM_FORCE_CODE)
            cmt_idx = find_comment(line)
            if cmt_idx != -1:
                if keyword in line[cmt_idx:]:
                    search_result_list.append(comment_result(ea, line[cmt_idx:]))
            ea = ida_bytes.next_head(ea, end)
            if ea == idaapi.BADADDR:
                break
        return search_result_list

    @classmethod
    def names_search(cls, names_search_config):
        start, end = names_search_config.get_range()
        keyword = names_search_config.get_keyword()

        if keyword is None or keyword == "":
            return []

        addr_name_dict = sorted(
            [(address, name) for address, name in idautils.Names() 
             if keyword in name and start <= address <= end],
            key=lambda x: x[0]
        )

        current_addr = names_search_config.get_current_addr()
        search_direction = names_search_config.get_search_direction()

        if names_search_config.is_search_once():
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
                    if find_code_snippet(current_addr, code_search_targets,end):
                        return [code_result(current_addr)]
                    
                    current_addr = ida_bytes.prev_head(current_addr, start)
                    if current_addr == idaapi.BADADDR or current_addr < start:

                        break
            return []

        ea = start
        search_result_list = []
        while ea < end:
            if find_code_snippet(ea, code_search_targets, end):
                search_result_list.append(code_result(ea))
            ea = ida_bytes.next_head(ea, end)
            if ea == idaapi.BADADDR or ea >= end:
                break
        return search_result_list



class SearchForm(idaapi.PluginForm):
    search_type = {
        "Data": 0,
        "Comments": 1,
        "Names": 2,
        "Assembly Code": 3,
    }
    search_range_start = ida_ida.inf_get_min_ea()
    search_range_end = ida_ida.inf_get_max_ea()


    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.InitUi()

    def InitUi(self):
        self.layout = QtWidgets.QVBoxLayout()

        self.search_configure_box = self._search_configure_box_init()
        self.search_result_box = self._search_result_box_init()

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter.addWidget(self.search_configure_box)
        splitter.addWidget(self.search_result_box)

        self.layout.addWidget(splitter)
        self.parent.setLayout(self.layout)
        return

    def OnClose(self, form):
        pass


    def _search_configure_box_init(self):
        self.SearchConfigureBox = QtWidgets.QGroupBox()
        self.SearchConfigureBox.setMinimumWidth(750)
        SearchConfigureLayout = QtWidgets.QVBoxLayout()

        """Search Type Select"""
        search_type_box = QtWidgets.QGroupBox("Search Type:")
        search_type_layout = QtWidgets.QVBoxLayout()
        
        self.search_type_comboBox = QtWidgets.QComboBox()
        self.search_type_comboBox.setMaximumWidth(200)
        for key in self.search_type.keys():
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
        self.search_keyword_edit.setAcceptRichText(False)
        search_keyword_layout.addWidget(self.search_keyword_edit)

        self.search_keyword_box.setLayout(search_keyword_layout)
        SearchConfigureLayout.addWidget(self.search_keyword_box)

        '''code input box'''
        self.search_code_box = QtWidgets.QGroupBox("Search Code:")
        search_code_layout = QtWidgets.QVBoxLayout()

        self.search_code_tree = QtWidgets.QTreeWidget()
        self.search_code_tree.setHeaderLabels(["Code","Instruction Mnemonic", "Operand 1", "Operand 2", "Operand 3"])
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

        """Configure"""
        self.data_configure_box = QtWidgets.QGroupBox("Advanced Configure:")
        data_configure_layout = QtWidgets.QVBoxLayout()


        self.case_sensitive_config = QtWidgets.QCheckBox("Case sensitive")
        data_configure_layout.addWidget(self.case_sensitive_config)

        
        self.fuuzy_search_config = QtWidgets.QCheckBox("Fuzzy Search")
        data_configure_layout.addWidget(self.fuuzy_search_config)




        self.data_configure_box.setLayout(data_configure_layout)
        SearchConfigureLayout.addWidget(self.data_configure_box)

        """Search Start Button"""

        search_button_box = QtWidgets.QGroupBox()
        search_button_layout = QtWidgets.QHBoxLayout()
        search_button_layout.addStretch(1)

        search_all_button = QtWidgets.QPushButton("Search All")
        search_all_button.clicked.connect(lambda: self._start_search(0))
        search_all_button.setMinimumWidth(200)
        search_button_layout.addWidget(search_all_button)

        search_next_button = QtWidgets.QPushButton("Search Next")
        search_next_button.clicked.connect(lambda: self._start_search(1))
        search_next_button.setMinimumWidth(200)
        search_button_layout.addWidget(search_next_button)


        search_previous_button = QtWidgets.QPushButton("Search Previous")
        search_previous_button.clicked.connect(lambda: self._start_search(2))
        search_previous_button.setMinimumWidth(200)
        search_button_layout.addWidget(search_previous_button)

        search_button_layout.addStretch(1)
        search_button_box.setLayout(search_button_layout)   
        SearchConfigureLayout.addWidget(search_button_box)

        # connect select_type_comboBox to self._on_search_type_changed after initialization
        self.search_type_comboBox.currentIndexChanged.connect(self._on_search_type_changed)
        self._on_search_type_changed(0)
        self.SearchConfigureBox.setLayout(SearchConfigureLayout)
        return self.SearchConfigureBox

    def _search_result_box_init(self):
        self.SearchResultBox = QtWidgets.QGroupBox()
        self.SearchResultLayout = QtWidgets.QVBoxLayout()

        search_result_box = QtWidgets.QGroupBox("Search Result")
        search_result_box.setMinimumWidth(750)
        search_result_layout = QtWidgets.QVBoxLayout()

        self.search_result_tree = QtWidgets.QTreeWidget()
        self.search_result_tree.setHeaderLabels(["icon","Type","Address","Detail"])
        search_result_layout.addWidget(self.search_result_tree)
        search_result_box.setLayout(search_result_layout)

        self.SearchResultLayout.addWidget(search_result_box)
        self.SearchResultBox.setLayout(self.SearchResultLayout)
        return self.SearchResultBox




    def _on_search_type_changed(self, index):
        current_text = self.search_type_comboBox.itemText(index)
        print(self.search_type[current_text])

        if(self.search_type[current_text] in [0,1,2]):
            self.search_keyword_box.show()
            self.data_configure_box.show()
            self.search_code_box.hide()

        elif(self.search_type[current_text] == 3):
            self.search_keyword_box.hide()
            self.data_configure_box.hide()
            self.search_code_box.show()


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




    """
    Search Function
    model: int
    0: Search All
    1: Search Next
    2: Search Previous
    """
    def _start_search(self,model:int):
        self._set_search_range(-1,-1)
        self.search_result_tree.clear()
        search_results =[]
        if(self.search_type_comboBox.currentIndex() == 0):
            search_config = data_search_config()
            search_config.set_range(self.search_range_start, self.search_range_end)
            if(model == 1):
                search_config.set_search_once(idaapi.get_screen_ea(),ida_bytes.BIN_SEARCH_FORWARD)
            elif(model == 2):
                search_config.set_search_once(idaapi.get_screen_ea(),ida_bytes.BIN_SEARCH_BACKWARD)
            search_config.set_keyword(self.search_keyword_edit.toPlainText())
            search_config.set_case_sensitive( self.case_sensitive_config.isChecked())
            search_results = SearchManager().bytes_search(search_config)


        elif(self.search_type_comboBox.currentIndex() == 1):
            search_config = comments_search_config()
            search_config.set_range(self.search_range_start, self.search_range_end)
            if(model == 1):
                search_config.set_search_once(idaapi.get_screen_ea(),ida_bytes.BIN_SEARCH_FORWARD)
            elif(model == 2):
                search_config.set_search_once(idaapi.get_screen_ea(),ida_bytes.BIN_SEARCH_BACKWARD)
            search_config.set_keyword(self.search_keyword_edit.toPlainText())
            search_results = SearchManager().comments_search(search_config)


        elif(self.search_type_comboBox.currentIndex() == 2):
            search_config = names_search_config()
            search_config.set_range(self.search_range_start, self.search_range_end)
            if(model == 1):
                search_config.set_search_once(idaapi.get_screen_ea(),ida_bytes.BIN_SEARCH_FORWARD)
            elif(model == 2):
                search_config.set_search_once(idaapi.get_screen_ea(),ida_bytes.BIN_SEARCH_BACKWARD)
            search_config.set_keyword(self.search_keyword_edit.toPlainText())
            search_results = SearchManager().names_search(search_config)


        elif(self.search_type_comboBox.currentIndex() == 3):
            search_config = code_search_config()
            search_config.set_range(self.search_range_start, self.search_range_end)
            if(model == 1):
                search_config.set_search_once(idaapi.get_screen_ea(),ida_bytes.BIN_SEARCH_FORWARD)
            elif(model == 2):
                search_config.set_search_once(idaapi.get_screen_ea(),ida_bytes.BIN_SEARCH_BACKWARD)
            search_config.set_code_search_target(self.extract_assembly_code_lines())
            search_results = SearchManager().assembly_code_search(search_config)

        for result in search_results:
            item = QtWidgets.QTreeWidgetItem([
                result.icon,
                type_str_dict[result.type],
                hex(result.address),
                result.detail
            ])
            self.search_result_tree.addTopLevelItem(item)








class SearchTool(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "Search"
    wanted_hotkey = "Shift-F"


    def __init__(self):
        super(SearchTool, self).__init__()
        self.name = "Search"
        self.version = "0.5"
        self.description = "A plugin for searching data in IDA"

    def term(self):
        pass

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        form = SearchForm()
        form.Show("Search")
        pass


# def PLUGIN_ENTRY():
#     return SearchTool()
# idaapi.load_plugin("F:\\Projects\\IDA-Search\\Search.py")

form = SearchForm()
form.Show("Search")




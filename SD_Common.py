"""
    SD_Common   common functions definition class.

    by ZaiRoN (zairon.wordpress.com)
    Copyright (C) 2015

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import struct

import idc
import idautils

class sd_common:

    def __init__(self):
        pass

    """
        apply_snippet_to_disasm     set name, description and available comments of the detected snippet
                                    Params:
                                    - _func_address     start address of the function
                                    - _snippet_info     info to set (name, description and comments)
    """
    def apply_snippet_to_disasm(self, _func_address, _snippet_info):
        # set function name
        snippet_name = _snippet_info[0]
        while idc.MakeNameEx(_func_address, snippet_name, idc.SN_NON_AUTO) == 0:
            snippet_name = idc.AskStr('', ' function name is already used, try another one')
            if snippet_name is None:
                return(False)

        # set function description
        idc.SetFunctionCmt(_func_address, _snippet_info[1], 0)

        # set comment(s)
        comments = _snippet_info[4]
        while comments:
            comm_len = struct.unpack('>I', comments[:4])[0]
            comments = comments[4:]
            offset = struct.unpack('>I', comments[:4])[0]
            comments = comments[4:]
            idc.MakeComm(_func_address + offset, comments[:comm_len])
            comments = comments[comm_len:]
        return True


    """
        get_start_end_function      get the start and end addresses of a function
                                    Param:
                                    - addr      address belonging to the function
    """
    def get_start_end_function(self, _addr):
        return idc.GetFunctionAttr(_addr, idc.FUNCATTR_START), idc.GetFunctionAttr(_addr, idc.FUNCATTR_END)


    """
        get_total_instructions      get the number of instructions of a function
                                    Params:
                                    - _start    function start address
                                    - _end      function end address
    """
    def get_total_instructions(selfself, _start, _end):
        return len(list(idautils.Heads(_start, _end)))


    """
        get_comments    prepare the comments to save inside the snippet. Comments are saved using this scheme:
                        <len_comment_1><instruction_1_offset><comment_1><len_comment_2><instruction_2_offset><comment_2>...
                        Params:
                            - _start    function start address
                            - _end      function end address
    """
    def get_comments(self, _start, _end):
        comments = ''
        # parse all the instructions
        for instr in idautils.Heads(_start, _end):
            if idc.GetFlags(instr) & idc.FF_COMM:
                # add the current instruction comment
                comments += struct.pack('>I', len(idc.Comment(instr))) + struct.pack(">I", instr - _start) + idc.Comment(instr)
        return comments


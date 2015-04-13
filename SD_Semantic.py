"""
    SD_Semantic     definition class of *semantic* stuff.

    by ZaiRoN (zairon.wordpress.com)
    Copyright (C) 2015- ZaiRoN (zaironcrk@hotmail.com)

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

import idc
import idautils

valid_types = [idc.o_imm, idc.o_mem, idc.o_displ, idc.o_far, idc.o_near]

class semantic:

    def __init__(self):
        pass

    """
        get_first_numerical_operand_offset      get the offset of the first numerical operand. Numerical stands for
                                                o_mem, o_phrase, o_displ, o_imm, o_far or o_near
    """
    def get_first_numerical_operand_offset(selfself, _info):
        _offset = 0
        for i in range(0, 6):
            if _info.Operands[i]:
                if idc.GetOpType(_info.ea, i) in valid_types:
                    _offset = _info.Operands[i].offb
                    return _offset
        return _offset


    """
        get_semantic_bytes       conversion is done removing all the bytes after the first operand offset
    """
    def get_semantic_bytes(self, _addr, _first_offset):
        _semantic_instr = ''
        for i in range(_first_offset):
            _semantic_instr += chr(idc.Byte(_addr + i))
        return _semantic_instr


    """
        from_syntactic_to_semantic      converts a syntactic bytes sequence into a semantic one.
    """
    def from_syntactic_to_semantic(self, _start, _end):
        _sem = ''
        # Parse all the instructions inside the function
        for instr in idautils.Heads(_start, _end):
            flags = idc.GetFlags(instr)
            if idc.isCode(flags):         # Code: convert instruction
                info = idautils.DecodeInstruction(instr)
                first_offset = self.get_first_numerical_operand_offset(info)
                if first_offset != 0:
                    tmp = self.get_semantic_bytes(info.ea, first_offset)
                    if tmp is not None:
                        _sem += ''.join(tmp)
                    else:
                        return None
                else:
                    _sem += ''.join(chr(idc.Byte(info.ea + i)) for i in range(info.size))
            elif idc.isAlign(flags):      # align: copy the byte without semantic conversion
                _sem += idc.GetManyBytes(instr, idc.NextHead(instr) - instr, False)
        return _sem

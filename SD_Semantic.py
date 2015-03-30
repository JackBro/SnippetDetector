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
        get_numerical_operands_number    return the number of numerical operands of the instruction.
    """
    def get_numerical_operands_number(self, _info):
        n_op = 0
        for i in range(0, 6):
            if _info.Operands[i]:
                if idc.GetOpType(_info.ea, i) in valid_types:
                    n_op += 1
        return n_op

    """
        get_operand_value_len_in_bytes      return the length in bytes of an operand.
    """
    def get_operand_value_len_in_bytes(self, _info, op_offset, val):
        if _info.size - op_offset > 7:
            if idc.Qword(_info.ea + op_offset) == val:
                return 8
        if _info.size - op_offset > 3:
            if idc.Dword(_info.ea + op_offset) == val:
                return 4
        if _info.size - op_offset > 1:
            if idc.Word(_info.ea + op_offset) == (val & 0x0000FFFF):
                return 2
        if _info.size - op_offset > 0:
            if idc.Byte(_info.ea + op_offset) == (val & 0x000000FF):
                return 1
        return 0


    """
        get_semantic_bytes       conversion is done removing all the operands from every single instruction.
    """
    def get_semantic_bytes(self, _info):
        toremove = []
        # Check the instruction operands
        for i in range(0, 6):
            if _info.Operands[i].type in valid_types:
                op_offset = _info.Operands[i].offb
                if op_offset == 0:
                    return None
                # check the operand type
                t = _info.Operands[i].type
                if (t == idc.o_imm) or (t == idc.o_mem) or (t == idc.o_displ):
                    op_len = self.get_operand_value_len_in_bytes(_info, op_offset, idc.GetOperandValue(_info.ea, i))
                    if op_len == 0:
                        return None
                elif t == idc.o_near:
                    val = idc.GetOperandValue(_info.ea, i)
                    if int(val) > int(_info.ea):
                        op_len = self.get_operand_value_len_in_bytes(_info, op_offset, val - _info.ea - _info.size)
                    else:
                        op_len = self.get_operand_value_len_in_bytes(_info, op_offset, (0x100000000 + val) - _info.ea - _info.size)
                    if op_len == 0:
                        return None
                else:
                    return None
                # set the byte index to remove from the original bytes sequence
                for j in range(op_offset, op_offset + op_len):
                    toremove.append(j)

        # Seems like everything is ok, mnemonic bytes sequence creation
        _semantic_instr = ''
        for i in range(_info.size):
            if i not in toremove:
                _semantic_instr += chr(idc.Byte(_info.ea + i))
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
                # avoid special instructions like "int 3", "shr eax, 1", ...
                if ((idc.Byte(instr) == 0xCC) and (idc.ItemSize(instr) == 1)):
                    _sem += chr(idc.Byte(instr))
                elif (((idc.Byte(instr) == 0xD0) or (idc.Byte(instr) == 0xD1)) and (idc.ItemSize(instr) == 2)):
                    _sem += chr(idc.Byte(instr))
                    _sem += chr(idc.Byte(instr + 1))
                else:
					# non special instruction
                    info = idautils.DecodeInstruction(instr)
                    if self.get_numerical_operands_number(info) != 0:
                        tmp = self.get_semantic_bytes(info)
                        if tmp is not None:
                            _sem += ''.join(tmp)
                        else:
                            return None
                    else:
                        _sem += ''.join(chr(idc.Byte(info.ea + i)) for i in range(info.size))
            elif idc.isAlign(flags):      # align: copy the byte without semantic conversion
                _sem += idc.GetManyBytes(instr, idc.NextHead(instr) - instr, False)
        return _sem



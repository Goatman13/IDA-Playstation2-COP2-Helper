from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc
import binascii

def get_2bit_field(bc):

	if bc == 0:
		return "x"
	elif bc == 1:
		return "y"
	elif bc == 2:
		return "z"
	else:
		return "w"	

def get_4bit_field(field):

	if field == 1:
		return "w"
	elif field == 2:
		return "z"
	elif field == 4:
		return "y"
	elif field == 8:
		return "x"
	elif field == 3:
		return "zw"
	elif field == 5:
		return "yw"
	elif field == 6:
		return "yz"
	elif field == 9:
		return "xw"
	elif field == 10:
		return "xz"
	elif field == 12:
		return "xy"
	elif field == 7:
		return "yzw"
	elif field == 11:
		return "xzw"
	elif field == 13:
		return "xyw"			
	elif field == 14:
		return "xyz"
	elif field == 15:
		return "xyzw"
	else:
		warning("Opcode is missing dest!")

def cop2_vi(address, name, instruction, imm):

	dest = (instruction >> 6) & 0xF
	reg1 = (instruction >> 11) & 0xF
	reg2 = (instruction >> 16) & 0xF
	
	if imm == 1:
		string = name + " vi{:d}, vi{:d}, 0x{:X}"
		set_manual_insn(address, string.format(reg2, reg1, dest))
	else:
		string = name + " vi{:d}, vi{:d}, vi{:d}"
		set_manual_insn(address, string.format(dest, reg1, reg2))

def cop2_vitof(address, name, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field = get_4bit_field(field)
	
	string  = name + "." + field + " " +"vf{:d}, vf{:d}"
	set_manual_insn(address, string.format(dest, source))

def cop2_bc(address, name, instruction, is_ACC):
	
	bc = instruction & 0x3
	if is_ACC == 0:
		dest = (instruction >> 6) & 0x1F
	else:
		dest = 34
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	
	bc = get_2bit_field(bc)
	field = get_4bit_field(field)
	
	if dest == 34:
		dest_str = " ACC, "
	else: 
		dest_str = " vf{:d}, "
		
	string  = name + bc + "." + field + dest_str + "vf{:d}, vf{:d}" + bc
	if (dest == 34): 
		string  = string.format(source, bc_reg)
	else:
		string  = string.format(dest, source, bc_reg)
	
	set_manual_insn(address, string)

def cop2_3reg_vf(address, name, instruction, is_ACC, is_IQ):
	
	dest = (instruction >> 6) & 0x1F
	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF	
	field = get_4bit_field(field)
	
	if is_IQ == 1:
		reg2_str = ", I"
	elif is_IQ == 2:
		reg2_str = ", Q"
	else:
		reg2_str = ", vf{:d}"
		
	if is_ACC == 1:
		dest_str = " ACC, "
	else: 
		dest_str = " vf{:d}, "
	
	string  = name + "." + field + dest_str + "vf{:d}" + reg2_str
	
	if is_IQ >= 1 and is_ACC == 1:
		string  = string.format(reg1)
	elif is_IQ >= 1 and is_ACC == 0:
		string  = string.format(dest, reg1)
	elif is_IQ == 0 and is_ACC == 1:
		string  = string.format(reg1, reg2)
	else:
		string  = string.format(dest, reg1, reg2)
		
	set_manual_insn(address, string)	

def cop2_special(address, instruction):

	op = instruction & 0x3F

	if op <= 0x03:
		cop2_bc(address, "vadd", instruction, 0)
	elif op >= 0x04 and op <= 0x07:
		cop2_bc(address, "vsub", instruction, 0)
	elif op >= 0x08 and op <= 0x0B:
		cop2_bc(address, "vmadd", instruction, 0)
	elif op >= 0x0C and op <= 0x0F:
		cop2_bc(address, "vmsub", instruction, 0)
	elif op >= 0x10 and op <= 0x13:
		cop2_bc(address, "vmax", instruction, 0)
	elif op >= 0x14 and op <= 0x17:
		cop2_bc(address, "vmini", instruction, 0)
	elif op >= 0x18 and op <= 0x1B:
		cop2_bc(address, "vmul", instruction, 0)
	elif op == 0x1C:
		cop2_3reg_vf(address, "vmulq", instruction, 0 ,2)
	elif op == 0x1D:
		cop2_3reg_vf(address, "vmaxi", instruction, 0 ,1)
	elif op == 0x1E:
		cop2_3reg_vf(address, "vmuli", instruction, 0 ,1)
	elif op == 0x1F:
		cop2_3reg_vf(address, "vminii", instruction, 0 ,1)
	elif op == 0x20:
		cop2_3reg_vf(address, "vaddq", instruction, 0 ,2)
	elif op == 0x21:
		cop2_3reg_vf(address, "vmaddq", instruction, 0 ,2)
	elif op == 0x22:
		cop2_3reg_vf(address, "vaddi", instruction, 0 ,1)
	elif op == 0x23:
		cop2_3reg_vf(address, "vmaddi", instruction, 0 ,1)
	elif op == 0x24:
		cop2_3reg_vf(address, "vsubq", instruction, 0 ,2)
	elif op == 0x25:
		cop2_3reg_vf(address, "vmsubq", instruction, 0 ,2)
	elif op == 0x26:
		cop2_3reg_vf(address, "vsubi", instruction, 0 ,1)
	elif op == 0x27:
		cop2_3reg_vf(address, "vmsubi", instruction, 0 ,1)
	elif op == 0x28:
		cop2_3reg_vf(address, "vadd", instruction, 0 ,0)
	elif op == 0x29:
		cop2_3reg_vf(address, "vmadd", instruction, 0 ,0)
	elif op == 0x2A:
		cop2_3reg_vf(address, "vmul", instruction, 0 ,0)
	elif op == 0x2B:
		cop2_3reg_vf(address, "vmax", instruction, 0 ,0)
	elif op == 0x2C:
		cop2_3reg_vf(address, "vsub", instruction, 0 ,0)
	elif op == 0x2D:
		cop2_3reg_vf(address, "vmsub", instruction, 0 ,0)
	elif op == 0x2E:
		cop2_vopmsub(address, instruction)
	elif op == 0x2F:
		cop2_3reg_vf(address, "vmini", instruction, 0 ,0)
	elif op == 0x30:
		cop2_vi(address, "viadd", instruction, 0)
	elif op == 0x31:
		cop2_vi(address, "visub", instruction, 0)
	elif op == 0x32:
		cop2_vi(address, "viaddi", instruction, 1)
	elif op == 0x34:
		cop2_vi(address, "viand", instruction, 0)
	elif op == 0x35:
		cop2_vi(address, "vior", instruction, 0)
	elif op == 0x38:
		cop2_vcallms(address, instruction)
	elif op == 0x39:
		set_manual_insn(address, "vcallmsr")
	elif op >= 0x3C and op <= 0x3F:
		cop2_special2(address, instruction)

def cop2_vopmsub(address, instruction):

	dest = (instruction >> 6) & 0x1F
	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	string = "vopmsub.xyz vf{:d}, vf{:d}, vf{:d}"
	set_manual_insn(address, string.format(dest, reg1, reg2))	

def cop2_vcallms(address, instruction):

	imm = (instruction >> 6) & 0x7FFF
	imm2 = imm * 8
	string = "vcallms {:X} (0x{:X})"
	set_manual_insn(address, string.format(imm, imm2))

def cop2_special2(address, instruction):

	op = (instruction & 0x3) | ((instruction >> 4) & 0x7C)
	
	if op <= 0x03:
		cop2_bc(address, "vadda", instruction, 1)
	elif op >= 0x04 and op <= 0x07:
		cop2_bc(address, "vsuba", instruction, 1)
	elif op >= 0x08 and op <= 0x0B:
		cop2_bc(address, "vmadda", instruction, 1)
	elif op >= 0x0C and op <= 0x0F:
		cop2_bc(address, "vmsuba", instruction, 1)
	elif op == 0x10:
		cop2_vitof(address, "vitof0", instruction)
	elif op == 0x11:
		cop2_vitof(address, "vitof4", instruction)
	elif op == 0x12:
		cop2_vitof(address, "vitof12", instruction)
	elif op == 0x13:
		cop2_vitof(address, "vitof15", instruction)
	elif op == 0x14:
		cop2_vitof(address, "vftoi0", instruction)
	elif op == 0x15:
		cop2_vitof(address, "vftoi4", instruction)
	elif op == 0x16:
		cop2_vitof(address, "vftoi12", instruction)
	elif op == 0x17:
		cop2_vitof(address, "vftoi15", instruction)
	elif op >= 0x18 and op <= 0x1B:
		cop2_bc(address, "vmula", instruction, 1)
	elif op == 0x1C:
		cop2_3reg_vf(address, "vmulaq", instruction, 1, 2)
	elif op == 0x1D:
		cop2_vitof(address, "vabs", instruction)
	elif op == 0x1E:
		cop2_3reg_vf(address, "vmulai", instruction, 1, 1)
	elif op == 0x1F:
		cop2_vclip(address, instruction)
	elif op == 0x20:
		cop2_3reg_vf(address, "vaddaq", instruction, 1, 2)
	elif op == 0x21:
		cop2_3reg_vf(address, "vmaddaq", instruction, 1, 2)
	elif op == 0x22:
		cop2_3reg_vf(address, "vaddai", instruction, 1, 1)
	elif op == 0x23:
		cop2_3reg_vf(address, "vmaddai", instruction, 1, 1)
	elif op == 0x25:
		cop2_3reg_vf(address, "vmsubaq", instruction, 1, 2)
	elif op == 0x26:
		cop2_3reg_vf(address, "vsubai", instruction, 1, 1)
	elif op == 0x27:
		cop2_3reg_vf(address, "vmsubai", instruction, 1, 1)
	elif op == 0x28:
		cop2_3reg_vf(address, "vadda", instruction, 1, 0)
	elif op == 0x29:
		cop2_3reg_vf(address, "vmadda", instruction, 1, 0)
	elif op == 0x2A:
		cop2_3reg_vf(address, "vmula", instruction, 1, 0)
	elif op == 0x2C:
		cop2_3reg_vf(address, "vsuba", instruction, 1, 0)
	elif op == 0x2D:
		cop2_3reg_vf(address, "vmsuba", instruction, 1, 0)
	elif op == 0x2E:
		cop2_vopmula(address, instruction)
	elif op == 0x2F:
		set_manual_insn(address, "vnop")
	elif op == 0x30:
		cop2_vitof(address, "vmove", instruction)
	elif op == 0x31:
		cop2_vitof(address, "vmr32", instruction)
	elif op == 0x34:
		cop2_vlsqid(address, "vlqi", instruction, 0, 0)
	elif op == 0x35:
		cop2_vlsqid(address, "vsqi", instruction, 0, 1)
	elif op == 0x36:
		cop2_vlsqid(address, "vlqd", instruction, 1, 0)
	elif op == 0x37:
		cop2_vlsqid(address, "vsqd", instruction, 1, 1)
	elif op == 0x38:
		cop2_qdiv(address, "vdiv", instruction)
	elif op == 0x39:
		cop2_qdiv(address, "vsqrt",instruction)
	elif op == 0x3A:
		cop2_qdiv(address, "vrsqrt", instruction)
	elif op == 0x3B:
		set_manual_insn(address, "vwaitq")
	elif op == 0x3C:
		cop2_vmtir(address, instruction)
	elif op == 0x3D:
		cop2_vmfir(address, instruction)
	elif op == 0x3E:
		cop2_vixwr(address, "vilwr", instruction)
	elif op == 0x3F:
		cop2_vixwr(address, "viswr", instruction)
	elif op == 0x40:
		cop2_vr0(address, "vrnext", instruction)
	elif op == 0x41:
		cop2_vr0(address, "vrget", instruction)
	elif op == 0x42:
		cop2_vr1(address, "vrinit", instruction)
	elif op == 0x43:
		cop2_vr1(address, "vrxor", instruction)
	else:
		warning("Bad op cop2_special2")

def cop2_vclip(address, instruction):

		reg1 = (instruction >> 11) & 0x1F
		reg2 = (instruction >> 16) & 0x1F
		string = "vclipw.xyz vf{:d}, vf{:d}w"
		set_manual_insn(address, string.format(reg1, reg2))	

def cop2_vopmula(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	string = "vopmula.xyz ACC, vf{:d}, vf{:d}"
	set_manual_insn(address, string.format(reg1, reg2))

def cop2_vlsqid(address, name, instruction, is_dec, store):

	#should be 0xF in theory for vi, but field is 5 bit anyway
	reg1 = (instruction >> 11) & 0x1F 
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field = get_4bit_field(field)
	
	if is_dec == 1:
		vi_reg = "(--vi{:d})"
	else:
		vi_reg = "(vi{:d}++)"
	
	string = name + "." + field + " vf{:d}, " + vi_reg
	
	if store == 1:
		set_manual_insn(address, string.format(reg1, reg2))
	else:
		set_manual_insn(address, string.format(reg2, reg1))

def cop2_qdiv(address, name, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	fsf = (instruction >> 21) & 0x3
	ftf = (instruction >> 23) & 0x3	
	fsf = get_2bit_field(fsf)
	ftf = get_2bit_field(ftf)
	
	if name == "vsqrt":
		string = "vsqrt Q, vf{:d}" + ftf
		set_manual_insn(address, string.format(reg2))
	else:
		string = name + " Q, vf{:d}" + fsf + " vf{:d}" + ftf
		set_manual_insn(address, string.format(reg1, reg2))

def cop2_vmtir(address, instruction):

	fs = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0xF
	fsf = (instruction >> 21) & 0x3
	fsf2 = get_2bit_field(fsf)
	string = "vmtir vi{:d}, vf{:d}" + fsf2
	set_manual_insn(address, string.format(it, fs))

def cop2_vmfir(address, instruction):

	_is = (instruction >> 11) & 0x1F
	ft = (instruction >> 16) & 0x1F
	dest_field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(dest_field)
	string = "vmfir." + field2 + " vf{:d}, vi{:d}"
	set_manual_insn(address, string.format(ft, _is))

def cop2_vixwr(address, instruction):

	_is = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(field)
	string = name + "." + field2 + " vi{:d}, (vi{:d})" + field2
	set_manual_insn(address, string.format(it, _is))

def cop2_vr0(address, name, instruction):

	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field = get_4bit_field(field)
	string = name + "." + field + " vf{:d}, R"
	set_manual_insn(address, string.format(dest))

def cop2_vr1(address, name, instruction):

	source = (instruction >> 11) & 0x1F
	fsf = (instruction >> 21) & 0x3
	fsf = get_2bit_field(fsf)
	string = name + " R, vf{:d}." + fsf
	set_manual_insn(address, string.format(source))

def cop2_helper(search):
	
	address = 0
	while (address < idaapi.BADADDR):
		address = idaapi.find_binary(address, idaapi.BADADDR, search, 0x10, SEARCH_DOWN)
		if address < idaapi.BADADDR:	
			if ((get_segm_attr(address, SEGATTR_PERM) & 1) == 0):
				address += 4
				continue
			if ((address & 3) != 0):
				address = ((address & 0xFFFFFFFC) + 4)
				continue
			
			#print(hex(address))
			if ((is_code(ida_bytes.get_flags(address)) == 1)):
				instruction = get_dword(address)
				cop2_special(address, instruction)
			
		address += 4

class cop2_helper_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = "PlayStation 2 COP2 Helper"
	help = "Generate Playstation 2 COP2 assembly"
	wanted_name = "Generate Cop2 Assembly"
	wanted_hotkey = "Alt-Shift-1"

	def init(self):
		idaapi.msg("PlayStation 2 COP2 Helper loaded.\n")
		return idaapi.PLUGIN_OK
	
	def run(self, arg):
		cop2_helper("?? ?? ?? 4A")
		cop2_helper("?? ?? ?? 4B")
	
	def term(self):
		pass

def PLUGIN_ENTRY():
	return cop2_helper_t()

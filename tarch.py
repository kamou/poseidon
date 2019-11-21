import triton
from texceptions import *


def constantFolding(Triton, node):
    if node.isSymbolized():
        return node
    return Triton.getAstContext().bv(node.evaluate(), node.getBitvectorSize())

class ArchCommon(object):
    def symbolize(self, addr, size):
        return self.tc.symbolizeMemory(triton.MemoryAccess(addr, size))


    def read_reg(self, reg):
        return self.tc.getConcreteRegisterValue(reg)

    def write_reg(self, reg, value):
        return self.tc.setConcreteRegisterValue(reg, value)

    def set_memory_feed(self, g, s=None):
        self.tc.addCallback(g, triton.CALLBACK.GET_CONCRETE_MEMORY_VALUE)
        if s:
            self.tc.addCallback(s, triton.CALLBACK.SET_CONCRETE_MEMORY_VALUE)

    def func_ret(self, value=None):
        if value is not None:
            self.tc.setConcreteRegisterValue(self.ret, value)

        sp = self.tc.getConcreteRegisterValue(self.sp)
        ret_addr = self.tc.getConcreteMemoryValue(triton.MemoryAccess(self.tc.getConcreteRegisterValue(self.sp), self.psize))
        self.tc.setConcreteRegisterValue(self.pc, ret_addr)
        self.tc.setConcreteRegisterValue(self.sp, sp+self.psize)

    def get_area(self, address, size):
        return self.tc.getConcreteMemoryAreaValue(address, size)

    def get_memory_value(self, addr, size):
        return self.tc.getConcreteMemoryValue(triton.MemoryAccess(addr, size))

    def set_memory_value(self, addr, value, size):
        return self.tc.setConcreteMemoryValue(triton.MemoryAccess(addr, size), value)

    def disassemble(self, addr=None):
        if not addr is None:
            pc = addr
        else:
            pc = self.read_reg(self.pc)

        inst = triton.Instruction()
        inst_code = self.get_area(pc, 16)
        inst.setOpcode(inst_code)
        inst.setAddress(pc)
        self.tc.disassembly(inst)
        return inst

    def process(self, addr=None):
        if not addr is None:
            pc = addr
        else:
            pc = self.read_reg(self.pc)

        inst = triton.Instruction()
        inst_code = self.get_area(pc, 16)
        inst.setOpcode(inst_code)
        inst.setAddress(pc)
        if not self.tc.processing(inst):
            raise UnmanagedInstruction(inst)
        return inst

class ArchX86(ArchCommon):
    def __init__(self):
        self.tc = triton.TritonContext()
        self.tc.setArchitecture(triton.ARCH.X86)
        self.tc.setMode(triton.MODE.ALIGNED_MEMORY, True)
        self.tc.setMode(triton.MODE.ONLY_ON_SYMBOLIZED, True)
        self.tc.addCallback(constantFolding, triton.CALLBACK.SYMBOLIC_SIMPLIFICATION)
        self.pc = self.tc.registers.eip
        self.sp = self.tc.registers.esp
        self.psize = triton.CPUSIZE.DWORD
        self.ret = self.tc.registers.eax
        self.tc.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

    def get_func_arg(self, n):
        offset = n*self.psize + self.psize
        value = self.tc.getConcreteMemoryValue(triton.MemoryAccess(self.tc.getConcreteRegisterValue(self.sp)+offset, self.psize))
        return value

    def set_func_arg(self, n, value):
        sp = self.tc.getConcreteRegisterValue(self.sp)
        offset = n*self.psize + self.psize
        self.tc.setConcreteMemoryValue(triton.MemoryAccess(sp + offset,  self.psize), value)
        return value

class ArchX8664(ArchCommon):
    def __init__(self):
        self.tc = triton.TritonContext()
        self.tc.setArchitecture(triton.ARCH.X86_64)
        self.tc.setMode(triton.MODE.ALIGNED_MEMORY, True)
        self.tc.addCallback(constantFolding, triton.CALLBACK.SYMBOLIC_SIMPLIFICATION)
        self.pc = self.tc.registers.rip
        self.sp = self.tc.registers.rsp
        self.psize = triton.CPUSIZE.QWORD
        self.ret = self.tc.registers.rax
        self.tc.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

        self.regs = {
            0: self.tc.registers.rdi,
            1: self.tc.registers.rsi,
            2: self.tc.registers.rdx,
            3: self.tc.registers.rcx,
            4: self.tc.registers.r8,
            5: self.tc.registers.r9
        }

    def get_func_arg(self, n):
        if n < len(self.regs):
            value = self.tc.getConcreteRegisterValue(self.regs[n])
        else:
            offset = (n-len(self.regs))*self.psize
            value = self.tc.getConcreteMemoryValue(triton.MemoryAccess(self.tc.getConcreteRegisterValue(self.sp)+offset, self.psize))
        return value

    def set_func_arg(self, n, value):
        if n < len(self.regs):
            self.tc.setConcreteRegisterValue(self.regs[n], value)
        else:
            offset = (n-len(self.regs))*self.psize + self.psize
            self.tc.setConcreteMemoryValue(MemoryAccess(offset,  self.psize), value)
        return value


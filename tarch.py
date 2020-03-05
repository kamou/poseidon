import triton
from texceptions import *
from tcc import *

class X86Cdecl(CallingConvention):
    def __init__(self, arch):
        self.arch = arch


class ArchCommon(object):
    def symbolize(self, addr, size):
        return self.tc.symbolizeMemory(triton.MemoryAccess(addr, size))

    def read_reg(self, reg):
        return self.tc.getConcreteRegisterValue(reg)

    def write_reg(self, reg, value):
        return self.tc.setConcreteRegisterValue(reg, value)

    def set_memory_feed(self, cb):
        self.tc.addCallback(cb, triton.CALLBACK.GET_CONCRETE_MEMORY_VALUE)

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

        for se in inst.getSymbolicExpressions():
            se.setComment(str(inst))

        return inst

    def get_syscall_func_arg(self, n):
        if n >= len(self.regs):
            raise SyscallTooManyArgs()
        value = self.tc.getConcreteRegisterValue(self.syscall_regs[n])
        return value

    def is_call(self, inst):
        if inst.getType() in self.call_types:
            return True
        return False
    def is_ret(self, inst):
        if inst.getType() in self.ret_types:
            return True
        return False

    def is_branch(self, inst):
        if inst.getType() in self.branch_types:
            return True
        return False

    def is_conditional_branch(self, inst):
        if inst.getType() in self.conditional_branch_types:
            return True
        return False

    def only_on_tainted(self, en):
        self.tc.setMode(triton.MODE.ONLY_ON_TAINTED, en)

    def taint_through_pointers(self, en):
        self.tc.setMode(triton.MODE.TAINT_THROUGH_POINTERS, en)

    def only_on_symbolized(self, en):
        self.tc.setMode(triton.MODE.ONLY_ON_SYMBOLIZED, en)

    def add_simplification(self, symplification):
        self.tc.removeCallback(self.simplify, triton.CALLBACK.SYMBOLIC_SIMPLIFICATION)
        self.tc.addCallback(self.simplify, triton.CALLBACK.SYMBOLIC_SIMPLIFICATION)
        self.simplifications.add(symplification)

    def clear_simplifications(self):
        self.tc.removeCallback(self.simplify, triton.CALLBACK.SYMBOLIC_SIMPLIFICATION)
        self.simplifications = set()

    def simplify(self, tc, node):
        for simplification in self.simplifications:
            node = simplification(self, tc, node)
        return node

class ArchX86(ArchCommon):
    def __init__(self):
        self.simplifications = set()
        self.tc = triton.TritonContext()
        self.tc.setArchitecture(triton.ARCH.X86)
        self.tc.setMode(triton.MODE.ALIGNED_MEMORY, True)
        self.tc.setMode(triton.MODE.SYMBOLIZE_INDEX_ROTATION, True)
        self.pc = self.tc.registers.eip
        self.sp = self.tc.registers.esp
        self.psize = triton.CPUSIZE.DWORD
        self.ret = self.tc.registers.eax
        self.tc.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

        self.syscall_regs = [
            self.tc.registers.eax,
            self.tc.registers.ebx,
            self.tc.registers.ecx,
            self.tc.registers.edx,
            self.tc.registers.esi,
            self.tc.registers.edi,
        ]
        self.ret_types = set([triton.OPCODE.X86.RET])
        self.call_types = set([triton.OPCODE.X86.CALL, triton.OPCODE.X86.LCALL])
        self.conditional_branch_types = set([
            triton.OPCODE.X86.JA,
            triton.OPCODE.X86.JBE,
            triton.OPCODE.X86.JECXZ,
            triton.OPCODE.X86.JL,
            triton.OPCODE.X86.JNE,
            triton.OPCODE.X86.JNS,
            triton.OPCODE.X86.JRCXZ,
            triton.OPCODE.X86.JAE,
            triton.OPCODE.X86.JCXZ,
            triton.OPCODE.X86.JG,
            triton.OPCODE.X86.JLE,
            triton.OPCODE.X86.JNO,
            triton.OPCODE.X86.JO,
            triton.OPCODE.X86.JS,
            triton.OPCODE.X86.JB,
            triton.OPCODE.X86.JE,
            triton.OPCODE.X86.JGE,
            triton.OPCODE.X86.JNP,
            triton.OPCODE.X86.JP
        ])
        self.branch_types = set()
        self.branch_types.update(self.conditional_branch_types)
        self.branch_types.add(triton.OPCODE.X86.JMP)

    def get_func_arg(self, n):
        offset = n*self.psize + self.psize
        value = self.tc.getConcreteMemoryValue(triton.MemoryAccess(self.tc.getConcreteRegisterValue(self.sp)+offset, self.psize))
        return value

    def set_func_arg(self, n, value):
        sp = self.tc.getConcreteRegisterValue(self.sp)
        offset = n*self.psize + self.psize
        self.tc.setConcreteMemoryValue(triton.MemoryAccess(sp + offset,  self.psize), value)
        return value

    def resolve_branch(self, inst):
        # TODO...
        assert(self.is_branch(inst))
        if dst.getType() == triton.OPERAND.IMM:
            return inst.getOperands()[0].getValue()
        elif dst.getType() == triton.OPERAND.MEM:
            disp = dst.getDisplacement()
            scale = dst.getScale()
            br = dst.getBaseRegister()
            sr = dst.getSegmentRegister()

class ArchX8664(ArchCommon):
    def __init__(self):
        self.simplifications = set()
        self.tc = triton.TritonContext()
        self.tc.setArchitecture(triton.ARCH.X86_64)
        self.tc.setMode(triton.MODE.ALIGNED_MEMORY, True)
        self.tc.addCallback(self.simplify, triton.CALLBACK.SYMBOLIC_SIMPLIFICATION)
        self.tc.setMode(triton.MODE.SYMBOLIZE_INDEX_ROTATION, True)
        self.pc = self.tc.registers.rip
        self.sp = self.tc.registers.rsp
        self.psize = triton.CPUSIZE.QWORD
        self.ret = self.tc.registers.rax
        self.tc.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

        self.regs = [
            self.tc.registers.rdi,
            self.tc.registers.rsi,
            self.tc.registers.rdx,
            self.tc.registers.rcx,
            self.tc.registers.r8,
            self.tc.registers.r9
        ]

        self.syscall_regs = [
            self.tc.registers.rax,
            self.tc.registers.rbx,
            self.tc.registers.rcx,
            self.tc.registers.rdx,
            self.tc.registers.rsi,
            self.tc.registers.rdi,
        ]

        self.ret_types = set([triton.OPCODE.X86.RET])
        self.call_types = set([triton.OPCODE.X86.CALL, triton.OPCODE.X86.LCALL])
        self.conditional_branch_types = set([
            triton.OPCODE.X86.JA,
            triton.OPCODE.X86.JBE,
            triton.OPCODE.X86.JECXZ,
            triton.OPCODE.X86.JL,
            triton.OPCODE.X86.JNE,
            triton.OPCODE.X86.JNS,
            triton.OPCODE.X86.JRCXZ,
            triton.OPCODE.X86.JAE,
            triton.OPCODE.X86.JCXZ,
            triton.OPCODE.X86.JG,
            triton.OPCODE.X86.JLE,
            triton.OPCODE.X86.JNO,
            triton.OPCODE.X86.JO,
            triton.OPCODE.X86.JS,
            triton.OPCODE.X86.JB,
            triton.OPCODE.X86.JE,
            triton.OPCODE.X86.JGE,
            triton.OPCODE.X86.JNP,
            triton.OPCODE.X86.JP
        ])

        self.branch_types = set()
        self.branch_types.update(self.conditional_branch_types)
        self.branch_types.add(triton.OPCODE.X86.JMP)

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


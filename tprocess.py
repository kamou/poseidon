import threading
import lief
from tarch import *
import r2pipe
import struct
from texceptions import *
import thooks
import binascii
import texceptions
import tmemory

class TritonProcess(object):
    last_pid = 0

    def setup_stack(self, addr):
        # FIXME: can do better...
        for i in range(0x10000):
            self.arch.tc.setConcreteMemoryValue(addr-i, 0)
        self.arch.write_reg(self.arch.sp, addr - 0x8000)

    def load_binary(self, filename):
        self.filename = filename
        if not self.container:
            self.container = lief.parse(filename)
        if self.container.format == lief.EXE_FORMATS.ELF:
            if self.container.header.machine_type == lief.ELF.ARCH.i386:
                self.arch = ArchX86()
                self.hooks = thooks.HooksLinux()
            elif self.container.header.machine_type == lief.ELF.ARCH.x86_64:
                self.arch = ArchX8664()
                self.hooks = thooks.HooksLinux()
            elif self.container.header.machine_type == lief.ELF.ARCH.AARCH64:
                print ("[!] lief.ARCH.AARCH64 Not supported yet")
                exit(1)
            else:
                print ("[!] {} Not supported yet".format(self.container.format))
                exit(1)

            self.ast = self.arch.tc.getAstContext()
            self.memory = tmemory.Memory(self.arch)

            # configure relocations:
            for reloc in self.container.relocations:
                print( "reloc {} at {:#x}".format(reloc.symbol.name, reloc.address))
                if reloc.symbol.name:
                    self.relocations[reloc.address] = reloc.symbol.name
                    self.arch.tc.setConcreteMemoryValue(triton.MemoryAccess(reloc.address, self.arch.psize), reloc.address)
        elif self.container.format == lief.EXE_FORMATS.PE:

            imports = self.container.imports
            for imp in imports:
                for entry in imp.entries:
                    self.relocations[entry.iat_value] = entry.name

            if self.container.header.machine == lief.PE.MACHINE_TYPES.I386:
                self.arch = ArchX86()
            elif self.container.header.machine == lief.PE.MACHINE_TYPES.AMD64:
                self.arch = ArchX8664()
            else:
                print ("[!] {} Not supported yet".format(self.container.header.machine_type))
                exit(1)
        else:
            print ("[!] Unknown format")
            exit(1)
        self.pc = self.arch.pc
        self.sp = self.arch.sp
        self.ret = self.arch.ret
        self.previousConstraints = self.ast.equal(self.ast.bvtrue(), self.ast.bvtrue())

        self.set_entrypoint(self.container.entrypoint)
        self.arch.set_memory_feed(g=self.container_cache, s=self.update_cache)

        # configure stack:
        self.setup_stack(0x57AC0000)

        # load .bss
        for s in self.container.sections:
            if s.name == ".bss":
                var = s.virtual_address
                sz = s.size
                for i in range(sz):
                    self.arch.tc.setConcreteMemoryValue(var+i, 0)
                break

    def add_bp(self, addr, cb):
        self.bp[addr] = cb

    def add_instruction_hook(self, itype, cb):
        self.instruction_hooks[itype] = cb

    def log(self, enable):
        self.log_instructions = enable

    def set_entrypoint(self, ep):
        self.entrypoint = ep
        self.arch.write_reg(self.arch.pc, self.entrypoint)

    def register_os_services(self, services):
        self.os_services = services

    def __init__(self, filename=None, container=None):
        self.bp = dict()
        self.cur_inst = None
        self.filename = filename
        self.pending_action = threading.Semaphore(0)
        self.pending = list()
        self.cur_inst = None
        self.cont = threading.Semaphore(0)
        self.debugee = None
        self.dirty = dict()
        self.relocations = dict()
        self.pid = TritonProcess.last_pid
        self.instruction_hooks = dict()
        TritonProcess.last_pid+=1

        self.hooks = None

        self.sym_callback = None
        self.initial_reg_state = dict()
        self.initial_mem_state = dict()

        self.invalid_memory_handler = None

        self.container = container
        if self.filename:
            self.load_binary(self.filename)
        self.sym_mem = dict()
        self.epi = None
        self.log_hook = False
        self.log_instructions = False

    def on_each_processed_inst(self, each):
        self.epi = each

    def hook(self, name):
        def decorator(func):
            self.add_hook(name, func)
            return func
        return decorator

    def add_hook(self, name, cb):
        self.hooks.add(name, cb)

    def update_cache(self, tc, mem, value):
        for i in range(mem.getSize()):
            self.dirty[mem.getAddress()+i] = True

    def container_cache(self, tc, mem):
        addr = mem.getAddress()
        size = mem.getSize()
        for index in range(size):
            if not tc.isMemoryMapped(addr+index):
                try:
                    data = self.container.get_content_from_virtual_address(addr+index, 1)
                except:
                    if self.invalid_memory_handler:
                        self.invalid_memory_handler(self)
                    else:
                        if self.cur_inst:
                            operands = self.cur_inst.getOperands()
                            if len(operands) == 2 and operands[1].getType() == 2:
                                segment = operands[1].getSegmentRegister().getName()
                                disp = operands[1].getDisplacement()
                                # FIXME move arch dependant code
                                if segment == "fs" and disp.getValue() == 0x28 and 0x28 == addr:
                                    data = [0]
                                else:
                                #     r2 = r2pipe.open(self.filename, ["-d"])
                                #     data = [r2.cmdj("pv1j @ {:#x}".format(addr+index))[0]["value"]]
                                #     r2.quit()
                                    raise InvalidMemoryAccess(self.cur_inst, addr, size) from None

                            else:
                                # r2 = r2pipe.open(self.filename, ["-d"])
                                # data = [r2.cmdj("pv1j @ {:#x}".format(addr+index))[0]["value"]]
                                # r2.quit()
                                raise InvalidMemoryAccess(self.cur_inst, addr, size) from None
                        else:
                            # r2 = r2pipe.open(self.filename, ["-d"])
                            # data = [r2.cmdj("pv1j @ {:#x}".format(addr+index))[0]["value"]]
                            # r2.quit()
                            raise InvalidMemoryAccess(self.cur_inst, addr, size) from None

                tc.setConcreteMemoryValue(addr+index, data[0])
                self.dirty[addr+index] = True

        return

    def mem_cache(self, tc, mem):
        addr = mem.getAddress()
        size = mem.getSize()
        for index in range(size):
            if not tc.isMemoryMapped(addr+index):
                data = self.container.get_content_from_virtual_address(addr+index, 1)
                tc.setConcreteMemoryValue(addr+index, data[0])

        return

    def symbolize(self, addr, size):
        if addr not in self.sym_mem:
            self.sym_mem[addr] = self.arch.symbolize(addr, size)
        return self.sym_mem[addr]

    def make_printable(self, sym):
        self.previousConstraints = self.ast.land([self.previousConstraints, self.ast.bvugt(self.ast.variable(sym), self.ast.bv(0x20, triton.CPUSIZE.BYTE_BIT))])
        self.previousConstraints = self.ast.land([self.previousConstraints, self.ast.bvult(self.ast.variable(sym), self.ast.bv(0x7f, triton.CPUSIZE.BYTE_BIT))])

    def add_constraint(self, c):
        self.previousConstraints = self.ast.land([self.previousConstraints, c])

    def solve(self):
        model = self.arch.tc.getModel(self.previousConstraints)
        if model:
            self.solutions = model
            raise texceptions.NewSolution(model)
        else:
            raise texceptions.NoPossibleSolution()

    def solve_with_equal(self, var, val):
        self.previousConstraints = self.ast.land([self.previousConstraints, var.getAst() == val])
        if var.getAst().evaluate() != val:
            print ( "requesting model")
            model = self.arch.tc.getModel(self.previousConstraints)
            print ( "done.")
            if model:
                self.solutions = model
                raise texceptions.NewSolution(model)
            else:
                raise texceptions.NoPossibleSolution()

    def update_area(self, address, data):
        self.arch.tc.setConcreteMemoryAreaValue(address, bytes(data, "utf8"))

    def get_area(self, address, size):
        return self.arch.get_area(address, size)

    def get_string(self, addr):
        s = str()
        index = 0
        while self.arch.tc.getConcreteMemoryValue(addr+index):
            c = chr(self.arch.tc.getConcreteMemoryValue(addr+index))
            # if c not in string.printable: c = ""
            s += c
            index  += 1

        return s

    def skip_inst(self):
        inst = self.disassemble()
        self.arch.write_reg(self.pc, inst.getAddress() + inst.getSize())

    def disassemble(self, addr=None):
        if not (addr is None):
            pc = addr
        else:
            pc = self.arch.read_reg(self.pc)

        if pc in self.relocations:
            if self.log_hook:
                print ("[+] Hook {}".format(self.relocations[pc]))
            return None
        inst = self.arch.disassemble(pc)
        return inst

    def process(self, addr=None):
        if addr is None:
            addr = self.arch.read_reg(self.pc)

        if addr in self.relocations:
            print ("addr: {:#x}".format(addr))
            self.cur_inst = None
            if self.hooks.call(self.relocations[addr], self):
                return self.disassemble(addr)
            return None

        inst = self.disassemble(addr)

        if not inst:
            return None

        if inst.getType() in self.instruction_hooks:
            if not self.instruction_hooks[inst.getType()](self):
                return None
        else:
            rdi = self.arch.read_reg(self.arch.tc.registers.rdi)
            if inst.getAddress() == 0x401175:
                print ("rdi({:#x}) = {:#x}".format(rdi, self.arch.get_memory_value(rdi, self.arch.psize)))
            inst = self.arch.process()

            if inst.isSymbolized():
                if self.sym_callback:
                    # stop execution if callback returns False
                    if not self.sym_callback(self, inst):
                        return None
            if self.epi:
                self.epi(self, inst)
        return inst

    def run(self, arg=[], start=None):
        if not start is None:
            argc = len(arg) + 1
            argv = [self.filename] + arg

            sp = self.arch.read_reg(self.sp)
            argv_address = sp - 0x8000
            # write argc
            argc_data = struct.pack("<Q", argc)
            self.arch.set_memory_value(sp, argc, self.arch.psize)
            argc = self.arch.get_memory_value(sp, self.arch.psize)
            self.arch.set_func_arg(3, argv_address)

            # write argv
            update_offset = 0
            args_offset = 1

            for arg in argv:
                self.update_area(argv_address + update_offset, arg + "\x00")
                self.arch.set_memory_value(sp + args_offset *self.arch.psize, argv_address + update_offset, self.arch.psize)
                update_offset += len(arg)
                args_offset += 1

            self.update_area(sp - args_offset *self.arch.psize, "\x00"*self.arch.psize)

        while True:
            self.cur_inst = self.disassemble()
            # if self.cur_inst and self.cur_inst.getAddress() == 0x172c:
            #     self.log_instructions = True
            # if self.cur_inst and self.cur_inst.getAddress() == 0x0000172e:
            #     print()
            #     self.log_instructions = False

            if self.cur_inst and self.cur_inst.getAddress() in self.bp:

                for se in inst.getSymbolicExpressions():
                    se.setComment(str(inst))

                if not self.bp[self.cur_inst.getAddress()](self):
                    break
            if self.cur_inst and self.log_instructions:
                print (self.cur_inst)

            self.process()

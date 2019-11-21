import threading
import lief
from tarch import *
import r2pipe
import struct
from texceptions import *
import thooks
import binascii
import texceptions

class TritonProcessNG(object):
    last_pid = 0

    def setup_stack(self, addr):
        # FIXME: can do better...
        for i in range(0x10000):
            self.arch.tc.setConcreteMemoryValue(addr-i, 0)
        self.arch.write_reg(self.arch.sp, addr)

    def load_binary(self, filename):
        self.filename = filename
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

            # configure relocations:
            for reloc in self.container.relocations:
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
        astCtxt = self.arch.tc.getAstContext()
        self.previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())

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


    def log(self, enable):
        self.log_instructions = enable

    def set_entrypoint(self, ep):
        self.entrypoint = ep
        self.arch.write_reg(self.arch.pc, self.entrypoint)

    def register_os_services(self, services):
        self.os_services = services

    def __init__(self, filename=None):
        self.cur_inst = None
        self.filename = filename
        self.pending_action = threading.Semaphore(0)
        self.pending = list()
        self.cur_inst = None
        self.cont = threading.Semaphore(0)
        self.debugee = None
        self.dirty = dict()
        self.relocations = dict()
        self.pid = TritonProcessNG.last_pid
        self.instruction_hooks = dict()
        TritonProcessNG.last_pid+=1

        self.hooks = None

        self.sym_callback = None
        self.initial_reg_state = dict()
        self.initial_mem_state = dict()

        self.invalid_memory_handler = None

        if self.filename:
            self.load_binary(self.filename)
        self.sym_mem = dict()
        self.epi = None
        self.log_hook = False

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
                                if segment == "fs" and disp.getValue() == 0x28 and 0x28 == addr:
                                    data = [0]
                                else:
                                    raise InvalidMemoryAccess(self.cur_inst, addr, size) from None

                            else:
                                raise InvalidMemoryAccess(self.cur_inst, addr, size) from None
                        else:
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

    def try_solution(self, condition):
        astCtxt = self.arch.tc.getAstContext()
        self.previousConstraints = astCtxt.land([self.previousConstraints, condition])
        model = self.arch.tc.getModel(self.previousConstraints)
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

    def disassemble(self, addr=None):
        if not addr is None:
            pc = addr
        else:
            pc = self.arch.read_reg(self.pc)
        if pc in self.relocations:
            if self.log_hook:
                print ("[+] Hook {}".format(self.relocations[pc]))
            return None
        inst = self.arch.disassemble()
        return inst

    def process(self, addr=None):
        if addr is None:
            addr = self.arch.read_reg(self.pc)

        if addr in self.relocations:
            self.cur_inst = None
            return self.hooks.call(self.relocations[addr], self)

        inst = self.disassemble(addr)

        if not inst:
            return None

        if inst.getType() in self.instruction_hooks:
            if not self.instruction_hooks[inst.getType()](self):
                return None
        else:
            inst = self.arch.process()

            if inst.isSymbolized():
                if self.sym_callback:
                    # stop execution if callback returns False
                    if not self.sym_callback(self, inst):
                        return None
            if self.epi:
                self.epi(self, inst)
        return inst

    def run(self, arg):
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
            if self.cur_inst and self.log_instructions:
                print (self.cur_inst)
            if not self.process():
                break

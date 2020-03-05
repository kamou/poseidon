import threading
import lief
from tarch import *
import struct
from texceptions import *
import thooks
import binascii
import texceptions

class colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

class TritonProcess(object):

    LOG_NONE=0
    LOG_ALL=1
    LOG_TAINTED=2
    LOG_SYMBOLIC=3

    def set_option(self, name, value):
        self.options[name] = valuel

    def setup_stack(self, addr):
        self.stack_start = addr
        self.stack_end = addr + 0x10000
        for i in range(0x10000):
            self.arch.tc.setConcreteMemoryValue(addr+i, 0)
        self.arch.write_reg(self.arch.sp, addr + 0x8000)

    def configure_arch(self):
        if self.container.format == lief.EXE_FORMATS.ELF:
            self.hooks = thooks.HooksLinux()
            if self.container.header.machine_type == lief.ELF.ARCH.i386:
                self.arch = ArchX86()
                return
            elif self.container.header.machine_type == lief.ELF.ARCH.x86_64:
                self.arch = ArchX8664()
                return
        elif self.container.format == lief.EXE_FORMATS.PE:
            if self.container.header.machine == lief.PE.MACHINE_TYPES.I386:
                self.arch = ArchX86()
                return
            elif self.container.header.machine == lief.PE.MACHINE_TYPES.AMD64:
                self.arch = ArchX8664()
                return
        raise ValueError("File format or architecture not supperted.")

    def configure_relocations(self):
        if self.container.format == lief.EXE_FORMATS.ELF:
            # configure relocations:
            for reloc in self.container.relocations:
                if reloc.symbol.name:
                    self.relocations[reloc.address] = reloc.symbol.name
                    self.arch.tc.setConcreteMemoryValue(triton.MemoryAccess(reloc.address, self.arch.psize), reloc.address)
        elif self.container.format == lief.EXE_FORMATS.PE:
            imports = self.container.imports
            for imp in imports:
                for entry in imp.entries:
                    self.relocations[entry.iat_value] = entry.name

    def add_bp(self, addr, cb):
        self.bp[addr] = cb

    def add_instruction_hook(self, itype, cb):
        self.instruction_hooks[itype] = cb

    def log(self, lvl):
        self.instruction_log_level = lvl

    def set_entrypoint(self, ep):
        self.entrypoint = ep
        self.arch.write_reg(self.arch.pc, self.entrypoint)

    def register_os_services(self, services):
        self.os_services = services

    def __init__(self, filename=None):
        self.hooks = None

        self.filename = filename
        self.container = lief.parse(filename)
        self.configure_arch()
        self.ast = self.arch.tc.getAstContext()

        self.relocations = dict()
        self.configure_relocations()

        self.pc = self.arch.pc
        self.sp = self.arch.sp
        self.ret = self.arch.ret

        self.set_entrypoint(self.container.entrypoint)
        self.arch.set_memory_feed(self.memory_feed)

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


        self.bp = dict()
        self.cur_inst = None
        self.cur_inst = None
        self.instruction_hooks = dict()
        self.sym_callback = None
        self.insts = dict()
        self.lasts = dict()
        self.invalid_memory_handler = None
        self.sym_mem = dict()
        self.epi = None
        self.log_hook = False
        self.instruction_log_level = TritonProcess.LOG_NONE
        self.on_disass = None
        self.log_opts = dict()
        self.log_opts["avoid_output_registers"] = ["rsp"]
        self.log_opts["avoid_input_registers"] = ["rsp", "rip"]

    def on_each_processed_inst(self, each):
        self.epi = each

    def hook(self, name):
        def decorator(func):
            self.add_hook(name, func)
            return func
        return decorator

    def add_hook(self, name, cb):
        self.hooks.add(name, cb)

    def memory_feed(self, tc, mem):
        addr = mem.getAddress()
        size = mem.getSize()
        for index in range(size):
            if not tc.isMemoryMapped(addr+index):
                try: data = self.container.get_content_from_virtual_address(addr+index, 1)
                except:
                    if self.invalid_memory_handler:
                        if not self.invalid_memory_handler(self, addr+index):
                            raise InvalidMemoryAccess(self.cur_inst, addr, size) from None
                        return
                    else:
                        raise InvalidMemoryAccess(self.cur_inst, addr, size) from None
                tc.setConcreteMemoryValue(addr+index, data[0])
        return

    def symbolize(self, addr, size):
        if addr not in self.sym_mem:
            self.sym_mem[addr] = self.arch.symbolize(addr, size)
        return self.sym_mem[addr]

    def update_area(self, address, data):
        self.arch.tc.setConcreteMemoryAreaValue(address, bytes(data, "utf8"))

    def get_area(self, address, size):
        return self.arch.get_area(address, size)

    def get_string(self, addr):
        s = str()
        while self.arch.tc.getConcreteMemoryValue(addr):
            s += chr(self.arch.tc.getConcreteMemoryValue(addr))
            addr  += 1
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
            self.cur_inst = None
            if self.hooks.call(self.relocations[addr], self):
                return self.disassemble(addr)
            return None

        self.cur_inst = self.disassemble(addr)

        if not self.cur_inst:
            return None

        if self.cur_inst.getType() in self.instruction_hooks:
            if not self.instruction_hooks[self.cur_inst.getType()](self):
                return None
        else:
            self.cur_inst = self.arch.process()

            if self.cur_inst and self.instruction_log_level > TritonProcess.LOG_NONE:
                self.do_log()

            if self.cur_inst.isSymbolized():
                if self.sym_callback:
                    # stop execution if callback returns False
                    if not self.sym_callback(self, self.cur_inst):
                        return None
            self.collect_mem_access()
            if self.epi:
                self.epi(self, self.cur_inst)
        return self.cur_inst

    def do_log(self):
        log_en = self.instruction_log_level == TritonProcess.LOG_ALL
        log_en |= (self.instruction_log_level == TritonProcess.LOG_TAINTED) and self.cur_inst.isTainted()
        log_en |= (self.instruction_log_level == TritonProcess.LOG_SYMBOLIC) and self.cur_inst.isSymbolized()
        avoid_or = self.log_opts["avoid_output_registers"]
        avoid_ir = self.log_opts["avoid_input_registers"]

        if log_en:
            rr = self.cur_inst.getReadRegisters()
            wr = self.cur_inst.getWrittenRegisters()

            rregs = list()

            flags = ""
            for r, v in rr:
                if r.getName() in avoid_ir: continue
                value = v.evaluate()
                if self.arch.tc.isFlag(r):
                    if v.evaluate():
                        flags += r.getName()[0]
                else:
                    color = ""
                    if self.is_executable(value):
                        color = colors.RED
                    elif self.stack_start <= value < self.stack_end:
                        color = colors.GREEN
                    rregs.append("{:3}: {}{:016x}{}".format(r.getName(), color, v.evaluate(), colors.ENDC))

            if flags:
                rregs.append("flags: {}".format(flags))


            wregs = list()
            flags = ""
            for r, v in wr:
                if r.getName() in avoid_or: continue
                value = v.evaluate()
                if self.arch.tc.isFlag(r):
                    if value:
                        flags += r.getName()[0]
                else:
                    color = ""
                    if self.is_executable(value):
                        color = colors.RED
                    elif self.stack_start <= value < self.stack_end:
                        color = colors.GREEN

                    wregs.append("{:3}: {}{:016x}{}".format(r.getName(), color, v.evaluate(), colors.ENDC))

            if flags:
                wregs.append("flags: {}".format(flags))

            comment = " # in : {}".format(", ".join(rregs))

            inst_str = str(self.cur_inst)
            l = len(inst_str)
            comment = "\n".join([comment, "{}# out: {}".format(" "*60, ", ".join(wregs))])
            addr, inst_str = inst_str.split(":", 1)
            inst_str = inst_str.strip()
            inst_str = "{}{}{}: {}".format(colors.YELLOW, addr.strip(), colors.ENDC, inst_str)

            if self.cur_inst.isSymbolized(): inst_str = "* {}".format(inst_str)
            elif self.cur_inst.isTainted(): inst_str = "+ {}".format(inst_str)
            else: inst_str = "  {}".format(inst_str)

            inst_str = "{}{}{}".format(inst_str, " "*(60 - l - 3), comment)

            print (inst_str)

    def is_executable(self, addr):
        if self.container.format == lief.EXE_FORMATS.ELF:
            for s in self.container.segments:
                if s.has(lief.ELF.SEGMENT_FLAGS.X):
                    if s.virtual_address <= addr < s.virtual_address + s.virtual_size:
                        return True
        return False

    def _collect_nodes(self, node, avoid=[]):
        nodes = set()
        todo = set([node])
        avoid = set(avoid.copy())
        while len(todo):
            node = todo.pop()

            if not node: continue
            if node in avoid: continue

            if node.getType() == triton.AST_NODE.REFERENCE:
                nodes.add(node)
                avoid.add(node)

                symexpr = node.getSymbolicExpression()
                origin = symexpr.getOrigin()

                if origin and origin.getType() == triton.OPERAND.MEM:
                    lea = origin.getLeaAst()
                    if lea:
                        todo.add(lea)

                slicing =  self.arch.tc.sliceExpressions(symexpr)
                todo.add(symexpr.getAst())

                for s in slicing:
                    todo.add(slicing[s].getAst())

            todo.update(set(node.getChildren()))
        del todo
        return nodes

    def collect_nodes(self, node, avoid=None):
        nodes = set()
        todo = set([node])
        if avoid == None: avoid = set()
        while len(todo):
            node = todo.pop()
            if not node: continue
            if node in avoid: continue
            avoid.add(node)
            if node.getHash() in self.lasts:
                lea_ast = self.lasts[node.getHash()]
                todo.update(lea_ast)

            if node.getHash() in self.lasts:
                lea_ast = self.lasts[node.getHash()]
                todo.update(lea_ast)

            if node.getType() == triton.AST_NODE.REFERENCE:
                nodes.add(node)
                symexpr = node.getSymbolicExpression()
                origin = symexpr.getOrigin()

                todo.add(symexpr.getAst())

            todo.update(set(node.getChildren()))
        del todo
        return nodes

    def collect_mem_access(self):
        if self.cur_inst.isTainted():
            inst_str = str(self.cur_inst)
            addr, inst_str = inst_str.split(":", 1)
            addr = int(addr.strip(), 16)
            inst_str = inst_str.strip()

            rr = self.cur_inst.getReadRegisters()
            wr = self.cur_inst.getWrittenRegisters()

            if self.cur_inst.isMemoryRead():
                la = self.cur_inst.getLoadAccess()
                for a, v in la:
                    ast = a.getLeaAst()
                    if ast:
                        if not v.getHash() in self.lasts:
                            self.lasts[v.getHash()] = set()
                        self.lasts[v.getHash()].add(ast)

            if self.cur_inst.isMemoryWrite():
                la = self.cur_inst.getStoreAccess()
                for a, v in la:
                    ast = a.getLeaAst()
                    if ast:
                        if not v.getHash() in self.lasts:
                            self.lasts[v.getHash()] = set()
                        self.lasts[v.getHash()].add(ast)

    def run(self, arg=[], start=None):
        if start is None:
            # FIXME: move code to os / calling convention specifique object
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
        else:
            if argv:
                # TODO: configure function arguments
                print("WARNING: Ignoring program argument")
            self.arch.write_reg(self.arch.pc, start)

        while True:
            self.cur_inst = self.disassemble()
            if self.on_disass:
                self.on_disass(self, self.cur_inst)

            if self.cur_inst and self.cur_inst.getAddress() in self.bp:
                if not self.bp[self.cur_inst.getAddress()](self):
                    break

            self.process()

            if self.cur_inst:
                for se in self.cur_inst.getSymbolicExpressions():
                    se.setComment(str(self.cur_inst))

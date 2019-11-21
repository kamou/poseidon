import threading
import lief
from tarch import *
import r2pipe
import struct

class TritonProcessNG(object):
    last_pid = 0
    def copy_from(self, context):
        self.container = context.container
        if self.container.format == lief.EXE_FORMATS.ELF:
            if self.container.header.machine_type == lief.ELF.ARCH.i386:
                self.arch = ArchX86()
            elif self.container.header.machine_type == lief.ELF.ARCH.x86_64:
                self.arch = ArchX8664()
            elif self.container.header.machine_type == lief.ELF.ARCH.AARCH64:
                print "[!] lief.ARCH.AARCH64 Not supported yet"
                exit(1)
            else:
                print "[!] {} Not supported yet".format(self.container.header.machine_type)
                exit(1)
        elif self.container.format == lief.EXE_FORMATS.PE:
            if self.container.header.machine == lief.PE.MACHINE_TYPES.I386:
                print "I386"
                self.arch = ArchX86()
            elif self.container.header.machine_type == lief.PE.MACHINE_TYPES.AMD64:
                self.arch = ArchX8664()
            else:
                print "[!] {} Not supported yet".format(self.container.header.machine_type)
                exit(1)
        else:
            print "[!] Unknown format"
            exit(1)
        astCtxt = self.arch.tc.getAstContext()
        self.previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())
        self.relocations = context.relocations

        for reg in dir(self.arch.tc.registers):
            try:
                val = context.arch.tc.getConcreteRegisterValue(self.arch.getRegister(reg))
                self.arch.tc.setConcreteRegisterValue(self.arch.getRegister(reg), val)
                self.initial_reg_state[reg] = val
            except: pass

        self.pc = self.arch.pc
        self.sp = self.arch.sp
        self.ret = self.arch.ret

        self.set_entrypoint(self.container.entrypoint)
        self.arch.set_memory_feed(g=self.container_cache, s=self.update_cache)

        for addr in context.dirty:
            value = context.arch.tc.getConcreteMemoryValue(addr)
            self.arch.tc.setConcreteMemoryValue(triton.MemoryAccess(addr, 1), value)
            self.initial_mem_state[addr] = value

    def setup_stack(self, addr):
        # FIXME: can do better...
        for i in range(0x10000):
            self.arch.tc.setConcreteMemoryValue(addr-i, 0)
        self.arch.tc.setConcreteRegisterValue(self.arch.sp, addr - 0x8000)

    def load_binary(self, filename):
        self.filename = filename
        self.container = lief.parse(filename)
        if self.container.format == lief.EXE_FORMATS.ELF:
            if self.container.header.machine_type == lief.ELF.ARCH.i386:
                self.arch = ArchX86()
            elif self.container.header.machine_type == lief.ELF.ARCH.x86_64:
                self.arch = ArchX8664()
            elif self.container.header.machine_type == lief.ELF.ARCH.AARCH64:
                print "[!] lief.ARCH.AARCH64 Not supported yet"
                exit(1)
            else:
                print "[!] {} Not supported yet".format(self.container.format)
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
                print "[!] {} Not supported yet".format(self.container.header.machine_type)
                exit(1)
        else:
            print "[!] Unknown format"
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
                print(".bss {:#x}".format(var))
                for i in xrange(sz):
                    self.arch.tc.setConcreteMemoryValue(var+i, 0)
                break


    def set_entrypoint(self, ep):
        self.entrypoint = ep
        self.arch.tc.setConcreteRegisterValue(self.arch.pc, self.entrypoint)

    def register_os_services(self, services):
        self.os_services = services

    def __init__(self):
        self.filename = None
        self.pending_action = threading.Semaphore(0)
        self.pending = list()
        self.cur_inst = None
        self.cont = threading.Semaphore(0)
        self.debugee = None
        self.mappings = []
        self.dirty = dict()
        self.relocations = dict()
        self.argc=1
        self.argv=0
        self.pid = TritonProcessNG.last_pid
        self.instruction_hooks = dict()
        TritonProcessNG.last_pid+=1

        self.fail = list()
        self.hooks = dict()
        self.sym_mem = dict()
        self.hooks["__libc_start_main"] = self.__libc_start_main
        self.hooks["signal"] = self.__signal
        self.hooks["getpid"] = self.__getpid
        self.hooks["memset"] = self.__memset
        self.hooks["fgets"] = self.__fgets
        self.hooks["strcspn"] = self.__strcspn
        self.hooks["strlen"] = self.__strlen
        self.hooks["puts"] = self.__puts
        self.hooks["fork"] = self.__fork
        self.hooks["ptrace"] = self.__ptrace

        self.solutions = None
        self.sym_callback = None
        self.initial_reg_state = dict()
        self.initial_mem_state = dict()

    def __libc_start_main(self):
        # call main with expected arguments (argc, argv, [envp])
        main = self.arch.get_func_arg(0)
        pc = self.arch.tc.getRegisterAst(self.pc).evaluate()
        self.arch.set_func_arg(0, self.argc)
        self.arch.set_func_arg(1, self.argv)
        self.arch.tc.setConcreteRegisterValue(self.pc, main)
        pc = self.arch.tc.getRegisterAst(self.pc).evaluate()
        # self.prepare_call([])
        return True

    def __fork(self):
        self.os_services["fork"](self)
    def __ptrace(self):
        self.os_services["ptrace"](self)

    def __signal(self):

        disp = dict()
        disp[0] = "SIG_DFL"
        disp[1] = "SIG_IGN"

        SIG_DFL = 0
        SIG_IGN = 1
        # call main with expected arguments (argc, argv, [envp])
        signal = self.arch.get_func_arg(0)
        handler = self.arch.get_func_arg(1)

        if handler in disp:
            print "signal({}, {})".format(signal, disp[handler])
        else:
            # TODO: emulate signals and call handlers
            print "signal({}, {:#x})".format(signal, handler)
            exit(1)

        self.arch.func_ret()
        return True

    def __getpid(self):
        print "[+] getpid() called, returning {}".format(self.pid)
        self.arch.func_ret(self.pid)
        return True

    def __memset(self):
        s = self.arch.get_func_arg(0)
        c = self.arch.get_func_arg(1)
        n = self.arch.get_func_arg(2)

        print "[+] memset({:#x}, {:#x}, {}) called".format(s, c, n)

        for index in range(n):
            self.arch.tc.setConcreteMemoryValue(s+index, c)

        self.arch.func_ret()
        return True

    def __fgets(self):
        s = self.arch.get_func_arg(0)
        size = self.arch.get_func_arg(1)
        stream = self.arch.get_func_arg(2)

        # dirty hack for now, just check it is stdin from symbols.
        # FIXME, handle fopen !!

        for sym in  (self.container.symbols):
            if sym.value == stream:
                break
        if sym.name == "stdin":
            print "[+] fgets({:#x}, {}, {})".format(s, size, sym.name)
            data = raw_input()
            r = len(data) if len(data) < size-1 else size-1
            for index in range(r):
                self.arch.tc.setConcreteMemoryValue(s+index, ord(data[index]))
            self.arch.tc.setConcreteMemoryValue(s+size-1, 0)
        else:
            print "[+] fgets({:#x}, {}, {:#x})".format(s, size, stream)
            print "[!] unknown file handle, aborting.."
            exit(1)

        self.arch.func_ret(s)
        return True

    def __strcspn(self):
        # size_t strcspn(const char *s, const char *reject);
        s = self.arch.get_func_arg(0)
        reject = self.arch.get_func_arg(1)
        s_string = self.get_string(s)
        reject_string = self.get_string(reject)
        print "[+] strcspn(\"{}\", \"{}\")".format(s_string.encode("string_escape"), reject_string.encode("string_escape"))
        for i, c in enumerate(s_string):
            if c in reject_string:
                break

        self.arch.func_ret(i+1)
        return True

    def __strlen(self):
        s = self.arch.get_func_arg(0)
        print "getting string at {:#x}".format(s)
        s_string = self.get_string(s)
        print "[+] strlen(\"{}\")".format(s_string.encode("string_escape"))
        self.arch.func_ret(len(s_string))
        return True

    def __puts(self):
        s = self.arch.get_func_arg(0)
        s_string = self.get_string(s)
        print s_string.encode("string_escape")
        self.arch.func_ret()
        return True

    def update_cache(self, tc, mem, value):
        for i in xrange(mem.getSize()):
            self.dirty[mem.getAddress()+i] = True

    def container_cache(self, tc, mem):
        addr = mem.getAddress()
        size = mem.getSize()
        for index in range(size):
            if not tc.isMemoryMapped(addr+index):
                try:
                    data = self.container.get_content_from_virtual_address(addr+index, 1)
                except:
                    pc = self.arch.tc.getRegisterAst(self.pc).evaluate()
                    print "pc = {:#x}".format(pc)
                    print "woopsy, can't find {:#x}".format(addr+index)
                # except:
                #     print "r2pipe"
                #     r2 = r2pipe.open("/home/ak42/CloudStation/challenges/grehack19/angry_tux", ["-d", "-2"])
                #     v = r2.cmd("p8 {} @ {:#x}".format(1, addr+index)).strip().decode("hex")
                #     r2.quit()
                #     data = []
                #     data.append(struct.unpack("B", v)[0])
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

    def symbolize(self, addr, name=""):
        if addr not in self.sym_mem:
            self.sym_mem[addr] = self.arch.symbolize(addr)
        return self.sym_mem[addr]

    def update_registers(self, regs):
        arch = self.arch

        for reg in regs:
            if reg == "rflags":
                arch.tc.setConcreteRegisterValue(arch.tc.registers.eflags, regs[reg])
            elif reg not in ("orax","oeax"):
                arch.tc.setConcreteRegisterValue(arch.getRegister(reg), regs[reg])

    def update_area(self, address, data):
        self.arch.tc.setConcreteMemoryAreaValue(address, data)

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

    def register(self, name):
        return self.arch.getRegister(name)


    def disassemble(self, addr=None):
        if not addr is None:
            pc = addr
        else:
            pc = self.arch.tc.getRegisterAst(self.pc).evaluate()
        if pc in self.relocations:
            print "[+] detected call to {}".format(self.relocations[pc])
            return None
        inst = self.arch.disassemble()
        return inst

    def process(self, addr=None):
        if addr is None:
            addr = self.arch.tc.getRegisterAst(self.pc).evaluate()

        if addr in self.relocations:
            if self.relocations[addr] in self.hooks:
                return self.hooks[self.relocations[addr]]()
            return None

        inst = self.disassemble(addr)

        if inst:
            if inst.getType() in self.instruction_hooks:
                if not self.instruction_hooks[inst.getType()](self):
                    return None
            else:
                self.arch.process(inst)
                if inst.isSymbolized():
                    if self.sym_callback:
                        # stop execution if callback returns False
                        if not self.sym_callback(self, inst):
                            return None
        return inst

    def run(self):
        while True:
            inst = self.disassemble()
            if inst:
                print inst
            if not self.process():
                break

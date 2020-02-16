import triton
import struct
import threading

from tarch import *
from tprocess import *
from tr2 import *
from toslinux import *

class TritonEnv(object):
    def __init__(self, filename=None):
        self.contexts = list()
        self.instruction_hooks = dict()

    def set_symcallback(self, cb):
        self.sym_callback = cb

    def architecture(self):
        arch = r2.arch()
        bits = r2.bits()
        if arch == "x86":
            if bits == 32:
                return ArchX86
            elif bits == 64:
                return ArchX8664

        # TODO: add aarch64 support using qemu gdb stubs for initial context
        # if arch == "aarch64":
        #     return triton.ARCH.AARCH64

        return None

    def on_inst(self, itype, hook):
        self.instruction_hooks[itype] = hook

    def fork(self, tp):
        new_tp = self.create_process(context=tp)

        sp = tp.arch.tc.getConcreteRegisterValue(tp.sp)
        ret_addr = tp.arch.tc.getConcreteMemoryValue(triton.MemoryAccess(tp.arch.tc.getConcreteRegisterValue(tp.sp), tp.arch.psize))

        tp.arch.tc.setConcreteRegisterValue(tp.pc, ret_addr)

        tp.arch.tc.setConcreteRegisterValue(tp.sp, sp+tp.arch.psize)

        assert(tp.pid + 1 == new_tp.pid)
        tp.arch.tc.setConcreteRegisterValue(tp.ret, tp.pid + 1)


        new_tp.arch.tc.setConcreteRegisterValue(tp.pc, ret_addr)

        new_tp.arch.tc.setConcreteRegisterValue(tp.sp, sp+tp.arch.psize)

        new_tp.arch.tc.setConcreteRegisterValue(tp.ret, 0)

        self._run(new_tp)

# TODO: move this to os specific api
    def ptrace(self, tp):
        # FIXME: AARC64 and X86 32bits
        arg0 = tp.arch.get_func_arg(0)
        arg1 = tp.arch.get_func_arg(1)
        arg2 = tp.arch.get_func_arg(2)
        arg3 = tp.arch.get_func_arg(3)

        if arg0 == 12:

            rax, rdi = tp.debugee.pending.pop()
            tp.arch.tc.setConcreteMemoryValue(triton.MemoryAccess(arg3+10*8, tp.arch.psize), rax)
            tp.arch.tc.setConcreteMemoryValue(triton.MemoryAccess(arg3+14*8, tp.arch.psize), rdi)

        elif arg0 == 0x4206:
            for c in self.contexts:
                if c.pid == arg1:
                    tp.debugee = c
                    break
        elif arg0 == 7:
            print "[+] ptrace_cont"
            tp.debugee.cont.release()
        elif arg0 == 17:
            print "{}: ptrace(DETACH)".format(tp.pid)
        else:
            print "{}: ptrace({})".format(tp.pid,arg0)


        sp = tp.arch.tc.getConcreteRegisterValue(tp.sp)
        ret_addr = tp.arch.tc.getConcreteMemoryValue(triton.MemoryAccess(tp.arch.tc.getConcreteRegisterValue(tp.sp), tp.arch.psize))

        tp.arch.tc.setConcreteRegisterValue(tp.pc, ret_addr)

        tp.arch.tc.setConcreteRegisterValue(tp.sp, sp+tp.arch.psize)

    def waitpid(self, tp):
        arg0 = tp.arch.get_func_arg(0)
        arg1 = tp.arch.get_func_arg(1)

        # FIXME: AARC64 and X86 32bits
        rdi = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rdi)

        rsi = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rsi)


        for c in self.contexts:
            if c.pid == tp.debugee.pid:
                if c.pid == arg0:
                    break


        # FIXME: hack for root-me ringgit challenge, should not be part of actual api
        tp.arch.tc.setConcreteMemoryValue(triton.MemoryAccess(tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rsi), tp.arch.psize), 0x57f)

        c.pending_action.acquire()

        sp = tp.arch.tc.getConcreteRegisterValue(tp.sp)
        ret_addr = tp.arch.tc.getConcreteMemoryValue(triton.MemoryAccess(tp.arch.tc.getConcreteRegisterValue(tp.sp), tp.arch.psize))

        tp.arch.tc.setConcreteRegisterValue(tp.pc, ret_addr)

        tp.arch.tc.setConcreteRegisterValue(tp.sp, sp+tp.arch.psize)

    def concretize(self, process):
        self.arch.tcs[process].arch.tc.concretizeAllMemory()

    def current_context(self):
        return self.contexts[self.cur_ctx]

    def _run(self, context):
        while True:
            inst = context.disassemble()
            if inst:
                print "pid:{}:{}".format(context.pid, inst)
            if not context.process():
                break

    def create_process(self, name="", context=None):
        process = TritonProcess()
        process.instruction_hooks = self.instruction_hooks
        services = dict()
        services["fork"] = self.fork
        services["ptrace"] = self.ptrace
        process.register_os_services(services)
        process.sym_callback = self.sym_callback
        if name:
            process.load_binary(name)
        elif context:
            process.copy_from(context)
        return process

    def run(self, name="", context=None, join=False):
        process = self.create_process(name=name, context=context)
        self.contexts.append(process)
        t = threading.Thread(target = self._run, args = (process,))
        process.thread = t
        t.start()
        if join:
            t.join()

def bp_exception_handler(tp):
    rax = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rax)

    # tp.context.concretizeRegister(tp.context.registers.rdi)
    rdi = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rdi)

    tp.pending.append((rax, rdi))
    # print dir(tp.container)
    # for s in tp.container.sections:
    #     if s.name == ".bss":
    #         var = s.virtual_address
    #         break
    # print "{:#x}".format(var+0x10)
    # if not tp.arch.tc.isMemoryMapped(var + 0x10):
    #     print "{}: memory not mapped".format(tp.pid)



    tp.pending_action.release()
    print "[+] waiting for ptrace_cont"
    tp.cont.acquire()
    print "[+] Done"

    # sp = tp.context.getConcreteRegisterValue(tp.sp)
    # ret_addr = tp.context.getConcreteMemoryValue(triton.MemoryAccess(tp.context.getConcreteRegisterValue(tp.sp), tp.arch.psize))

    # tp.context.concretizeRegister(tp.pc)
    pc = tp.arch.tc.getConcreteRegisterValue(tp.pc)
    tp.arch.tc.setConcreteRegisterValue(tp.pc, pc + 1)

te = TritonEnv()

# te.on_inst(triton.OPCODE.X86.INT3, bp_exception_handler)
# print dir(triton.OPCODE)

SYSCALL_TABLE = dict()
SYSCALL_EXIT = 1
SYSCALL_WRITE = 4
SYSCALL_READ = 3

def syscall_write(tp):
    global valid
    print "SYSCALL_WRITE"
    fd = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rbx)
    buf = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rcx)
    sz = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rdx)
    data = tp.get_area(buf, sz)
    print data
    if "Congrats" in data:
        valid = True
    return True

def syscall_read(tp):
    print "SYSCALL_READ"
    fd = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rbx)
    buf = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rcx)
    sz = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rdx)

    # initial data
    data = "0000000000000000000000000000000000000"
    if tp.solutions:
        data = tp.solutions

    tp.update_area(buf, data[:sz])
    printable_syms = list()
    astCtxt = tp.arch.tc.getAstContext()
    for i in range(sz):
        sym =tp.symbolize(buf +i)
        printable_syms.append(astCtxt.bvugt(astCtxt.variable(sym), astCtxt.bv(0x20,  triton.CPUSIZE.BYTE_BIT)))
        printable_syms.append(astCtxt.bvult(astCtxt.variable(sym), astCtxt.bv(0x7f, triton.CPUSIZE.BYTE_BIT)))

    tp.previousConstraints = astCtxt.land(printable_syms)
    return True

def syscall_exit(tp):
    print "SYSCALL_EXIT"
    print "exit"
    return False

SYSCALL_TABLE[SYSCALL_WRITE] = syscall_write
SYSCALL_TABLE[SYSCALL_READ] = syscall_read
SYSCALL_TABLE[SYSCALL_EXIT] = syscall_exit

def int80_handler(tp):
    rax = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rax)
    if rax in SYSCALL_TABLE:
        if SYSCALL_TABLE[rax](tp):
            pc = tp.arch.tc.getConcreteRegisterValue(tp.pc)
            tp.arch.tc.setConcreteRegisterValue(tp.pc, pc + tp.disassemble().getSize())
            return True
    else:
        print "[!] Error, syscall not yet supported"
    return False

def sym_inst_callback(tp, inst):
    # print inst
    if (inst.isBranch() or inst.isControlFlow()):
        astCtxt = tp.arch.tc.getAstContext()
        pc = tp.arch.tc.getConcreteRegisterValue(tp.pc)
        if pc in (0x4000df, 0x400128):
            zf = tp.arch.tc.getSymbolicRegister(tp.arch.tc.registers.zf)
            astCtxt = tp.arch.tc.getAstContext()
            tp.previousConstraints = astCtxt.land([tp.previousConstraints, zf.getAst() == 1])
            model = tp.arch.tc.getModel(tp.previousConstraints)
            out = "".join([chr(model[sym].getValue()) for sym in model])
            tp.solutions = out
            # stop execution on fail
            if pc == 0x4000df or pc == 0x4001be:
                return False

        else:
            zf = tp.arch.tc.getSymbolicRegister(tp.arch.tc.registers.zf)
            astCtxt = tp.arch.tc.getAstContext()
            tp.previousConstraints = astCtxt.land([tp.previousConstraints, zf.getAst() == zf.getAst().evaluate()])
    return True

# te.on_inst(triton.OPCODE.X86.INT, int80_handler)
# te.set_symcallback(sym_inst_callback)
# te.run("/home/ak42/CloudStation/challenges/grehack19/angry_tux", join=True)

solution = None
valid = False
while True:
    process = TritonProcess()
    if solution:
        process.solutions = solution
    process.instruction_hooks[triton.OPCODE.X86.INT] = int80_handler
    process.sym_callback = sym_inst_callback
    process.load_binary("/home/ak42/CloudStation/challenges/grehack19/angry_tux")

    process.run()

    solution =  process.solutions
    print "solution: ", solution

    if valid:
        break


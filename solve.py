import triton
import struct
import threading

from tarch import *
from tprocess import *
from tr2 import *
from toslinux import *

SYSCALL_TABLE = dict()
SYSCALL_EXIT = 1
SYSCALL_WRITE = 4
SYSCALL_READ = 3

def syscall_write(tp):
    global valid
    fd = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rbx)
    buf = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rcx)
    sz = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rdx)
    data = tp.get_area(buf, sz)
    print data
    if "Congrats" in data:
        valid = True
    return True

def syscall_read(tp):
    fd = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rbx)
    buf = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rcx)
    sz = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rdx)

    # initial data
    data = "A"*sz
    if tp.solutions:
        data = tp.solutions

    tp.update_area(buf, data[:sz])
    printable_syms = list()
    astCtxt = tp.arch.tc.getAstContext()
    for i in xrange(sz):
        sym =tp.symbolize(buf + i)
        printable_syms.append(astCtxt.bvugt(astCtxt.variable(sym), astCtxt.bv(0x20, triton.CPUSIZE.BYTE_BIT)))
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
            if pc == 0x4000df or pc == 0x4001be:
                return False

        else:
            zf = tp.arch.tc.getSymbolicRegister(tp.arch.tc.registers.zf)
            astCtxt = tp.arch.tc.getAstContext()
            tp.previousConstraints = astCtxt.land([tp.previousConstraints, zf.getAst() == zf.getAst().evaluate()])
    return True

solution = None
valid = False

def GetModuleHandleA():
    print "GetModuleHandleA"
    return True

while True:
    process = TritonProcessNG()
    process.hooks["GetModuleHandleA"] = GetModuleHandleA
    if solution:
        process.solutions = solution
    process.instruction_hooks[triton.OPCODE.X86.INT] = int80_handler
    process.sym_callback = sym_inst_callback
    # process.load_binary("../../../pdf-js/DidierStevensSuite/rthide.exe")

    # process.load_binary("/home/ak42/CloudStation/challenges/crackmes.one/EasyPeasy.exe")
    # process.set_entrypoint(0x401530)

    # process.load_binary("/home/ak42/CloudStation/challenges/grehack19/angry_tux")
    # process.load_binary("../../../crackme/whitebox/r2con2017/trainings/beginner-training-01/upx/packed-upx")
    process.load_binary("a.out")

    process.run()

    solution =  process.solutions
    print "solution: ", solution

    if valid:
        break


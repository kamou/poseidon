#!/usr/bin/env python3

import sys
from tprocess import *
import texceptions
import tanalysis

def sym_callback(tp, inst):
    if (inst.isBranch() or inst.isControlFlow()):
        input()
        rcx = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rcx)
        rdx = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rdx)
        rax = tp.arch.tc.getConcreteRegisterValue(tp.arch.tc.registers.rax)
        astCtxt = tp.arch.tc.getAstContext()
        zf = tp.arch.tc.getSymbolicRegister(tp.arch.tc.registers.zf)
        tp.solve_with_equal(zf, 1)
    return True

def write(tp):
    fd = tp.arch.get_func_arg(0)
    addr = tp.arch.get_func_arg(1)
    sz = tp.arch.get_func_arg(2)
    print("write {} {} bytes from {:#x}".format(fd, sz, addr))
    if fd == 1:
        _s1 = tp.get_string(addr)
        print (_s1)
        tp.arch.func_ret()
        return True

    return False

def read(tp):
    print("read")
    fd = tp.arch.get_func_arg(0)
    addr = tp.arch.get_func_arg(1)
    sz = tp.arch.get_func_arg(2)
    print("read {} {} bytes to {:#x}".format(fd, sz, addr))
    if fd == 0:
        # data = input() + '\x00'
        data = "A"*0x30
        tp.arch.tc.setConcreteMemoryAreaValue(addr, bytes(data[:sz], "utf8"))
        tp.arch.func_ret(len(data[:sz]))
        # tp.arch.tc.symbolizeRegister(tp.arch.tc.registers.rax)
        for offset in range(addr, addr + sz, 1):
            sym = tp.symbolize(offset, 1)
            print(sym)
        return True
    exit(1)

    return False

solutions = None

while True:
    si = 0
    try:
        process = TritonProcess("./change_my_mind")
        process.log(True)
        process.solutions = solutions
        process.sym_callback = sym_callback
        process.hooks.add("write", write)
        process.hooks.add("read", read)
        process.run()
    except texceptions.NewSolution as e:
        solutions = e.model
        print (solutions)
        exit(1)
    except texceptions.UnmanagedInstruction:
        break
    except texceptions.NoPossibleSolution:
        print ("no solutions")
        break

output = "".join([chr(process.solutions[sym].getValue()) for sym in process.solutions])
print(output)



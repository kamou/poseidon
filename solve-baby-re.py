#!/usr/bin/env python3

import sys
from tprocess import *
import texceptions
import tanalysis

def sym_callback(tp, inst):
    if (inst.isBranch() or inst.isControlFlow()):
        astCtxt = tp.arch.tc.getAstContext()
        zf = tp.arch.tc.getSymbolicRegister(tp.arch.tc.registers.zf)
        tp.solve_with_equal(zf, 1)
    return True

def scanf(tp):
    global si
    fmt = tp.arch.get_func_arg(0)
    addr = tp.arch.get_func_arg(1)
    value = 0x61616161

    if tp.solutions:
        value = tp.solutions[si].getValue()
        si += 1

    tp.arch.set_memory_value(addr, value, 4)
    astCtxt = tp.arch.tc.getAstContext()
    sym = tp.symbolize(addr, 4)

    tp.arch.func_ret()

    return True

solutions = None

while True:
    si = 0
    try:
        process = TritonProcess("./samples/baby-re")
        process.log(True)
        process.solutions = solutions
        process.sym_callback = sym_callback
        process.hooks.add("__isoc99_scanf", scanf)
        process.run()
    except texceptions.NewSolution as e:
        solutions = e.model
    except texceptions.UnmanagedInstruction:
        break

output = "".join([chr(process.solutions[sym].getValue()) for sym in process.solutions])
print(output)



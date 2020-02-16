#!/usr/bin/env python3

import sys
from tprocess import *
import texceptions

def sym_callback(tp, inst):
    if (inst.isBranch() or inst.isControlFlow()):
        astCtxt = tp.arch.tc.getAstContext()
        zf = tp.arch.tc.getSymbolicRegister(tp.arch.tc.registers.zf)
        tp.solve_with_equal(zf, 1)
    return True

def main(tp):
    argc = tp.arch.get_func_arg(0)
    argv = tp.arch.get_func_arg(1)
    argv1 = tp.arch.get_memory_value(argv + 4, 4)
    for i in range(32):
        sym = tp.symbolize(argv1 + i, 1)
    return True

solution = "A"*32

while True:
    si = 0
    try:
        process = TritonProcess("./a.out")
        process.log(True)
        process.sym_callback = sym_callback
        process.add_bp(0x08049090, main)
        process.run([solution + "a" * (32-len(solution))])
    except texceptions.NewSolution as e:
        solution = "".join([chr(e.model[sym].getValue()) for sym in e.model])
    except texceptions.UnmanagedInstruction:
        print (solution)
        # break



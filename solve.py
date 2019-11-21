#!/usr/bin/env python3

import sys
from tprocess import *
import texceptions

def sym_callback(tp, inst):
    if (inst.isBranch() or inst.isControlFlow()):
        astCtxt = tp.arch.tc.getAstContext()
        zf = tp.arch.tc.getSymbolicRegister(tp.arch.tc.registers.zf)
        tp.previousConstraints = astCtxt.land([tp.previousConstraints, zf.getAst() == 1])
        if zf.getAst().evaluate() == 0:
            model = tp.arch.tc.getModel(tp.previousConstraints)
            if model:
                tp.solutions = model
                raise texceptions.NewSolution(model)
            else:
                raise texceptions.NoPossibleSolution()
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

def printf(tp):
    fmt = tp.arch.get_func_arg(0)
    _fmt = tp.get_string(fmt)
    tp.arch.func_ret()
    return True

if len(sys.argv) < 2:
    print("Binary required")
    exit(1)

solutions = None

while True:
    si = 0
    try:
        process = TritonProcessNG(sys.argv[1])
        process.solutions = solutions
        process.log(False)
        process.sym_callback = sym_callback
        process.hooks.add("printf", printf)
        process.hooks.add("__isoc99_scanf", scanf)
        process.run(sys.argv[2:])
    except texceptions.NewSolution as e:
        si = 0
        solutions = process.solutions
    except texceptions.UnmanagedInstruction:
        output = "".join([chr(process.solutions[sym].getValue()) for sym in process.solutions])
        print(output)
        break



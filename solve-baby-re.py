#!/usr/bin/env python3

import sys
from tprocess import *
import texceptions
import tanalysis

def sym_callback(tp, inst):
    global constraints
    if (inst.isBranch() or inst.isControlFlow()):
        astCtxt = tp.arch.tc.getAstContext()
        zf = tp.arch.tc.getSymbolicRegister(tp.arch.tc.registers.zf)
        constraints = tp.ast.land([constraints, zf.getAst() == 1])

        if zf.getAst().evaluate() != 1:
            model = tp.arch.tc.getModel(constraints)
            if model:
                raise texceptions.NewSolution(model)
            else:
                raise texceptions.NoPossibleSolution()

    return True

def scanf(tp):
    global solutions
    global si
    fmt = tp.arch.get_func_arg(0)
    addr = tp.arch.get_func_arg(1)
    value = 0x61616161

    if solutions:
        value = tp.solutions[si].getValue()
        si += 1

    tp.arch.set_memory_value(addr, value, 4)
    astCtxt = tp.arch.tc.getAstContext()
    sym = tp.symbolize(addr, 4)

    tp.arch.func_ret()

    return True

solutions = None

def memory_exception(tp, addr):
    if tp.cur_inst:
        operands = tp.cur_inst.getOperands()
        if len(operands) == 2 and operands[1].getType() == 2:
            segment = operands[1].getSegmentRegister().getName()
            disp = operands[1].getDisplacement()
            if segment == "fs" and disp.getValue() == 0x28 and 0x28 <= addr < 0x30:
                tp.arch.tc.setConcreteMemoryValue(addr, 0)
                return True
    return False

while True:
    si = 0
    try:
        process = TritonProcess("./samples/baby-re")
        constraints = process.ast.equal(process.ast.bvtrue(), process.ast.bvtrue())
        process.invalid_memory_handler = memory_exception
        process.log(TritonProcess.LOG_SYMBOLIC)
        # process.arch.only_on_tainted(True)
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



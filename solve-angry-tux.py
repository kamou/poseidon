#!/usr/bin/env python3

import sys
from tprocess import *
import texceptions

def sym_callback(tp, inst):
    if (inst.isBranch() or inst.isControlFlow()):
        tp.ast = tp.arch.tc.getAstContext()
        zf = tp.arch.tc.getSymbolicRegister(tp.arch.tc.registers.zf)
        pc = tp.arch.tc.getConcreteRegisterValue(tp.pc)
        if pc == 0x4000df:
            tp.solve_with_equal(zf, 1)
        else:
            tp.previousConstraints = tp.ast.land([tp.previousConstraints, zf.getAst() == zf.getAst().evaluate()])
    return True


solution = "0000000000000000000000000000000000000000000"
def syscall(tp):
    global solution
    sc = tp.arch.get_syscall_func_arg(0)

    if sc == 4: # write
        fd = tp.arch.get_syscall_func_arg(1)
        buf = tp.arch.get_syscall_func_arg(2)
        size = tp.arch.get_syscall_func_arg(3)
        output = tp.get_string(buf)
        # print (output[:size])
        tp.skip_inst()
        return True

    elif sc == 3: # read
        fd = tp.arch.get_syscall_func_arg(1)
        buf = tp.arch.get_syscall_func_arg(2)
        size = tp.arch.get_syscall_func_arg(3)

        tp.update_area(buf, solution)
        syms = dict()

        for i in range(size):
            syms[i] = tp.symbolize(buf+i, 1)
            tp.make_printable(syms[i])

        # cstr.land()
        tp.add_constraint(
            tp.ast.variable(syms[0]) == ord("G")
        )
        tp.add_constraint(
            tp.ast.variable(syms[1]) == ord("H")
        )
        tp.add_constraint(
            tp.ast.variable(syms[2]) == ord("1")
        )
        tp.add_constraint(
            tp.ast.variable(syms[3]) == ord("9")
        )

        tp.skip_inst()
        return True

    elif sc == 1: # exit
        raise texceptions.ExecutionTerminated()
    return False

while True:
    si = 0
    try:
        process = TritonProcess("./samples/angry_tux")
        process.add_instruction_hook(triton.OPCODE.X86.INT, syscall)
        # process.log(True)
        process.sym_callback = sym_callback
        process.run()
        solution = process.solutions
    except texceptions.NewSolution as e:
        solution = "".join([chr(e.model[sym].getValue()) for sym in e.model])
    except texceptions.ExecutionTerminated:
        print ("solution:", solution)
        break



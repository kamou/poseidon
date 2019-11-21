import lief

# customRelocation = [
#     ('strlen',            strlenHandler,   0x10000000),
#     ('printf',            printfHandler,   0x10000001),
#     ('__libc_start_main', libcMainHandler, 0x10000002),
# ]

class TritonOs(object):
    def __init__(self):
        pass


class TritonOsLinux(TritonOs):
    def __init__(self):
        self.contexts = list()
        # create main context
        # self.main_pid = r2.pid()
        # context = TritonProcess(self.architecture(), self.main_pid)
        # self.contexts.append(context)

        # # init main context
        # regs = r2.regs()
        # context.update_registers(regs)

        # print "[+] Updating for new process {}".format(self.main_pid)
        # mappings = r2.mappings()
        # for m in mappings:
        #     data = r2.read_at(m["addr"], m["addr_end"] - m["addr"])
        #     context.update_area(m["addr"], data)

        # var = 0
        # sections = r2.cmdj("iSj")
        # for s in sections:
        #     if s["name"] == ".data":
        #         var = s["vaddr"]
        #         break

        # for i in range(0x80):
        #     context.symbolize(var + 0x70 + i)

        for imp in r2.imports():
            if imp["name"] == "sym.imp.fork":
                context.hooks[imp["offset"]] = self.fork
            elif imp["name"] == "sym.imp.ptrace":
                context.hooks[imp["offset"]] = self.ptrace
            elif imp["name"] == "sym.imp.waitpid":
                context.hooks[imp["offset"]] = self.waitpid
            else:
                context.fail_on(imp["offset"])
        # context.hooks[triton.OPCODE.X86.INT3] = self.int3

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

    def on_inst(self, itype, hook, ctxid=None):
        if ctxid is not None:
            self.contexts[ctxid].hooks[triton.OPCODE.X86.INT3] = hook
        else:
            for context in self.contexts:
                context.hooks[triton.OPCODE.X86.INT3] = hook

    def concretize(self, process):
        self.arch.tcs[process].arch.tc.concretizeAllMemory()

    def current_context(self):
        return self.contexts[self.cur_ctx]

    def _run(self, context):
        # print "running pid {}".format(self.pid)
        arch = context.arch
        pc = arch.tc.getRegisterAst(context.pc).evaluate()

        while True:
            inst = triton.Instruction()
            inst.setOpcode(context.get_area(pc, 16))
            inst.setAddress(pc)
            context.arch.tc.disassembly(inst)
            print (inst)

            context.cur_inst = inst
            if pc in context.hooks:
                context.hooks[pc](context)
            elif inst.getType() in context.hooks:
                context.hooks[inst.getType()](self, context)

            elif pc in context.fail:
                raise ValueError(pc)
            else:
                context.arch.tc.processing(inst)
            # if inst.isSymbolized():
            #     print "{}: {}".format(context.pid, inst)
            pc = context.arch.tc.getRegisterAst(context.pc).evaluate()

    def real_run(self, filename):
        lief.parse(filename)
        new_tp = TritonProcess(self.architecture(), tp.pid + 1)
    def run(self, context=None, join=False):
        if context is None:
            context = self.contexts[0]
        t = threading.Thread(target = self._run, args = (context,))
        context.thread = t
        t.start()
        if join:
            t.join()

    # def __init__(self, filename):
    #     self.container = lief.parse(filename)

    # def _run(self, context):
    #     # print "running pid {}".format(self.pid)
    #     arch = context.arch
    #     pc = arch.tc.getRegisterAst(context.pc).evaluate()

    #     while True:
    #         inst = triton.Instruction()
    #         inst.setOpcode(context.get_area(pc, 16))
    #         inst.setAddress(pc)
    #         context.arch.tc.disassembly(inst)
    #         print inst

    #         context.cur_inst = inst
    #         if pc in context.hooks:
    #             context.hooks[pc](context)
    #         elif inst.getType() in context.hooks:
    #             context.hooks[inst.getType()](self, context)

    #         elif pc in context.fail:
    #             raise ValueError(pc)
    #         else:
    #             context.arch.tc.processing(inst)
    #         # if inst.isSymbolized():
    #         #     print "{}: {}".format(context.pid, inst)
    #         pc = context.arch.tc.getRegisterAst(context.pc).evaluate()
    # def run():
    #     pass

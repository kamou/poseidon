import lief
import triton
import tprocess

class TFunction(object):
    def __init__(self, addr):
        self.bbs = dict()
        self.calls = set()
        self.no_return = True
        self.addr = addr
        self.imp = False

    def bb_at(self, addr):
        if addr in self.bbs:
            return self.bbs[addr]

    def add(self, bb):
        if not bb:
            return
        bbat = self.bb_at(bb.addr)
        if bbat:
            if bbat.addr != bb.addr:
                bb.split(bb.addr)
        else:
            self.bbs[bb.addr] = bb

    def has_addr(self, addr):
        for bb in self.bbs:
            if self.bbs[bb].has_addr(addr):
                return True
        return False

    def has_bb_addr(self, addr):
        return addr in self.bbs

    def is_no_return(self):
        return self.no_return

    def set_no_return(self, nr):
        self.no_return = nr

class TFunctionPool(object):
    def __init__(self):
        self.fcns = dict()

    def add(self, fcn):
        self.fcns[fcn.addr] = fcn

    def fcn_at(self, addr):
        if addr in self.fcns:
            return self.fcns[addr]

    def update(self, fcns):
        for fcn in fcns:
            if fcn: self.fcns[fcn.addr] = fcn

class TBasicPool(object):
    def __init__(self):
        self.bbs = dict()

    def add(self, bb):
        self.bbs[bb.addr] = bb

    def bb_get(self, addr):
        if self.has_bb(addr):
            return self.bbs[addr]

    def bb_at(self, addr):
        for bb in self.bbs:
            if self.bbs[bb].addr <= addr < self.bbs[bb].addr + self.bbs[bb].size:
                return self.bbs[bb]

    def has_bb(self, addr):
        return addr in self.bbs

    def split(self, addr):
        if addr not in self.bbs:
            return None, None

        bb = self.bbs[addr]
        first, second = bb.split(addr)
        # update current state
        self.update([first, second])
        return first, second

    def update(self, bbs):
        for bb in bbs:
            if bb: self.bbs[bb.addr] = bb

class TBasicBlock(object):
    def __init__(self, addr, size, bf=None, bt=None):
        self.addr = addr
        self.size = size
        self.bf = bf
        self.bt = bt
        self.functions = set()
        self.parents = set()

    def used_by(self, fcn):
        self.functions.add(fcn)
        # fcn.add(self)

    def add_parent(self, block):
        self.parents.add(block)

    def split(self, addr):
        if (addr == self.addr):
            return None, self

        nb = TBasicBlock(addr, self.size - (addr - self.addr), bf=self.bf, bt=self.bt)
        nb.add_parent(self)
        self.size = addr - self.addr
        self.bf = nb
        self.bt = None
        return self, nb

    def update(self):
        pass

    def has_addr(self, addr):
        if self.addr <= addr < self.addr + self.size:
            return True
        return False


class TAnalyis(object):
    def __init__(self, tp):
        self.tp = tp
        self.bb_pool = TBasicPool()
        self.fcn_pool = TFunctionPool()
        # Useful for detecting recursion
        self.analysing = set()

    def analyse_function(self, addr):
        self.analysing.add(addr)
        todo = list([addr])
        fcn = TFunction(addr)
        fcn.set_no_return(True)

        parents = dict()
        while len(todo):
            addr = todo.pop()

            first, second = self.bb_pool.split(addr)
            if second:
                if second.addr in parents:
                    second.parents.update(parents[second.addr])
            fcn.add(second)
            current_block = addr

            while True:
                inst = self.tp.disassemble(addr)
                if self.tp.arch.is_branch(inst):
                    dst = inst.getOperands()[0]
                    if dst.getType() == triton.OPERAND.IMM:
                        dst = dst.getValue()
                        nxt = inst.getAddress() + inst.getSize()

                        bb = TBasicBlock(current_block, nxt - current_block)
                        self.bb_pool.add(bb)
                        fcn.add(bb)

                        if not self.bb_pool.has_bb(dst):
                            todo.append(dst)
                        else:
                            bb = self.bb_pool.bb_get(dst)
                            bb.add_parent(current_block)
                            fcn.add(bb)

                        if dst not in parents:
                            parents[dst] = set()

                        parents[dst].add(current_block)

                    elif dst.getType() == triton.OPERAND.MEM:
                        disp = dst.getDisplacement()
                        scale = dst.getScale()
                        br = dst.getBaseRegister()
                        sr = dst.getSegmentRegister()

                        if disp.getType() != triton.OPERAND.IMM:
                            print ("[!] Branch type not supported 1")
                            print (inst)
                            exit(1)

                        if scale.getType() != triton.OPERAND.IMM or scale.getValue() != 1:
                            print ("[!] Branch type not supported 2")
                            print (inst)
                            exit(1)

                        if br.getType() == triton.OPERAND.REG:
                            if br != self.tp.pc:
                                print ("[!] Branch type not supported 3")
                                print (inst)
                                exit(1)

                        if sr.getType() == triton.OPERAND.REG:
                            if sr.getName() != "unknown":
                                print ("[!] Branch type not supported 4")
                                print (inst)
                                exit(1)

                        pointer = addr + disp.getValue() + inst.getSize()
                        target = self.tp.arch.get_memory_value(pointer, self.tp.arch.psize)& 0x00ffffffff
                        assert(pointer in self.tp.relocations)
                        if target in self.tp.relocations:
                            nxt = inst.getAddress() + inst.getSize()
                            fcn.imp = True
                            fcn.name = self.tp.relocations[target]
                            if fcn.name not in self.tp.hooks.no_return:
                                fcn.set_no_return(False)
                            # TODO: detect known no return functions
                            bb = TBasicBlock(current_block, nxt - current_block)
                            fcn.add(bb)
                            self.bb_pool.add(bb)
                            self.fcn_pool.add(fcn)
                            self.analysing.remove(fcn.addr)
                            return fcn
                        else:
                            print ("wtf")
                            exit(1)
                    else:
                        if dst.getType() == triton.OPERAND.IMM:
                            todo.append(dst.getValue())
                        else:
                            # TODO: use emulation to resolve restination.
                            print ("[!] Branch to Register not implemented")
                            print (inst)
                            fcn.set_no_return(False)
                        break

                    if not self.tp.arch.is_conditional_branch(inst):
                        break

                    current_block = inst.getAddress() + inst.getSize()

                elif self.tp.arch.is_ret(inst):
                    nxt = inst.getAddress() + inst.getSize()
                    bb = TBasicBlock(current_block, nxt - current_block)
                    self.bb_pool.add(bb)
                    fcn.add(bb)
                    fcn.set_no_return(False)
                    break

                elif self.tp.arch.is_call(inst):
                    # TODO: check for known no ret functions
                    dst = inst.getOperands()[0]
                    if dst.getType() == triton.OPERAND.IMM:
                        dst  = inst.getOperands()[0].getValue()
                        if  dst not in self.analysing:
                            callee = self.fcn_pool.fcn_at(dst)
                            if not callee:
                                callee = self.analyse_function(dst)
                            if callee.is_no_return():
                                nxt = inst.getAddress() + inst.getSize()
                                bb = TBasicBlock(current_block, nxt - current_block)
                                self.bb_pool.add(bb)
                                fcn.add(bb)
                                break
                        else:
                            print ("[*] Recursion detected for function {:#x}".format(dst))
                        fcn.calls.add(dst)
                    elif dst.getType() == triton.OPERAND.MEM:
                         print ("[!] Call to MemoryAccess not implemented")
                         print (inst)
                    else:
                         print ("[!] Call type not implemented")
                         print (inst)

                # TODO: look for no ret syscalls
                addr = addr + inst.getSize()

        self.analysing.remove(fcn.addr)
        self.fcn_pool.add(fcn)
        # if fcn.is_no_return():
            # print("NORETURN @ {:#x}".format(fcn.addr))
        return fcn

    def find_input_registers(self, fcn):
        print ("[*] Creating process")
        tp = tprocess.TritonProcess(self.tp.filename, container=self.tp.container)
        # for reg in tp.arch.tc.getParentRegisters():
        #     try:
        #         tp.arch.tc.symbolizeRegister(reg)
        #     except: pass
        pc = fcn.addr
        known_regs = set()
        input_regs = set()
        tp.arch.write_reg(tp.pc, fcn.addr)
        print ("[*] emulating")
        while True:
            inst = tp.disassemble()
            print (inst)
            if inst and tp.arch.is_call(inst):
                if inst.getOperands()[0].getType() == triton.OPERAND.IMM:
                     dst  =inst.getOperands()[0].getValue()
                     called = self.fcn_pool.fcn_at(dst)
                     if called.no_return:
                         return input_regs
                pc = inst.getAddress() + inst.getSize()
                tp.arch.write_reg(tp.pc, pc)
                continue
            try:
                inst = tp.process()
            except:
                print ("except")
                return(input_regs)
            if inst:
                found_regs = list()
                for reg in inst.getReadRegisters():
                    if reg[0].getName() not in known_regs:
                        found_regs.append(reg[0].getName())
                for reg in inst.getWrittenRegisters():
                    if reg[0].getName() in found_regs:
                        r  = tp.arch.tc.getSymbolicRegister(reg[0])
                        print ("@@@@@@@")
                        print ("@@@@@@@")
                        print ("@@@@@@@")
                        print ("@@@@@@@")
                        print ("@@@@@@@")
                        print (r)
                    else: input_regs.update(found_regs)

                    known_regs.add(reg[0].getName())

                if tp.arch.is_ret(inst):
                    return input_regs

            pc = tp.arch.read_reg(tp.pc)


import lief
import triton

# class TBBPool(object):
#     def __init__(self):
#         self.bbmap = dict()

#     def add_block(self, block):
#         for bb in self.bbmap:
#             if block.in(bb):
#                 bb1, bb2 = bb.split(block)

class TFunction(object):
    def __init__(self, addr):
        self.bbs = list()
        self.calls = list()

    def bb_at(self, addr):
        for bb in self.bbs:
            if bb.has_addr(addr):
                return bb

    # def add(self, bb):
    #     bbat = self.bb_at(bb.addr)
    #     if bbat:
    #         if bbat.addr != bb.addr:
    #             bb.split(bb.addr)
    #     else:
    #         self.bbs.append(bb)

    def has_addr(self, addr):
        for bb in self.bbs:
            if bb.has_addr(addr):
                return True
        return False
    def has_bb_addr(self, addr):
        for bb in self.bbs:
            if bb.addr == (addr):
                return True
        return False

class TBasicPool(object):
    def __init__(self):
        self.bbs = list()
    def add(self, bb):
        self.bbs.append(bb)

    def bb_at(self, addr):
        for bb in self.bbs:
            if bb.addr <= addr < bb.addr + bb.size:
                return bb

    def bb_split_at(self, addr):
        bb = self.bb_at(addr)
        bb.split(addr)

class TBasicBlock(object):
    def __init__(self, addr, size, bf=None, bt=None):
        self.addr = addr
        self.size = size
        self.bf = bf
        self.bt = bt
        self.functions = set()
        self.parent = list()

    def used_by(self, fcn):
        self.functions.add(fcn)
        # fcn.add(self)

    def add_parent(self, block):
        self.parent.append(block)

    def split(self, addr):
        assert(addr > self.addr and addr < self.addr + self.size)
        nb = TBasicBlock(addr, self.size - (addr - self.addr), bf=self.bf, bt=self.bt)
        nb.add_parent(self)
        self.size = addr - self.addr
        self.bf = None
        self.bt = nb

    def update(self):
        pass

    def has_addr(self, addr):
        if self.addr <= addr < self.addr + self.size:
            return True
        return False


class TAnalysis(object):
    def __init__(self, filename):
        self.container = lief.parse(filename)
        self.entrypoint = self.container.entrypoint
        if self.container.format == lief.EXE_FORMATS.ELF:
            if self.container.header.machine_type == lief.ELF.ARCH.i386:
                self.arch = capstone.CS_ARCH_X86
                self.bits = capstone.CS_MODE_32
            elif self.container.header.machine_type == lief.ELF.ARCH.x86_64:
                self.arch = capstone.CS_ARCH_X86
                self.bits = capstone.CS_MODE_64
            elif self.container.header.machine_type == lief.ELF.ARCH.AARCH64:
                print "[!] lief.ARCH.AARCH64 Not supported yet"
                exit(1)
            else:
                print "[!] {} Not supported yet".format(self.container.format)
                exit(1)

        self.exe = list()
        for s in self.container.segments:
            if (s.has(lief.ELF.SEGMENT_FLAGS.X)):
                self.exe.append(s)

        self.md = capstone.Cs(self.arch, self.bits)
        self.md.detail = True
        self.basicblocks = []
        self.pool = TBasicPool()
        # self.basicblocks.append(TBasicBlock(self.entrypoint, 0, bt=None, bf=None))

    def is_executable(self, addr):
        for s in self.exe:
            if s.virtual_address <= addr < s.virtual_address + s.virtual_size:
                # print self.exe, s
                return True
        return False

    def analyse_function(self, addr, recursive=False):
        todo = [addr]
        fcn = TFunction(addr)
        while len(todo):
            addr = todo.pop()
            try:
                while fcn.has_bb_addr(addr):
                    addr = todo.pop()
            except:
                break

            cur_block_addr = addr
            print "handling {:#x}".format(addr)
            while True:
                data = self.container.get_content_from_virtual_address(addr, 32)
                data = ''.join(chr(i) for i in data)
                dis =  self.md.disasm(data, addr)

                old_addr = addr
                for i in dis:
                    print hex(addr),(i.mnemonic), i.op_str
                    print i.groups
                    if 1 in i.groups:
                        assert(len(i.operands) == 1)
                        print dir(i)
                        # print dir(i.detail)
                        j_addr = i.operands[0]
                        if j_addr.type == 2:
                            todo.append(j_addr.imm)

                        bb = self.pool.bb_at(cur_block_addr)
                        if bb:
                            if bb.addr == cur_block_addr:
                                # bb already decoded
                                print "already decoded {:#x}".format(bb.addr)
                                bb.used_by(fcn)
                            else:
                                bb.split(cur_block_addr)
                                # split
                        else:
                            bb = TBasicBlock(cur_block_addr, addr+i.size-cur_block_addr)
                            bb.used_by(fcn)
                            self.pool.add(bb)
                        print "---------"
                        cur_block_addr = addr+i.size
                    # call
                    elif 2 in i.groups:
                        pass
                    # ret
                    elif 3 in i.groups:
                        break
                    # hlt ?
                    elif 6 in i.groups:
                        break

                    addr += i.size

                if old_addr == addr:
                    print "invalid instr"
                    break

ta = TAnalysis("./ringgit")
print ta.analyse_function(0x1254)

import r2pipe

def require_dbg(self, f):
    def not dbg_check(*args, **kwargs):
        if self.debug:
            raise ValueError("'{}' requires debug mode")

        return f(*args, **kwargs)
    return dbg_check

def require_write(self, f):
    def dbg_check(*args, **kwargs):
        if not self.debug and not self.write:
            raise ValueError("'{}' requires debug mode")

        return f(*args, **kwargs)
    return dbg_check

class R2(object):
    def __init__(self, filename, write=False, debug=False, profile=None):
        self.options = list()
        if debug and write:
            raise ValueError("Can't ask for debug and write")

        if debug:   self.options.append("-d")
        if write:   self.options.append("-w")
        if profile:
            self.options.append("-e")
            self.options.append("dbg.profile={}".format(profile))

        self.r2 = r2pipe.open(filename, self.options)

    @require_dbg
    def until(self, address):
        self.do_cmd("dcu {:#x}".format(address))

    @require_dbg
    def step(self, over=False):
        if over:
            self.do_cmd("dso")
        else:
            self.do_cmd("ds")

    @require_dbg
    def breakpoint(self, address):
        self.do_cmd("db {:#x}".format(address))

    @require_dbg
    def continue(self):
        self.do_cmd("dc")

    @require_write
    def write(self, data, address):
        self.do_cmd("wx {} @ {:#x}".format(binascii.hexlify(data), address))

    @require_write
    def assemble(self, asm_str, address):
        self.do_cmd("\"wa {}\" @ {:#x}".format(asm_str, address))

    def do_cmd(self, data):
        self.r2.cmd(data)

    def search(self, data, address):
        self.do_cmd("/x {} @ {:#x}", binascii.hexlify(data), address)
        self.do_cmd("fs search")
        hits = self.do_cmdj("fj")
        return [ hit["offset"] for hit in hits ]

    def quit():
        self.r2.quit()


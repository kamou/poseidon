import r2pipe
import binascii
import time

def require_dbg(f):
    def dbg_check(self, *args, **kwargs):
        if not self.debug:
            raise ValueError("'{}' requires debug mode")

        return f(self, *args, **kwargs)
    return dbg_check

def require_write(f):
    def dbg_check(self, *args, **kwargs):
        if not self.debug and not self.writeable:
            raise ValueError("'{}' requires debug mode")
        return f(self, *args, **kwargs)
    return dbg_check

class R2(object):
    def __init__(self, filename=None, write=False, debug=False, profile=None, options=None):
        if options:
            self.options = options
        else:
            self.options = list()
        self.debug = debug
        self.writeable = write
        if debug and write:
            raise ValueError("Can't ask for debug and write")

        if debug:   self.options.append("-d")
        if write:   self.options.append("-w")
        if profile:
            self.options.append("-e")
            self.options.append("dbg.profile={}".format(profile))

        print (self.options)
        if filename:
            self.r2 = r2pipe.open(filename, self.options)
        else:
            self.r2 = r2pipe.open()
            self.debug = True

    @require_dbg
    def until(self, address):
        return self.do_cmd("dcu {:#x}".format(address))

    @require_dbg
    def until_flag(self, flag):
        return self.do_cmd("dcu {}".format(flag))

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
    def cont(self):
        self.do_cmd("dc")

    @require_dbg
    def write_reg(self, reg, value):
        self.r2.cmd("dr {}={:#x}".format(reg, value))

    @require_dbg
    def registers(self):
        return self.do_cmdj("drj")

    def read(self, address, size):
        return bytes.fromhex(self.do_cmd("p8 {} @ {:#x}".format(size, address)).strip())

    @require_dbg
    def get_maps(self):
        return self.do_cmdj("dmj")

    @require_write
    def write(self, data, address):
        data = binascii.hexlify(data).decode("utf-8")
        return self.do_cmd("wx {} @ {:#x}".format(data, address))

    @require_write
    def assemble(self, asm_str, address):
        self.do_cmd("\"wa {}\" @ {:#x}".format(asm_str, address))

    def do_cmd(self, cmd):
        ret = self.r2.cmd(cmd.strip())
        # time.sleep(0.5)
        return ret

    def do_cmdj(self, cmd):
        data = self.r2.cmdj(cmd.strip())
        # time.sleep(0.5)

        if data is None:
            print ("DATA NONE")

        while data is None:
            data = self.r2.cmdj(cmd)
        return data

    def search(self, data):
        data = binascii.hexlify(data).decode("utf-8")
        self.do_cmd("/x {}".format(data))
        self.do_cmd("fs search")
        hits = self.do_cmdj("fj")
        return [ hit["offset"] for hit in hits ]

    def quit(self):
        self.r2.quit()


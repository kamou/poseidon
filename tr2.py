import r2pipe

class R2(object):
    def __init__(self, filename, profile=None, debug=False):
        self.debug = debug
        if self.debug:
            if profile:
                self.r2 = r2pipe.open(
                    filename,
                    [
                        "-e", "dbg.profile={}".format(profile),
                        "-d"
                    ]
                )
            else:
                self.r2 = r2pipe.open(filename, ["-d"])
        else:
            self.r2 = r2pipe.open(filename)
        self.info = self.cmdj("iIj")
    def regs(self):
        return self.r2.cmdj("drj")
    def imports(self):
        self.cmd("fs imports")
        return self.cmdj("fj")
    def mappings(self):
        return self.r2.cmdj("dmj")
    def entrypoint(self):
        return self.cmdj("iej")[0]["vaddr"]
    def read_at(self, at, n):
        return self.cmd("p8 {} @ {:#x}".format(n, at)).strip().decode("hex")
    def arch(self):
        return self.info["arch"]
    def bits(self):
        return self.info["bits"]
    def cmdj(self, cmd):
        return self.r2.cmdj(cmd)
    def cmd(self, cmd):
        return self.r2.cmd(cmd)
    def pid(self):
        pids = self.cmdj("dpj")
        for pid in pids:
            if pid["path"] == "(current)":
                return  pid["pid"]

    def main(self):
        self.cmd("fs symbols")
        symbols = self.cmdj("fj")
        for symbol in symbols:
            if symbol["name"] in ("sym.main", "main"):
                return symbol["offset"]

    def address(self, address):
        if isinstance(address, str):
            self.r2.cmd("fs *")
            flags = self.r2.cmdj("fj")
            for f in flags:
                if f["name"] == address:
                    return f["offset"]
            try:
                return int(address, 16)
            except:
                return int(self.cmdj("?j {}".format(address))["hex"], 16)

        elif isinstance(address, int):
            return address

        return None

    def run(self, until=None):
        if until:
            print (self.r2.cmd("dcu {:#x}".format(self.address(until))))
        else:
            print (self.r2.cmd("dc"))

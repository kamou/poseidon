
class ExecutionTerminated(Exception):
    pass

class SyscallTooManyArgs(Exception):
    pass

class NewSolution(Exception):
    def __init__(self, model):
        self.model = model

        super(NewSolution, self).__init__()
    def __str__(self):
        return(
            "new possible model: {}".format(self.model)
        )

class NoPossibleSolution(Exception):
    def __init__(self):
        super(NoPossibleSolution, self).__init__()


class UnmanagedInstruction(Exception):
    def __init__(self, inst):
        self.inst = inst
        super(UnmanagedInstruction, self).__init__()
    def __str__(self):
        return(
            "Unknown Instruction\n\t{}".format( self.inst)
        )

class MissingHook(Exception):
    def __init__(self, name):
        self.name = name
        super(MissingHook, self).__init__()

    def __str__(self):
        return(
            "Unknown function {}".format(self.name)
        )

class InvalidMemoryAccess(Exception):
    def __init__(self, inst, addr, size):
        self.inst = inst
        self.addr = addr
        self.size = size
        super(InvalidMemoryAccess, self).__init__()
    def __str__(self):
        if self.inst:
            return(
                "Invalid Memory Access at {:#x}[{}] from {:#x}\n\t{}".format(
                    self.addr,
                    self.size,
                    self.inst.getAddress(),
                    self.inst
                )
            )
        else:
            return(
                "Invalid Memory Access at {:#x}[{}]".format(
                    self.addr,
                    self.size,
                )
            )

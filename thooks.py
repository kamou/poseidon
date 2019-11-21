import texceptions
import codecs

class HooksLib(object):

    def __init__(self):
        self.heap = 0xff700000
        self.offset = 0
        self.user = dict()

    def add(self, name, cb):
        self.user[name] = cb

    def call(self, name, tp):

        if name in self.user:
            return self.user[name](tp)

        try:
            func = getattr(self, "__{}_hook__".format(name))
        except:
            raise texceptions.MissingHook(name) from None
        if callable(func):
            return func(tp)

        raise texceptions.MissingHook(name)


    def __exit_hook__(self, tp):
        return False

    def __malloc_hook__(self, tp):
        size = tp.arch.get_func_arg(0)
        address = self.heap + self.offset
        self.offset += size
        tp.arch.func_ret(address)
        return True




class HooksLinux(HooksLib):

    def ____libc_start_main_hook__(self, tp):
        # call main with expected arguments (argc, argv, [envp])
        main = tp.arch.get_func_arg(0)
        argc = tp.arch.get_func_arg(1)
        argv = tp.arch.get_func_arg(2)

        sp = tp.arch.read_reg(tp.sp)
        tp.arch.write_reg(tp.pc, main)
        tp.arch.set_func_arg(0, argc)
        tp.arch.set_func_arg(1, argv)

        return True

    def __getpid_hook__(self, tp):
        tp.arch.func_ret(tp.pid)
        return True

    def __printf_hook__(self, tp):
        fmt = tp.arch.get_func_arg(0)
        print (tp.get_string(fmt))
        tp.arch.func_ret()
        return True

    def __fflush_hook__(self, tp):
        tp.arch.func_ret()
        return True


    def __memset_hook__(self, tp):
        s = tp.arch.get_func_arg(0)
        c = tp.arch.get_func_arg(1)
        n = tp.arch.get_func_arg(2)

        for index in range(n):
            tp.arch.tc.setConcreteMemoryValue(s+index, c)

        tp.arch.func_ret()
        return True

    def __strncmp_hook__(self, tp):
        # int strncmp(const char *s1, const char *s2, size_t n);
        s1 = tp.arch.get_func_arg(0)
        s2 = tp.arch.get_func_arg(1)
        n = tp.arch.get_func_arg(2)
        _s1 = tp.get_string(s1)
        _s2 = tp.get_string(s2)
        if _s1[:n] == _s2[:n]:
            tp.arch.func_ret(0)
        else:
            # FIXME
            tp.arch.func_ret(1)
        return True

    def __setlocale_hook__(self, tp):
        tp.arch.func_ret(0)
        return True

    def __strcmp_hook__(self, tp):
        # int strncmp(const char *s1, const char *s2, size_t n);
        s1 = tp.arch.get_func_arg(0)
        s2 = tp.arch.get_func_arg(1)
        _s1 = tp.get_string(s1)
        _s2 = tp.get_string(s2)

        if _s1 == _s2:
            tp.arch.func_ret(0)
        else:
            # FIXME
            tp.arch.func_ret(1)
        return True

    def __fgets_hook__(self, tp):
        s = tp.arch.get_func_arg(0)
        size = tp.arch.get_func_arg(1)
        stream = tp.arch.get_func_arg(2)

        # dirty hack for now, just check it is stdin from symbols.
        # FIXME, handle fopen !!

        for sym in  (tp.container.symbols):
            if sym.value == stream:
                break
        if sym.name == "stdin":
            data = raw_input()
            r = len(data) if len(data) < size-1 else size-1
            for index in range(r):
                tp.arch.tc.setConcreteMemoryValue(s+index, ord(data[index]))
            tp.arch.tc.setConcreteMemoryValue(s+size-1, 0)
        else:
            print ("[+] fgets({:#x}, {}, {:#x})".format(s, size, stream))
            print ("[!] unknown file handle, aborting..")
            exit(1)

        tp.arch.func_ret(s)
        return True

    def __strstr_hook__(self, tp):
        haystack = tp.arch.get_func_arg(0)
        needle = tp.arch.get_func_arg(1)
        _haystack = tp.get_string(haystack)
        _needle = tp.get_string(needle)
        offset = _haystack.find(_needle)
        tp.arch.func_ret(haystack + offset)
        return True

    def __strrchr_hook__(self, tp):
        s = tp.arch.get_func_arg(0)
        c = tp.arch.get_func_arg(1)
        _s = tp.get_string(s)
        offset = _s.rfind(chr(c))
        tp.arch.func_ret(s + offset)
        return True

    def __strcspn_hook__(self, tp):
        # size_t strcspn(const char *s, const char *reject);
        s = tp.arch.get_func_arg(0)
        reject = tp.arch.get_func_arg(1)
        _s = tp.get_string(s)
        reject_string = tp.get_string(reject)
        for i, c in enumerate(_s):
            if c in reject_string:
                break

        tp.arch.func_ret(i+1)
        return True

    def __strlen_hook__(self, tp):
        s = tp.arch.get_func_arg(0)
        _s = tp.get_string(s)
        tp.arch.func_ret(len(_s))
        return True

    def __puts_hook__(self, tp):
        s = tp.arch.get_func_arg(0)
        _s = tp.get_string(s)
        print (_s)
        tp.arch.func_ret()
        return True

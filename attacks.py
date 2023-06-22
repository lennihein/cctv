from infofetch import Info
from printingtools import RED, GREEN, YELLOW, MAGENTA, CYAN

STD_OK = "protected", GREEN
STD_POK = "likely protected", CYAN
STD_PNO = "assume vulnerable", MAGENTA
STD_NO = "vulnerable", RED
STD_NA = "unknown", YELLOW

PROT = "protected"
PPROT = "likely protected"
PVULN = "assume vulnerable"
VULN = "vulnerable"
UNK = "unknown"


class Attacks:

    @staticmethod
    def mpx(i: Info):
        """Meltdown-BR-MPX"""
        cases = {"supported": STD_PNO, "not supported": ("protected", GREEN, "MPX not supported"), "unknown": STD_NA
                 }
        return cases[i.mpx]

    @staticmethod
    def v1(i: Info):
        """Meltdown-US-L1"""
        # if full virtualisation is used, US-L1 can't be used cross-vm
        if i.virt.current == i.virt.vm and i.virt.current is not None:
            return PROT, GREEN, "fully virtualised"
        else:
            # todo: check for US-L1 status in case of
            return STD_NA

    @staticmethod
    def de(i: Info):
        """Meltdown-DE"""
        if i.cpu_vendor != "ARM":
            return "protected", GREEN, "only affects ARM"
        else:
            return STD_NA

    @staticmethod
    def foreshadow_vmm(i: Info):
        """Foreshadow-VMM"""
        # vulnerable cpu?
        l1tf_state: str
        try:
            with open('/sys/devices/system/cpu/vulnerabilities/l1tf') as f:
                l1tf_state = f.read().strip()
            if l1tf_state == "Not affected":
                return "protected", GREEN, "CPU not affected"
        except FileNotFoundError:
            pass
        # # virtualised?
        # # todo: what is with container?
        # if not i.virt.vm:
        #     return "protected", GREEN, "not virtualised"
        # trusted guests? no
        # EPT disabled?
        if i.ept != "supported":
            return "protected", GREEN, "ept disabled"
        # SMT disabled?
        if i.smt == "disabled or not supported":
            if i.l1d_flush == "likely active":
                return "likely protected", CYAN, "L1D Flush likely"
            elif i.l1d_flush == "assume inactive":
                return "assume vulnerable", MAGENTA, "L1D Flush unlikely"
            else:
                return "assume vulnerable", MAGENTA, "L1D Flush unlikely"
        elif i.smt == "enabled":
            # home alone no
            return "vulnerable", RED, "SMT active"
        elif i.smt == "unknown":
            # home alone no
            return "assume vulnerable", MAGENTA, "SMT likely active"
        raise AssertionError

    @staticmethod
    def fallout(i: Info):
        """Fallout"""
        # protected against cross hyperthread (i.e. SMT is not an issue)
        # vulnerable cpu?
        mds_state: str
        try:
            with open('/sys/devices/system/cpu/vulnerabilities/mds') as f:
                mds_state = f.read().strip()
            if mds_state == "Not affected":
                return "protected", GREEN, "CPU not affected"

            # # virtualised?
            # # todo: what is with container?
            # if not i.virt.vm:
            #     return "protected", GREEN, "not virtualised"
            # trusted guests? no
            # SMT dontcare
            # MDS enabled on host?
            if i.md_clear == "supported":
                if ("Clear CPU buffers" in mds_state):
                    return "likely protected", CYAN, "best effort clear"
        except FileNotFoundError:
            pass
        # L1TF vulnerable?
        l1tf_state: str
        try:
            with open('/sys/devices/system/cpu/vulnerabilities/l1tf') as f:
                l1tf_state = f.read().strip()
            if l1tf_state == "Not Affected":
                return "protected", GREEN, "not affected"
        except FileNotFoundError:
            pass
        # L1D Flush enabled?
        if i.l1d_flush == "likely active":
            return "likely protected", CYAN, "L1D Flush likely"
        elif i.l1d_flush == "assume inactive":
            return "assume vulnerable", MAGENTA, "L1D Flush unlikely"
        else:
            return "assume vulnerable", MAGENTA, "L1D Flush unlikely"

    @staticmethod
    def zombieload(i: Info):
        """Zombieload Same Hyperthread"""
        return Attacks.fallout(i)

    @staticmethod
    def zombieload_ht(i: Info):
        """Zombieload Cross Hyperthread"""
        # vulnerable cpu?
        mds_state: str
        try:
            with open('/sys/devices/system/cpu/vulnerabilities/mds') as f:
                mds_state = f.read().strip()
            if mds_state == "Not Affected":
                return "protected", GREEN, "not affected"
        except FileNotFoundError:
            pass
        # # virtualised?
        # # todo: what is with container?
        # if not i.virt.vm:
        #     return "protected", GREEN, "not virtualised"
        # trusted guests? no
        # SMT disabled?
        if i.smt == "disabled or not supported":
            return Attacks.fallout(i)
        elif i.smt == "enabled":
            # home alone no
            return "vulnerable", RED, "SMT active"
        elif i.smt == "unknown":
            # home alone no
            return "assume vulnerable", MAGENTA, "SMT likely active"

    @staticmethod
    def ridl(i: Info):
        """Rogue Inflight Data Load Same Hyperthread"""
        return Attacks.fallout(i)

    @staticmethod
    def ridl_ht(i: Info):
        """Rogue Inflight Data Load Cross Hyperthread"""
        return Attacks.zombieload_ht(i)

    @staticmethod
    def data_bounce(i: Info):
        """Data Bounce"""
        return STD_NA

    @staticmethod
    def lazy_fp(i: Info):
        """LazyFP"""
        return STD_NA

    @staticmethod
    def pf_rw(i: Info):
        """Meltdown-RW (aka 1.2)"""
        return STD_NA

    @staticmethod
    def ud(i: Info):
        """Meltdown-UD"""
        if i.cpu_arch == "aarch64" or i.cpu_vendor == "ARM":
            assert (i.cpu_arch == "aarch64" and i.cpu_vendor == "ARM")
            return STD_NA
        else:
            return "protected", GREEN, "only affects ARM"

    @staticmethod
    def ss(i: Info):
        """Meltdown-SS"""
        if i.cpu_vendor == "AMD":
            return STD_NA
        else:
            return "protected", GREEN, "only affects AMD"

    @staticmethod
    def bnd(i: Info):
        """Meltdown-BR-BND"""
        return STD_NA

    @staticmethod
    def cpl_reg(i: Info):
        """Meltdown-CPL-REG (aka v3a)"""
        return STD_NA

    @staticmethod
    def pk(i: Info):
        """Meltdown-PK"""
        # /sys/devices/cpu/caps/pmu_name is bugged on some systems
        # try:
        #     with open('/sys/devices/cpu/caps/pmu_name') as f:
        #         pmu = f.read().strip()
        #         if pmu == "skylake-sp":
        #             return STD_NO
        # except FileNotFoundError:
        #     pass
        # return PROT, GREEN, "only affects Skylake-SP"
        if i.pku == "full support":
            # todo: is vulnerable?
            return PVULN, MAGENTA, "full Protection Keys support"
        elif i.pku == "hardware support":
            # todo: is vulnerable?
            return PVULN, MAGENTA, "Protection Keys hardware support"
        return "protected", GREEN, "Protection Keys not supported"

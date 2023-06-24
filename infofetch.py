from printingtools import res_print, BOLD, UNDERLINE, ENDC, FAIL, WARNING
from subprocess import run
import os
import platform


class VirtInfo:
    def __init__(self, current, vm, container):
        self.current = current if current != "none" else None
        self.vm = vm if vm != "none" else None
        self.container = container if container != "none" else None

    def __str__(self):
        if self.current is None:
            return "None"
        if None in {self.vm, self.container}:
            return self.current
        else:
            outer = self.vm if self.vm != self.current else self.container
            return f"{UNDERLINE + self.current + ENDC} inside {outer}"


class Info:
    def __init__(self, duration: float = .3, wait: float = 0.3):
        # params
        self.print_duration = duration
        self.print_wait = wait
        # infos
        self.lscpu: str = run(["lscpu"], capture_output=True).stdout.decode('utf-8')
        self.flags: list = [ln.split(": ")[1] for ln in self.lscpu.split("\n") if "Flags: " in ln][0].strip().split(" ")
        self.virt: VirtInfo = VirtInfo("none", "none", "none")
        self.smt = None
        self.mpx = None
        self.l1d_hw = None
        self.l1d_flush = None
        self.md_clear = None
        self.ucode = None
        self.ept = None
        self.guest_pte_inversion = None
        self.cpu_name = None
        self.cpu_vendor = None
        self.cpu_arch = None
        self.cpu_uarch = None
        self.kernel = None
        self.system = None
        self.valid = True
        self.pku = None
        self.check_all()

    def check_all(self):
        public_methods = [getattr(self, method) for method in dir(self) if callable(getattr(self, method)) if
                          not (method.startswith('_') or method == "check_all")]
        for method in public_methods:
            res_print(method.__doc__, str(method()), BOLD)
        print()

    def check_02_smt(self):
        """SMT state"""
        threads_count = int([ln for ln in self.lscpu.split("\n") if "Thread(s) per core:" in ln][0].split(" ")[-1])
        if threads_count > 1:
            self.smt = "enabled"
        else:
            if self.virt.vm:
                self.smt = "unknown"
            else:
                self.smt = "disabled or not supported"
        return self.smt

    def check_ept(self):
        """EPT Support"""
        self.ept = "supported" if "ept" in self.flags else "not supported"
        return self.ept

    def check_guest_pte_inversion(self):
        """Guest Page Table Entry Inversion"""
        l1tf_state: str
        try:
            with open('/sys/devices/system/cpu/vulnerabilities/l1tf') as f:
                l1tf_state = f.read().strip()
            self.guest_pte_inversion = "active" if "PTE Inversion" in l1tf_state else "inactive"
        except FileNotFoundError:
            print(f"{WARNING}/sys/devices/system/cpu/vulnerabilities/ not found!{ENDC}")
            self.guest_pte_inversion = "unknown"
        # res_print("L1TF", l1tf_state, val_style=BOLD)
        # assert self.guest_pte_inversion == "active"
        return self.guest_pte_inversion

    def check_mpx(self):
        """MPX support"""
        self.mpx = "supported" if "mpx" in self.flags else "not supported"
        return self.mpx

    def check_10_l1d_flush_hw(self):
        """L1D Flush hardware support"""
        self.l1d_hw = "supported" if "flush_l1d" in self.flags else "not supported"
        return self.l1d_hw

    def check_11_l1d_flush(self):
        """L1D Flush"""
        # no way of knowing ... :(
        self.l1d_flush = "unknown"
        # assume enabled if hardware support exists
        if self.l1d_hw == "supported":
            self.l1d_flush = "likely active"
        elif self.l1d_hw == "not supported":
            self.l1d_flush = "assume inactive"
        # todo: remove me
        if self.l1d_flush == "unknown":
            raise Exception(f"unknown l1d_flush: hw support reported as {self.l1d_hw}")
        return self.l1d_flush

    def check_md_clear(self):
        """MD_CLEAR hardware support"""
        self.md_clear = "supported" if "md_clear" in self.flags else "not supported"
        return self.md_clear

    def check_01_virt(self):
        """Virtualisation Technology"""
        try:
            vm = run(["systemd-detect-virt", "--vm"],
                     capture_output=True).stdout.decode('utf-8').strip()
            container = run(["systemd-detect-virt", "--container"],
                            capture_output=True).stdout.decode('utf-8').strip()
            current = run(["systemd-detect-virt"],
                          capture_output=True).stdout.decode('utf-8').strip()
            self.virt = VirtInfo(current, vm, container)
        except FileNotFoundError:
            print(f"{WARNING}`systemd-detect-virt` not found. Please install.{ENDC}")
            print(f"{WARNING}Using fallback methods...{ENDC}")
            virt: str = "none"
            vendor: str = "none"
            vendor_ln = [ln for ln in self.lscpu.split("\n") if "Hypervisor vendor:" in ln]
            if vendor_ln:
                vendor = vendor_ln[0].split("  ")[-1]
            virt_ln = [ln for ln in self.lscpu.split("\n") if "Virtualization type:" in ln]
            if virt_ln:
                virt = virt_ln[0].split("  ")[-1]
            if vendor != "none":
                assert (virt == "full")
            docker = os.path.isfile("/run/.containerenv")
            wsl = os.path.isdir("/run/WSL")
            assert (not (docker and wsl))
            container = "docker" if docker else "wsl" if wsl else "none"
            self.virt = VirtInfo(container if container != "none" else vendor, vendor, container)
        if not self.virt.current:
            print(f"{FAIL}No Virtualisation Detected.{ENDC}")
            self.valid = False
        return self.virt

    def check_ucode(self):
        """Microcode"""
        # not possible to detect in full virt
        # not possible to detect in docker unless --priviledged
        self.ucode = "unknown"
        # we can guess using md_clear hardware support
        if self.md_clear == "supported":
            self.ucode = "likely sufficiently recent"
        if self.md_clear == "not supported":
            self.ucode = "likely out-of-date"
        return self.ucode

    def check_000_vendor(self):
        """CPU Vendor"""
        if "GenuineIntel" in self.lscpu:
            self.cpu_vendor = "Intel"
        if "AuthenticAMD" in self.lscpu:
            self.cpu_vendor = "AMD"
        if "ARM" in self.lscpu:
            self.cpu_vendor = "ARM"
        if self.cpu_vendor != "Intel":
            print(f"{FAIL}Only Intel CPUs are supported for now!{ENDC}")
            self.valid = False
        return self.cpu_vendor

    def check_001_cpu_name(self):
        """CPU Name"""
        self.cpu_name = next(i for i in self.lscpu.split("\n") if "Model name:" in i).split(":")[1].strip()
        return self.cpu_name

    def check_002_cpu_arch(self):
        """Architecture"""
        self.cpu_arch = next(i for i in self.lscpu.split("\n") if "Architecture:" in i).split(":")[1].strip()
        assert self.cpu_arch in ["x86_64", "aarch64"]
        # if self.cpu_arch == "aarch64":
        #     print(f"{FAIL}ARM64 is not supported yet!{ENDC}")
        #     self.valid = False
        return self.cpu_arch

    # PMU name is not available on all CPUs, further it is plain wrong sometimes...
    # def check_003_cpu_uarch(self):
    #     """Microarchitecture"""
    #     # intel
    #     try:
    #         with open('/sys/devices/cpu/caps/pmu_name') as f:
    #             self.cpu_uarch = f.read().strip()
    #     except FileNotFoundError:
    #         pass
    #     return self.cpu_uarch

    def check_system(self):
        """System"""
        self.system = platform.system()
        return self.system

    def check_kernel(self):
        """Kernel"""
        self.kernel = platform.release()
        return self.kernel

    def check_pku(self):
        """Memory Protection Keys"""
        if "ospke" in self.flags:
            self.pku = "full support"
        elif "pku" in self.flags:
            self.pku = "hardware support"
        else:
            self.pku = "not supported"
        return self.pku

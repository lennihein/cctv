#!/usr/bin/env python3
from printingtools import res_print, FAIL, ENDC, FAINT, color_test, WARNING
from infofetch import Info
from attacks import Attacks
from sys import argv
import time


def eval_attacks(i: Info):
    atks = [getattr(Attacks, method) for method in dir(Attacks) if callable(getattr(Attacks, method)) if
            not (method.startswith('_'))]
    for a in atks:
        ret_val = a(i)
        if not ret_val:
            print("Error: {} returned None".format(a.__name__))
            raise AssertionError
        res, res_style, comment = ret_val if len(ret_val) == 3 else (ret_val[0], ret_val[1], "")
        res_print(a.__doc__, res, res_style, comment=comment)


if __name__ == '__main__':

    debug = False

    # DEBUG MODE
    if len(argv) >= 2 and "--debug" in argv[1:]:
        debug = True
        print(f"{FAINT}Debug mode enabled{ENDC}")
        color_test()
        time.sleep(0.1)

    # initialise info
    info = Info()

    # IGNORE CONTAINER MODE
    if len(argv) >= 2 and "--ignore-container" in argv[1:]:
        print(f"{WARNING}Ignoring containerisation{ENDC}")
        info.virt.container = None
        info.virt.current = info.virt.vm

    # if assumptions are not met, omit attacks
    if not info.valid:
        if not debug:
            print(f"Ommitting attacks due to {FAIL}failed{ENDC} checks.")
            exit(1)
        else:
            print(f"{FAINT}Warning: Some checks failed, but debug mode is enabled. Output might be incorrect.{ENDC}")

    # output attack evaluation
    eval_attacks(info)

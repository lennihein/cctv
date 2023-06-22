import sys
import time
import os
import re

HEADER = '\033[95m'
BLUE = '\033[94m'
CYAN = '\033[96m'
GREEN = '\033[92m'
RED = '\33[31m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
FAINT = '\33[2m'
YELLOW = '\33[33m'
MAGENTA = '\33[35m'


def get_terminal_width():
    '''
    you know what this does
    '''
    global columns, rows
    try:
        return os.get_terminal_size(0)[0]
    except OSError:
        return 120


def inline_print(text: str, length: int = get_terminal_width(), duration: float = 0, wait: float = 0, fill: chr = None):
    if fill:
        text = text + fill * (length - raw_len(text))
    clear_line(length=length)
    if not duration:
        sys.stdout.write(text[0:length])
        sys.stdout.flush()
    else:
        for c in text:
            sys.stdout.write(c)
            sys.stdout.flush()
            time.sleep(duration / len(text))
    time.sleep(wait)


def clear_line(length: int = get_terminal_width()):
    for _ in range(length):
        sys.stdout.write('\033[D \033[D')


def res_print(key: str, val: str, val_style: str, key_style: str = BOLD, comment: str = "", two_lines: bool = False, newline: bool = False):
    length = get_terminal_width()
    cs = f" ({comment})" if comment else ""
    if two_lines and cs:
        print(f"{key_style + key + ENDC}:{' ' * (length - raw_len(key) - raw_len(val) - 1 )}{val_style + val + ENDC}")
        print(f"{' ' * (length - raw_len(cs))}{cs}")
    else:
        print(f"{key_style + key + ENDC}:{' ' * (length - raw_len(key) - raw_len(val) - 1 - raw_len(cs))}{val_style + val + ENDC}{cs}")
    if newline:
        print()


def clear():
    print("\033[H\033[J", end="")


def remove_escape_sequences(s: str):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', s)


def raw_len(s: str):
    base_string: str = remove_escape_sequences(s)
    return len(base_string)


def color_test():
    test_s = f"{YELLOW}YELLOW {GREEN}GREEN {CYAN}CYAN {MAGENTA}MAGENTA {RED}RED {BLUE}BLUE"
    print(f"╭{'─' * (raw_len(test_s) + 2)}╮\n│ {test_s}{ENDC} │\n╰{'─' * (raw_len(test_s) + 2)}╯")

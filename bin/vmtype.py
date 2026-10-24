#!/usr/bin/env python3
"""
vmtype.py DOMAIN TEXT|--pw NAME|--key KEY... -- type into a VM's console with
virsh send-key (US layout), for a kept VM that cannot be reached over WinRM.
TEXT is typed as is, with \\n as Enter; --pw types the kept Administrator
password from run-NAME.pw (never printed); --key sends one chord, e.g.
--key KEY_LEFTCTRL KEY_LEFTALT KEY_DELETE.
"""
import os
import subprocess
import sys
import time

PLAIN = {' ': 'KEY_SPACE', '-': 'KEY_MINUS', '=': 'KEY_EQUAL', ';': 'KEY_SEMICOLON',
         "'": 'KEY_APOSTROPHE', ',': 'KEY_COMMA', '.': 'KEY_DOT', '/': 'KEY_SLASH',
         '\\': 'KEY_BACKSLASH', '[': 'KEY_LEFTBRACE', ']': 'KEY_RIGHTBRACE', '`': 'KEY_GRAVE',
         '\n': 'KEY_ENTER', '\t': 'KEY_TAB'}
SHIFT = {'!': '1', '@': '2', '#': '3', '$': '4', '%': '5', '^': '6', '&': '7', '*': '8',
         '(': '9', ')': '0', '_': '-', '+': '=', ':': ';', '"': "'", '<': ',', '>': '.',
         '?': '/', '|': '\\', '{': '[', '}': ']', '~': '`'}


def keys(c):
    if c.isalpha():
        k = ['KEY_' + c.upper()]
        return ['KEY_LEFTSHIFT'] + k if c.isupper() else k
    if c.isdigit():
        return ['KEY_' + c]
    if c in PLAIN:
        return [PLAIN[c]]
    if c in SHIFT:
        return ['KEY_LEFTSHIFT'] + keys(SHIFT[c])
    sys.exit(f'no key for {c!r}')


def send(dom, chord):
    subprocess.run(['virsh', '-c', 'qemu:///session', 'send-key', dom, '--codeset', 'linux',
                    '--holdtime', '40', *chord], check=True, stdout=subprocess.DEVNULL)
    time.sleep(0.05)


def main():
    dom, args = sys.argv[1], sys.argv[2:]
    if args[0] == '--key':
        send(dom, args[1:])
        return
    if args[0] == '--pw':
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        here = os.path.join(os.environ.get('BL_STATE') or os.path.join(repo, 'work'), 'win')
        text = open(os.path.join(here, f'run-{args[1]}.pw')).read().strip()
    else:
        text = ' '.join(args).replace('\\n', '\n')
    for c in text:
        send(dom, keys(c))


main()

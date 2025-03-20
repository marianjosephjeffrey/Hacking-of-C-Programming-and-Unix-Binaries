# 🏴‍☠️ Hacking of C Programming and Unix Binaries  

## 📌 Overview  
As part of a **binary exploitation and reverse engineering course at the University of Maryland**, I performed **buffer overflow attacks, privilege escalation, and return-oriented programming (ROP) techniques** on **C binaries** across **32-bit and 64-bit Unix environments**. The project focused on **understanding memory corruption vulnerabilities and exploiting them to capture system flags**.  

---

## 🛠 Key Contributions  

- 🔍 **Performed buffer overflow attacks** to capture **flags encrypted in memory** of compiled C binaries.  
- 🏴‍☠️ **Executed binary exploitation across 32-bit and 64-bit Unix binaries**, bypassing **memory protections**.  
- ⚡ **Gained escalated privileges** through **stack manipulation techniques**, including **Return-Oriented Programming (ROP)**.  
- 🔄 **Analyzed and reversed C binaries** using **Ghidra**, identifying **vulnerable functions and memory structures**.  
- 🛡 **Implemented mitigations for common binary vulnerabilities**, such as **stack canaries and address space layout randomization (ASLR)**.  
- 🎯 **Successfully exploited binaries in pwndbg**, achieving **final privilege escalation and flag capture**.  

---

## 🛠 Tools & Technologies Used  

| Category                     | Tools & Technologies |
|------------------------------|----------------------|
| 🔍 Reverse Engineering       | Ghidra, Radare2 |
| 🏴‍☠️ Binary Exploitation    | pwntools, pwndbg |
| 📜 Memory Exploitation       | Buffer Overflows, ROP, Stack Smashing |
| 🔑 Privilege Escalation      | SUID Binaries, Stack Manipulations |
| 🛡 Security Bypasses         | ASLR, NX, Stack Canaries |
| 🎯 Capture The Flag (CTF)    | Custom Binary Exploits |

---

## ⚙️ Sample Exploits & Commands  

### 🔍 Finding a Buffer Overflow in a C Binary  
```c
#include <stdio.h>
#include <string.h>

void vulnerable() {
    char buffer[64];
    gets(buffer);
}

int main() {
    vulnerable();
    return 0;
}
```
🏴‍☠️ Exploiting Buffer Overflow to Overwrite Return Address
```python
from pwn import *

binary = ELF("./vulnerable_binary")
rop = ROP(binary)

payload = b"A" * 72  # Overflow buffer size
payload += rop.ret  # Return-oriented programming (ROP) technique

p = process(binary.path)
p.sendline(payload)
p.interactive()
```
🔑 Disabling ASLR for Easier Exploitation
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
📜 Debugging Binary with pwndbg
```bash
gdb -q ./vulnerable_binary
(gdb) start
(gdb) disassemble main
(gdb) run $(python3 exploit.py)
```

⸻

📋 Final Report & Evaluation

The project concluded with a comprehensive security analysis, detailing:

✅ Findings from binary exploitation, including buffer overflows, privilege escalation, and memory corruption vulnerabilities.
✅ Reverse engineering insights, analyzing function flow and security mechanisms in compiled C binaries.
✅ Exploit development techniques, showcasing ROP chains, stack smashing, and security bypasses.
✅ Mitigation strategies, suggesting stack canaries, ASLR enforcement, and secure coding practices.
✅ Final presentation & demonstration, proving successful binary exploitation leading to system flag capture.

⸻

🎤 Presentation & Impact

I compiled the findings and exploitation techniques into a technical penetration testing report, outlining real-world memory corruption vulnerabilities and their mitigations.

⸻

💬 Have Questions?

Feel free to reach out or open an issue! 🚀🔐

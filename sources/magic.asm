PUBLIC EnableVMXOperation
PUBLIC GetCS
PUBLIC GetDS
PUBLIC GetES
PUBLIC GetFS
PUBLIC GetGDTR
PUBLIC GetGS
PUBLIC GetIDTR
PUBLIC GetLDTR
PUBLIC GetRflags
PUBLIC GetSS

.code

EnableVMXOperation PROC PUBLIC
    xor rax, rax
    mov rax, cr4
    or rax, 2000h ; cr4.vmxe = 1
    mov cr4, rax 
    ret
EnableVMXOperation  ENDP

GetCS PROC PUBLIC
    mov rax, cs
    ret
GetCS ENDP

GetDS PROC PUBLIC
    mov rax, ds
    ret
GetDS ENDP

GetES PROC PUBLIC
    mov rax, es
    ret
GetES ENDP

GetFS PROC PUBLIC
    mov rax, fs
    ret
GetFS ENDP

GetGDTR PROC PUBLIC
    SGDT [RCX]
    RET
GetGDTR ENDP 

GetGS PROC PUBLIC
    mov rax, gs
    ret
GetGS ENDP

GetIDTR PROC PUBLIC
    SIDT [RCX]
    RET
GetIDTR ENDP

GetLDTR PROC PUBLIC
    SLDT RAX
    RET
GetLDTR  ENDP

GetRflags PROC PUBLIC
    pushfq
    pop rax
    ret
GetRflags ENDP

GetSS PROC PUBLIC
    mov rax, ss
    ret
GetSS  ENDP

GetTR PROC PUBLIC
    STR RAX
    RET
GetTR  ENDP

END
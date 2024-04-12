PUBLIC EnableVMXOperation

.code

EnableVMXOperation PROC PUBLIC
    xor rax, rax
    mov rax, cr4
    or rax, 2000h ; cr4.vmxe = 1
    mov cr4, rax 
    ret
EnableVMXOperation  ENDP

END
global libtem_trampoline_handle_signal
	extern libtem_handle_signal
	extern printHello

section .text
	
libtem_trampoline_handle_signal:
libtem_trampoline_wrpkru:
	mov ebx, edx
	xor ecx, ecx
	xor edx, edx
	mov eax, 0x55555550
	db 0x0f,0x01,0xef
	cmp eax, 0x55555550
	jne libtem_trampoline_wrpkru
	mov eax, edx
	jmp libtem_handle_signal wrt ..plt

section .note.GNU-stack noalloc noexec nowrite progbits
.code

GetBase proc

		xor rax, rax
		mov rax, gs:[60h]
		mov rax, [rax + 18h]
		mov rsi, [rax + 20h]
		mov rsi, qword ptr [rsi + 8h]
		lodsq
		xchg rax, rsi
		lodsq
		mov rax, [rax + 20h]
		ret

GetBase endp

end
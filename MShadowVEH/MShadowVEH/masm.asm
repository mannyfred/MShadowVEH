.code

; Random ghetto masm I threw together
GetBase proc

		xor r9, r9
		mov rax, gs:[60h]
		mov r9, rax
		mov rax, [rax + 18h]
		mov rsi, [rax + 20h]
		mov rsi, qword ptr [rsi + 8h]
		lodsq
		xchg rax, rsi
		lodsq
		mov rax, [rax + 20h]

		xor rsi, rsi
		mov esi, dword ptr [r9 + 120h]
		cmp esi, 22000
		jb Win10
		cmp esi, 19045
		ja Win10
		mov qword ptr [rcx], 0
		ret

	Win10:
		mov qword ptr [rcx], 1
		ret

GetBase endp

end
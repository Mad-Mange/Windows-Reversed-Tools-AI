.text
.globl _native_bridge
_native_bridge:
    push ebp
    push ebx
    push esi
    push edi
    push dword ptr [_BRIDGE_STACK]
    push dword ptr fs:[4]
    push dword ptr fs:[8]
    push dword ptr fs:[0]
    mov dword ptr [_BRIDGE_STACK], esp
    mov eax, dword ptr [esp+36]
    mov edx, dword ptr [eax+44]
    mov dword ptr fs:[4], edx
    mov edx, dword ptr [eax+48]
    mov dword ptr fs:[8], edx
    mov dword ptr fs:[0], -1
    mov edx, dword ptr [esp+40]
    mov dword ptr [eax+40], edx
    push dword ptr [eax+32]
    popfd
    mov ecx, dword ptr [eax+4]
    mov edx, dword ptr [eax+8]
    mov ebx, dword ptr [eax+12]
    mov ebp, dword ptr [eax+20]
    mov esi, dword ptr [eax+24]
    mov edi, dword ptr [eax+28]
    mov esp, dword ptr [eax+16]
    push dword ptr [eax+40]
    lea esp, [esp+4]
    mov eax, dword ptr [eax]
    call dword ptr [esp-4]
    pushfd
    pushad
    cld
    mov esi, esp
    mov ebp, dword ptr [_BRIDGE_STACK]
    mov eax, dword ptr [ebp+36]
    mov ecx, dword ptr [esi+28]
    mov dword ptr [eax], ecx
    mov ecx, dword ptr [esi+24]
    mov dword ptr [eax+4], ecx
    mov ecx, dword ptr [esi+20]
    mov dword ptr [eax+8], ecx
    mov ecx, dword ptr [esi+16]
    mov dword ptr [eax+12], ecx
    lea ecx, [esi+36]
    mov dword ptr [eax+16], ecx
    mov ecx, dword ptr [esi+8]
    mov dword ptr [eax+20], ecx
    mov ecx, dword ptr [esi+4]
    mov dword ptr [eax+24], ecx
    mov ecx, dword ptr [esi]
    mov dword ptr [eax+28], ecx
    mov ecx, dword ptr [esi+32]
    mov dword ptr [eax+32], ecx
    mov esp, ebp
    pop dword ptr fs:[0]
    pop dword ptr fs:[8]
    pop dword ptr fs:[4]
    pop dword ptr [_BRIDGE_STACK]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.globl _callback_entry
_callback_entry:
    pushfd
    pushad
    cld
    push esp
    call _callback_dispatch
    add esp, 4
    mov dword ptr [esp+28], eax
    mov dword ptr [esp+24], edx
    popad
    popfd
    pop edx
    pop edx
    lea esp, [esp+ecx]
    jmp edx

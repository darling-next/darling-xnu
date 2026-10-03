.text
.globl __darling_bsd_syscall
.private_extern __darling_bsd_syscall

#if defined(__x86_64__)

__darling_bsd_syscall:
Lentry_hook:
	# EXPERIMENT (temporary): a semantics-preserving jump inside the 13-byte hook area -- same 13 bytes, same
	# behaviour, different bytes. If the guest still starts, the area is statically occupiable and the earlier
	# breakage was my trampoline's ABI; if it does not, something else claims these bytes and only a RUNTIME hook
	# installation (xtrace's model) is available.
	# MEASURED (2026-09-27): this MUST be a `call`, not a `jmp`. xtrace installs the same hook with
	# `setup_hook(..., jump=false)` -- i.e. a call -- and the trampoline ends in `ret`, so a `jmp` here returns
	# straight to the syscall's caller and SKIPS THE WHOLE DISPATCHER: every Darwin syscall in the guest then
	# returns garbage and every run is NO-RUN, hatch or not. That was the third measured way this instrument broke
	# the guest; the contract's first claim is what catches it.
	call	__darling_bsd_syscall_trace_entry
	.space 8, 0x90
	movq    ___bsd_syscall_table@GOTPCREL(%rip), %r10
	movq	(%r10,%rax,8), %r10
	test	%r10, %r10
	jz		.no_sys
	# Re-push possible 7th and 8th arg
	movq	24(%rsp), %r11
	pushq	%r11
	movq	24(%rsp), %r11
	pushq	%r11
	call	*%r10
	addq	$16, %rsp
.std_ret:
Lexit_hook:
	.space 13, 0x90
	ret
.no_sys:
	movq	%rax, %rdi
	call	___unknown_syscall
	jmp		.std_ret

# step A: trampoline copied from xtrace's proven pattern, calling an EMPTY C body.
__darling_bsd_syscall_trace_entry:
	pushq	%rbp
	movq	%rsp, %rbp
	andq	$-16, %rsp
	subq	$8, %rsp
	movq	40(%rbp), %r11
	pushq	%r11
	movq	32(%rbp), %r11
	pushq	%r11
	pushq	%r9
	pushq	%r8
	pushq	%rcx
	pushq	%rdx
	pushq	%rsi
	pushq	%rdi
	pushq	%rax
	movq	%rax, %rdi
	leaq	8(%rsp), %rsi
	call	___darling_bsd_syscall_trace_c
	popq	%rax
	popq	%rdi
	popq	%rsi
	popq	%rdx
	popq	%rcx
	popq	%r8
	popq	%r9
	leave
	ret



.section        __DATA,__data
.globl __darling_bsd_syscall_entry
.globl __darling_bsd_syscall_exit
__darling_bsd_syscall_entry:
	.quad Lentry_hook
__darling_bsd_syscall_exit:
	.quad Lexit_hook

#elif defined(__i386__)

#define copy_arg(off) \
	movl	8+off(%esp), %ecx ;\
	movl	%ecx, -56+off(%esp)

__darling_bsd_syscall:
Lentry_hook:
	.space 7, 0x90
	calll	1f
1:
	popl	%ecx
2:
	movl	L___bsd_syscall_table$non_lazy_ptr-1b(%ecx), %ecx
	andl	$0xffff, %eax // Because there is some extra stuff in upper bytes we don't need
	movl	(%ecx,%eax,4), %eax
	test	%eax, %eax
	jz		.no_sys
	// Copy arguments
	copy_arg(0)
	copy_arg(4)
	copy_arg(8)
	copy_arg(12)
	copy_arg(16)
	copy_arg(20)
	copy_arg(24)
	copy_arg(28)
	copy_arg(32)
	copy_arg(36)
	copy_arg(40)
	copy_arg(44)
	copy_arg(48)
	copy_arg(52)
	subl	$56, %esp
	call	*%eax
	addl	$56, %esp
.std_ret:
Lexit_hook:
	.space 7, 0x90
	ret
.no_sys:
	pushl	%ecx
	call	___unknown_syscall
	addl	$4, %esp
	jmp .std_ret

	.section        __IMPORT,__pointers,non_lazy_symbol_pointers
L___bsd_syscall_table$non_lazy_ptr:
	.indirect_symbol        ___bsd_syscall_table
	.long   0

.section        __DATA,__data
.globl __darling_bsd_syscall_entry
.globl __darling_bsd_syscall_exit
__darling_bsd_syscall_entry:
	.long Lentry_hook
__darling_bsd_syscall_exit:
	.long Lexit_hook

.subsections_via_symbols

#else
#	error Missing assembly
#endif


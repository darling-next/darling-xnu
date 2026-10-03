#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>

#include <elfcalls.h>
#include <dlfcn.h>

#include <darling/emulation/common/simple.h>

extern struct elf_calls* _elfcalls;

struct elf_calls* elfcalls(void)
{
	if (!_elfcalls)
	{
		//void* module = dlopen("/usr/lib/darling/libelfloader.dylib", RTLD_NOW);
		// if (!module)
		//	__simple_printf("Load error: %s\n", dlerror());

		// struct elf_calls** ptr = (struct elf_calls**) dlsym(module, "_elfcalls");
		// __simple_printf("_elfcalls is at %p\n", ptr);
		// __simple_printf("*_elfcalls = %p\n", *ptr);
		//_elfcalls = *(struct elf_calls**) dlsym(module, "_elfcalls");
		__simple_printf("elfcalls not found?\n");
		__simple_abort();
	}
	return _elfcalls;
}

void native_exit(int ec)
{
	// EXIT DECISION PROBE. MEASURED NEED: the workload dies with status 139 (jkilled by SIGSEGV) while NO host signal
	// is delivered (gdb: six of twelve runs 'exited with code 0213' and never stopped on a signal), no loader probe
	// fires, no guest crash handler fires and the sigexc default-action path never runs -- so the decision that turns a
	// death into an exit STATUS is the thing to name, and this function is exactly the boundary between the guest's
	// decision and the host's exit. The return address names the caller that decided it.
	{
		static int emitted = 0;
		if (emitted < 24) {
			++emitted;
			__simple_printf("[native-exit status=%d ra=%p]\n", ec, __builtin_return_address(0));
		}
	}
	if (_elfcalls)
		_elfcalls->exit(ec);
}

long native_sysconf(int name)
{
	if (_elfcalls)
		return _elfcalls->sysconf(name);
	return -1;
}

void __mldr_postfork_child(void)
{
	return elfcalls()->postfork_child();
}

void __mldr_prefork_prepare(void)
{
	return elfcalls()->prefork_prepare();
}

void __mldr_postfork_parent(void)
{
	return elfcalls()->postfork_parent();
}

void* __darling_thread_create(unsigned long stack_size, unsigned long pthobj_size,
			void* entry_point, uintptr_t arg3,
			uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
			darling_thread_create_callbacks_t callbacks, void* dthread)
{
	// CREATOR IDENTITY (unconditional): every guest thread creation funnels through this trampoline, so a thread
	// that dies in a trap stub must be traceable to a creator or to none. Prints the process (which equals the
	// host pid in Darling) and the entry point, so a faulting thread can be matched to its creation site.
	extern int getpid(void);
	__simple_printf("[tc-tramp pid=%d entry=%p dthread=%p]\n", (int)getpid(), entry_point, dthread);
	return elfcalls()->darling_thread_create(stack_size, pthobj_size, entry_point,
			arg3, arg4, arg5, arg6, callbacks, dthread);
}

int __darling_thread_terminate(void* stackaddr,
			unsigned long freesize, unsigned long pthobj_size)
{
	return elfcalls()->darling_thread_terminate(stackaddr, freesize, pthobj_size);
}

void* __darling_thread_get_stack(void)
{
	return elfcalls()->darling_thread_get_stack();
}

void* native_dlopen(const char* path)
{
	return elfcalls()->dlopen(path);
}

char* native_dlerror(void)
{
	return elfcalls()->dlerror();
}

void* native_dlsym(void* module, const char* name)
{
	return elfcalls()->dlsym(module, name);
}

int native_dlclose(void* module)
{
	return elfcalls()->dlclose(module);
}

const void* __dserver_socket_address(void) {
	return elfcalls()->dserver_socket_address();
};

// perf#30 FD-COURIER: the process-scoped descriptor channel's address, owned by the loader.
const void* __dserver_fd_courier_address(void) {
	return elfcalls()->dserver_fd_courier_address();
};

// perf#30 FD-COURIER: the process's incarnation identity, from the loader, so every image agrees.
uint64_t __dserver_process_generation(void) {
	return elfcalls()->dserver_process_generation();
};

// perf#30 FD-COURIER: the process's single courier connection, owned by the loader.
int __dserver_fd_courier_socket(void) {
	return elfcalls()->dserver_fd_courier_socket();
};

// perf#30 FD-COURIER: ask the LOADER to drop the connection; an image cannot do it by closing a number.
void __dserver_fd_courier_reset(void) {
	elfcalls()->dserver_fd_courier_reset();
};

// perf#30 PROCESS-CONTROL PLANE: the process's management page (created once by the loader).
void* __dserver_process_control_page(void) {
	return elfcalls()->dserver_process_control_page();
};

int __dserver_process_socket(void) {
	return elfcalls()->dserver_process_socket();
};



void __dserver_close_socket(int socket) {
	return elfcalls()->dserver_close_socket(socket);
};

int __dserver_adopt_ring_fd(int fd) {
	return elfcalls()->dserver_adopt_ring_fd(fd);
}

// perf#28 (ONE doorbell): see elfcalls_wrapper.h. The null guard mirrors the release wrapper: an
// older loader that does not carry the appended pointer must degrade to "no doorbell", never to a
// call through a garbage slot.
int __dserver_ring_doorbell(int fd) {
	if (elfcalls()->dserver_ring_doorbell) {
		return elfcalls()->dserver_ring_doorbell(fd);
	}
	return -1;
}

void* __dserver_ring_lane_registry(void) {
	if (elfcalls()->dserver_ring_lane_registry) {
		return elfcalls()->dserver_ring_lane_registry();
	}
	return (void*)0;
}

int __dserver_ring_lane_slots(void) {
	if (elfcalls()->dserver_ring_lane_slots) {
		return elfcalls()->dserver_ring_lane_slots();
	}
	return 0;
}

void __dserver_release_ring_fd(int fd) {
	if (elfcalls()->dserver_release_ring_fd) {
		elfcalls()->dserver_release_ring_fd(fd);
	}
}

bool __dserver_fd_is_internal(int fd) {
	return elfcalls()->dserver_fd_is_internal(fd);
}

int __dserver_get_process_lifetime_pipe() {
	return elfcalls()->dserver_get_process_lifetime_pipe();
}

int __dserver_process_lifetime_pipe_refresh(void) {
	return elfcalls()->dserver_process_lifetime_pipe_refresh();
};

void __dserver_close_process_lifetime_pipe(int fd) {
	return elfcalls()->dserver_close_process_lifetime_pipe(fd);
};

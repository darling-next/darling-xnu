#ifndef DARLING_GUEST_NAMESPACE_AUTHORITY_H
#define DARLING_GUEST_NAMESPACE_AUTHORITY_H

#include <stdint.h>

enum darling_guest_namespace_bootstrap_state {
	DARLING_GUEST_NAMESPACE_OFF = 0,
	DARLING_GUEST_NAMESPACE_REQUIRED = 1,
	DARLING_GUEST_NAMESPACE_INVALID = -1,
};

struct darling_guest_namespace_mutation {
	int gate_fd;
	int prefix_fd;
	uint64_t generation;
};

enum darling_guest_namespace_layer {
	DARLING_GUEST_NAMESPACE_UPPER = 1,
};

struct darling_guest_namespace_resolved {
	int parent_fd;
	char leaf[256];
	enum darling_guest_namespace_layer layer;
	uint64_t parent_device;
	uint64_t parent_inode;
};

int darling_guest_namespace_initialize(void);
int darling_guest_namespace_state(void);
int darling_guest_namespace_protected_fd(unsigned int index);
int darling_guest_namespace_begin(struct darling_guest_namespace_mutation* mutation);
void darling_guest_namespace_end(struct darling_guest_namespace_mutation* mutation);
int darling_guest_namespace_resolve(struct darling_guest_namespace_mutation* mutation,
	const char* absolute_guest_path, struct darling_guest_namespace_resolved* resolved);
void darling_guest_namespace_resolved_close(struct darling_guest_namespace_resolved* resolved);
long darling_guest_namespace_mkdir(const char* path, unsigned int mode);
long darling_guest_namespace_create(const char* path, int linux_flags, unsigned int mode);
long darling_guest_namespace_unlink(const char* path, int linux_flags);
long darling_guest_namespace_rename(const char* source, const char* destination);

#ifdef TEST
typedef long (*darling_guest_namespace_test_transaction_fn)(uint32_t operation,
	const char* source, const char* destination, int flags, uint32_t mode);
void darling_guest_namespace_test_set_capability(unsigned int index, int fd);
void darling_guest_namespace_test_set_transaction(
	darling_guest_namespace_test_transaction_fn transaction);
void darling_guest_namespace_test_reset(void);
#endif

#endif

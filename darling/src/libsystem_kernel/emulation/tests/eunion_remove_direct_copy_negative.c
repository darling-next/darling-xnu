#define TEST 1

// This compile-negative fixture deliberately includes the internal
// implementation so it exercises the exact owning capability representation.
// A successful compile would mean direct C assignment became possible.
#include "../src/linux_premigration/eunion_remove_runtime.c"

int main(void)
{
	eunion_remove_capability left = {{0}};
	eunion_remove_capability right = {{0}};
	left = right;
	return 0;
}

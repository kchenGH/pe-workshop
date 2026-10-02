#include "win32_min.h"

/* Inspect these declarations in PE Workshop's Variables view. */
volatile int global_counter = 7;
static const char banner[] = "PE Workshop DWARF demo: result 34.\r\n";
typedef int Counter;
enum Mode { ModeIdle, ModeReady };
struct Pair { int left; int right; };

static int compute_score(int seed) {
    Counter alias = seed + 1;
    int local_total = alias + global_counter;
    double scale = 1.5;
    struct Pair pair = { seed, local_total };
    int values[3] = { 1, 2, 3 };
    int *pointer = &local_total;
    enum Mode local_mode = ModeReady;
    {
        int block_value = values[0] + pair.left;
        *pointer += block_value;
    }
    return local_total + (int)scale + pair.right + values[2] + local_mode;
}

void sample_main(void) {
    int result = compute_score(4);
    DWORD written = 0;
    BOOL ok = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), banner,
        (DWORD)(sizeof(banner) - 1), &written, (void *)0);
    ExitProcess(ok && written == sizeof(banner) - 1 && result == 34 ? 0 : 1);
}

#include "win32_min.h"

#ifdef ORIGINAL_SAMPLE
static const char message[] = "PE Workshop training marker: ORIGINAL.\r\n";
#else
static const char message[] = "PE Workshop console demo: native Win32.\r\n";
#endif

/* A real absolute pointer makes the linker emit a base relocation. Volatile
   keeps the read in the final executable instead of folding it into an RVA. */
static const char *volatile relocated_message = message;

void sample_main(void) {
    DWORD written = 0;
    const DWORD length = (DWORD)(sizeof(message) - 1);
    BOOL ok = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), relocated_message,
        length, &written, (void *)0);
    ExitProcess(ok && written == length ? 0 : 1);
}

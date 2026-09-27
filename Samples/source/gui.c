#include "win32_min.h"

static const char message[] = "PE Workshop GUI demo: native Win32.\n\n"
    "This harmless sample only displays this dialog.";
static const char *volatile relocated_message = message;

static int is_self_test(const char *command_line) {
    /* Accept the literal switch as a separate command-line token. */
    const char option[] = "--self-test";
    unsigned int i;
    const char *start = command_line;
    while (*command_line) {
        if (command_line == start || command_line[-1] == ' ') {
            for (i = 0; option[i] && command_line[i] == option[i]; ++i) {}
            if (!option[i] && (!command_line[i] || command_line[i] == ' '))
                return 1;
        }
        ++command_line;
    }
    return 0;
}

void sample_main(void) {
    if (is_self_test(GetCommandLineA())) ExitProcess(0);
    /* MB_OK | MB_ICONINFORMATION. Self-test above never opens a window. */
    int result = MessageBoxA((void *)0, relocated_message,
        "PE Workshop - GUI sample", 0x40);
    ExitProcess(result ? 0 : 1);
}

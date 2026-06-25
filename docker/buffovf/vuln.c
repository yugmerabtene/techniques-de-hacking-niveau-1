#include <stdio.h>
#include <string.h>
#include <unistd.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Input received: %s\n", buffer);
}

int main() {
    char input[256];
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("Usage: echo <input> | %s\n", "vuln");
        return 1;
    }
    input[strcspn(input, "\n")] = 0;
    vulnerable_function(input);
    return 0;
}

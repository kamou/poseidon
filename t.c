#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    int test;
    if (argc != 2) {
        printf("Please provide one argument\n");
        exit(1);
    }

    puts(argv[1]);
    return 0;
}

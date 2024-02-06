#include <stdio.h>
#include <stdlib.h>

int main(){
    char buf[64];
    puts("Bonjour");
    read(0, buf, 64);
    printf("%s\n", buf);
}
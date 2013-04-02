CC = gcc
exe:
	gcc -o $@ -O3 -fno-strict-aliasing -flto -fwhole-program -march=native -mtune=native -Wall *.c

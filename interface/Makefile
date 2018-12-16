default: all

main.o: main.c
	gcc -c main.c -o main.o

all: main.o
	gcc main.o -o main

clean:
	-rm -f *.o *.out main

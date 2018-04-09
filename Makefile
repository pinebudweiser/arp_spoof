all : main

main : main.o
	gcc -o main main.c -lpcap -pthread
clean :
	rm -rf *.o
	rm -rf main

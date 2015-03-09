CFLAGS=-I.

make:
	gcc -std=c99 -o myfsck readwrite.c
run:
	./rw disk 0
tar:
	tar cvf myfsck.tar *.h *.c makefile *.txt
dk:
	cp disk1 disk
f:
	./myfsck -i disk -f 0

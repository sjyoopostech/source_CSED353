all : result_exe

result_exe : code.o
	gcc -o result.exe code.o -lpcap

code.o : code.c
	gcc -c -o code.o code.c -lpcap

clean :
	rm *.o result.exe

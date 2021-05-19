All: main

main: virusDetector.o
gcc -g -m32 -Wall -o virusDetector virusDetector.o

task3.o: task3.c
gcc -g -Wall -m32 -c -o virusDetector.o virusDetector.c

.PHONY: clean
clean:
rm -f *.o virusDetector

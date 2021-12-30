SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}
%:	%.c
	gcc $@.c -o $@ -lpcap
clean:
	rm ${EXE}


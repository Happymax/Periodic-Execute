PROGNAME := periodexec # Program name to output
SRC := src.c # Source files
OFLAG := -O3
CFLAGS := # Add additional compiler flags here
#MATHFLAG := -lm # Mathflag must stay at the end for lxhalle to compile
DEBUGFLAG := -O0 -fsanitize=address -Wall -Wextra
CC := $(if $(findstring Linux,$(shell uname -s)),gcc,cc)

all: periodexec

re: clean all

install:	periodexec
	sudo cp ./$(PROGNAME) /usr/local/bin/$(PROGNAME)

uninstall:
	sudo rm /usr/local/bin/$(PROGNAME)

sanitize: $(SRC) # Needs libasan and libubsan packages installed
	$(CC) $(CFLAGS) $(DEBUGFLAG) $(PLATFORMFLAG) -o $(PROGNAME) $^

periodexec: $(SRC)
	$(CC) $(CFLAGS) $(OFLAG) $(PLATFORMFLAG) -o $(PROGNAME) $^

clean:
	rm -f $(PROGNAME)

.PHONY: clean re sanitize install uninstall

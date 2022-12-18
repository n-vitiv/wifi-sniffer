CC = g++
CFLAGS = -g -Wall -Wpedantic -Werror -I.

SRCDIR = src

PROJ_NAME=wifi-sniffer

SOURCES := $(wildcard $(SRCDIR)/*.cpp)
OBJECTS := $(SOURCES:$(SRCDIR)/%.cpp=%.o)

all :$(PROJ_NAME) $(CLEAN_OBJECTS)

$(PROJ_NAME) : $(OBJECTS)
	$(CC) $(CFLAGS) $(LFLAGS) $^ -o $@ -I/usr/include/libnl3 -lnl-genl-3 -lnl-3
	rm -rf *.o 

$(OBJECTS) : %.o : $(SRCDIR)/%.cpp
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean :
	rm -rf $(PROJ_NAME)

BOT          = isabot
BOT_SOURCES  = isabot.cpp

DEFINES        =
CFLAGS         = -g
LIBRARIES      = -lpcap -lssl -lcrypto
CC              = g++
BOT_OBJECTS  = $(BOT_SOURCES:.cpp=.o)
INCLUDES        = #-I.
LIBDIRS         =
LDFLAGS         = $(LIBDIRS) $(LIBRARIES)


.SUFFIXES: .cpp .o

.cpp.o:
		$(CC) $(CFLAGS) -c $<

all:		$(BOT) 

rebuild:	clean all

$(BOT):	$(BOT_OBJECTS)
		$(CC) -g $(BOT_OBJECTS) $(LDFLAGS) -o $@

clean:
	rm -fr core* *~ $(BOT_OBJECTS) $(BOT) .make.state .sb
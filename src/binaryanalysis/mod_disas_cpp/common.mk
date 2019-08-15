CC=g++

createoutput:
	$(MKDIR_P) $(PATH_TO_BIN)

%.o: %.cpp
	$(CC) -c $*.cpp $(CFLAGS) $(INCLUDE_PATH) -o $@

%-pic.o: %.c %.h
	$(CC) -c $*.c -fPIC $(CFLAGS) $(INCLUDE_PATH) -o $*-pic.o

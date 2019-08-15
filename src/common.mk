#CC=gcc

createoutput: 
	$(MKDIR_P) $(PATH_TO_BIN)

createresult:
	$(MKDIR_P) $(PATH_TO_RES)

%.o: %.c %.h
	$(CC) -c $*.c $(CFLAGS) $(INCLUDE_PATH) -o $*.o

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_PATH) -c $*.c  -o $*.o

%-pic.o: %.c %.h
	$(CC) -c $*.c -fPIC $(CFLAGS) $(INCLUDE_PATH) -o $*-pic.o

%-pic.o: %.c
	$(CC) -c $*.c -fPIC $(CFLAGS) $(INCLUDE_PATH) -o $*-pic.o

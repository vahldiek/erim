all:
	CC=../levee/bin/clang make test
	CC=../levee/bin/clang CFLAGS=-fcpi make test
	CC=../levee/bin/clang CFLAGS=-fcps make test
	CC=../leveeERIM/bin/clang make test
	CC=../leveeERIM/bin/clang CFLAGS=-fcpi make test
	CC=../leveeERIM/bin/clang CFLAGS=-fcps make test
	CC=../leveeERIMSIM/bin/clang make test
	CC=../leveeERIMSIM/bin/clang CFLAGS=-fcpi make test
	CC=../leveeERIMSIM/bin/clang CFLAGS=-fcps make test

test:
	$(CC) $(CFLAGS) -flto test.c -o test
	./test
	rm test

#include <stdio.h>
#include <stdlib.h>
#include <timer.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <math.h>
#include <erim.h>

#define MEMSCAN 1
#define SINGLE 1
#define NUM_ITERATIONS 1000
#define PAGESIZE 4096

int main(int argc, const char ** argv) {

  int it = 0, args = 0, index = 0;
  struct stat sb;

  if(argc < 2) {
    printf("provide at least one file name\n");
    return EXIT_FAILURE;
  }

  printf("#binary;iter;size;#wrpkru;total;avg;avg single;stddev\n");

  for(args = 1; args < argc; args++) {
#if (defined MMAP_NEW) || (defined MPROT) || (defined US_SCAN)
    void * addr;
#endif
    unsigned long totalwrpkru = 0;
    unsigned long time = 0, sum = 0, sqr = 0;

    int fd = open(argv[args], O_RDONLY);
    if(fd == -1) {
      printf("file not found\n");
      exit(EXIT_FAILURE);
    }
    if (fstat (fd, &sb) == -1) {
      perror ("fstat");
        return 1;
    }
    
    char * addr = (char*) mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if(addr == MAP_FAILED) {
      printf("error in mmap\n");
      exit(EXIT_FAILURE);
    }
    
    SWS_INIT_TIMER(compl);
    SWS_START_TIMER(compl);
    
    for(it = 0; it < NUM_ITERATIONS; it++) {
      SWS_INIT_TIMER(t);
      SWS_START_TIMER(t);
      
      erim_memScanRegion(ERIM_UNTRUSTED_PKRU, addr, sb.st_size, NULL, 0, "");
      
      SWS_END_TIMER(t);
      time=SWS_SPEND_TIME(t);

      sum += time;
      sqr += time*time;
    }
    SWS_END_TIMER(compl);
    
    munmap(addr, sb.st_size);

    close(fd);
    
    double avg = sum/NUM_ITERATIONS;
    double stddev = sqrt (
			  (sqr - 2 * avg * sum + NUM_ITERATIONS * avg * avg)
	  / NUM_ITERATIONS);
    double count = NUM_ITERATIONS;
    
    printf("%s;%d;%d;%ld;%llu;%f;%f\n", argv[args], NUM_ITERATIONS, (int)sb.st_size,totalwrpkru,
	   sum, avg, stddev);
  }
    
  return EXIT_SUCCESS;
}

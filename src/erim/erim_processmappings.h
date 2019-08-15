/*
 * erim_processmappings.h
 *
 */

#ifndef EAPI_PROCESSMAPPINGS_H_
#define EAPI_PROCESSMAPPINGS_H_

#ifdef __cplusplus
extern "C"
{
#endif

/* Process Maps Parser defines
 */

typedef struct erim_procmaps_s{
  char* addr_start; //< start address of the region
  char* addr_end; //< end address of the region
  unsigned long length; //<  length of the region by bytes
  
  char perm[5];//< permissions rwxp
  short is_r;//< is readible
  short is_w;//< is writable
  short is_x;//< is executable
  short is_p;//< is private
  
  long offset;//< offset
  
  char dev[12];//< the device that backs the region, format major:minor
  int inode;//< inode of the file that backs the area
  char pathname[600];//< the path of the file that backs the area
  
  //The next region in the list
  struct erim_procmaps_s * next;//<handler of the chinaed list
} erim_procmaps;
    
erim_procmaps * erim_pmapsParse(int pid);
erim_procmaps * erim_pmapsNext(erim_procmaps * cur);
void erim_pmapsFree(erim_procmaps * maps_list);

#ifdef __cplusplus
}
#endif
  
#endif /* EAPI_PROCESSMAPPINGS_H_ */

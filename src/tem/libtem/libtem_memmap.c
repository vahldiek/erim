#include <stdlib.h>
#include <sys/mman.h>
#include <bsd/string.h>

#include <libtem.h>
#include <libtem_memmap.h>

#include <erim.h>

#define LTEM_MEMMAP_MEM LTEM_SEC->ltem_memmap

typedef struct ltem_memmap_s {

  ltem_memmap_entry_t entry;
  
  struct ltem_memmap_s * next;
  struct ltem_memmap_s * prev;
  
} ltem_memmap_t;

static ltem_memmap_t * memmap_createEntry(unsigned long long start,
					  unsigned long long end,
					  char prot,
					  char * name) {
  
  ltem_memmap_t * e = erim_malloc(sizeof(ltem_memmap_t));

  e->entry.start = start;
  e->entry.end = end;
  e->entry.prot = prot;
  if(name)
    strlcpy(e->entry.name, name, 256);
  else
    e->entry.name[0] = '\0';
  
  e->next = e->prev = NULL;

  return e;
}

static int memmap_insertAfter(ltem_memmap_t ** head,
			      ltem_memmap_t * index,
			      ltem_memmap_t * new) {

  if(*head == NULL) {
    *head = new;
    new->next = new;
    new->prev = new;
    return 0;
  }

  /*
   * index -> next
   *    ^       |
   *    |--------
   *
   * To
   *
   * index -> new -> (index->next)
   *   ^       |           |
   *   | -------           |
   *           ^------------
   */
  
  index->next->prev = new; 
  new->next = index->next; 
  index->next = new; 
  new->prev = index;

  return 0;
}


static int memmap_insertBefore(ltem_memmap_t ** head,
			       ltem_memmap_t * index,
			       ltem_memmap_t * new) {

  if(*head == NULL) {
    *head = new;
    new->next = new;
    new->prev = new;
    return 0;
  }

  /*
   *  prev ->  index
   *    ^       |
   *    |--------
   *
   * To
   *
   * (index->prev) -> new -> (index)
   *   ^               |           |
   *   | ---------------           |
   *                   ^------------
   */

  index->prev->next = new; 
  new->prev = index->prev; 
  index->prev = new; 
  new->next = index;

  if(index == *head)
    *head = new;

  return 0;
}

static int memmap_insertEnd(ltem_memmap_t ** head,
			    ltem_memmap_t * new) {

  if(*head == NULL) {
    return memmap_insertAfter(head, *head, new);
  }

  return memmap_insertAfter(head, (*head)->prev, new);
}

static ltem_memmap_t * memmap_find(ltem_memmap_t * head,
					 unsigned long long addr) {

  ltem_memmap_t * cur = head;

  for (cur = head ; cur ; cur = cur->next) {
    if(cur->entry.start <= addr && cur->entry.end >= addr) {
      // found correct entry
      return cur;
    }    
  }

  return NULL;
}

static ltem_memmap_t * memmap_findBefore(ltem_memmap_t * head,
					 unsigned long long addr) {

  ltem_memmap_t * cur = head;

  for (cur = head ;
       cur && cur->entry.start < addr;
       cur = cur->next);

  return cur->prev;
}

static ltem_memmap_t * memmap_findAfter(ltem_memmap_t * head,
					 unsigned long long addr) {
  ltem_memmap_t * cur = memmap_findBefore(head, addr);
  
  return cur ? cur->next : NULL;
}

static int memmap_instertSorted(ltem_memmap_t **head,
					    ltem_memmap_t * new) {

  if(*head == NULL) {
    // empty list
    return memmap_insertBefore(head, *head, new);
  }

  // list with at least one element
  if((*head)->entry.start > new->entry.end) {
    // insert before first element
    return memmap_insertBefore(head, *head, new);
  } else {
    ltem_memmap_t * before = memmap_findBefore(*head, new->entry.start);
    return memmap_insertAfter(head, before, new);
  }
}

int libtem_memmap_init(erim_procmaps * pmaps) {

  LTEM_DBM("memmap inited");
  
  // insert existing memmap into current layout (initial map is
  // inserted immediately, as it is checked by erim_memScan
  // and all executable memory is still executable).
  // This is required to be able to check the boundaries of executable
  // pages later when new pages are added.
  for(; pmaps ; pmaps = erim_pmapsNext(pmaps)) {
    //    ltem_memmap_t * e = NULL;// memmap_createEntry(start, end, prot, pathname);
    //memmap_insertEnd((ltem_memmap_t**)&LTEM_MEMMAP_MEM, e);
  }
  
  return 0;
}

int libtem_memmap_fini() {
  int ret = 0;
  erim_switch_to_trusted;
  ltem_memmap_t * lmem = LTEM_SEC->ltem_memmap;

  LTEM_DBM("memmap finied");

  erim_switch_to_untrusted;
  
  return ret;
}

int libtem_memmap_add(void * addr, size_t length, int prot, int flags, int fd, off_t offset) {
  int ret = 0;

  ltem_memmap_t * lmem = LTEM_SEC->ltem_memmap;
  
  LTEM_DBM("memmap add addr %p size %ld prot %x flags %x fd %d offset %ld", addr,
	   length, prot, flags, fd, offset);
  
  return ret;
}

int libtem_memmap_update(void * addr, size_t len, int prot, int pkey) {
  int ret = 0;

  ltem_memmap_t * lmem = LTEM_SEC->ltem_memmap;

  //LTEM_DBM("memmap update addr %p size %ld prot %x pkey %d", addr, len, prot,
  //  pkey);

  return ret;
}

int libtem_memmap_find(void * addr, ltem_memmap_entry_t * mentry) {

  mentry->prot = PROT_READ | PROT_EXEC;
  
  return 1;
}

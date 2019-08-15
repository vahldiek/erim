/*
 * erim_ds.h
 *
 *  Created on: May 23, 2017
 *      Author: vahldiek
 */

#ifndef ERIM_DS_H_
#define ERIM_DS_H_

typedef struct erim_result {
  struct erim_result * next;
  
  Elf64_Phdr * phdr;
  unsigned int segment;
  unsigned long long seg_location;
  const char * code;
  unsigned long long code_length;
  unsigned long long location;
  unsigned long long vm_location;
  
  unsigned int section;
  Elf64_Shdr * shdr;
  unsigned long long sec_location;
  
  char raw_bytes[30];
  unsigned int raw_bytes_len;
  char insn_text[2][255];
  unsigned int insn_len[2];
  unsigned long int insn_addr[2];
  
  struct {
    char executable : 1;
    char disas_failed : 1;
    char seq_spans_insn : 1;
    char block_in_cfg : 1;
  } flags;  

  unsigned int num_funcs;
  unsigned int num_points;
  unsigned int offset_to_point;
  unsigned int point_type;
  
} erim_result_t;

typedef struct erim_input {
  
  char * filename;
  uint8_t * seq;
  uint8_t seq_len;
  unsigned int disas_id;
  enum {
    ERIM_MODE_FULL=0,
    ERIM_MODE_ANALYSIS,
    ERIM_MODE_LOCATION
  } mode;
  
  enum {
    ERIM_FLAG_SEQ=1,
    ERIM_FLAG_XRSTOR=2,
    ERIM_FLAG_BOTH=3
  } flag;

  elfObject eo;

} erim_input_t;

#endif /* ERIM_DS_H_ */

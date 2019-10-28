/*
 * erim.c
 *
 *  Created on: Jan 20, 2017
 *      Author: vahldiek
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>
#include <libgen.h>
#include <elf_object.h>
#include <common.h>
#include <capstone/capstone.h>
#include <ba_erim.h>
#include <mod_disas.h>

#define SEQ_LEN 	3
#define SEQ			0xEF010F
#define SEQ_ARR	 0x0f, 0x01, 0xef

#define prt(...) printf(__VA_ARGS__)
#define offprt(tabs, ...) {int offprti = 0; for(offprti = 0; offprti < tabs; offprti++) printf("\t"); prt(__VA_ARGS__);}

static void prt_xml(erim_t * e);


/*
 * check for match in seq
 */
inline int match_seq(const char * ptr) {
	const char seq[SEQ_LEN] = { SEQ_ARR };
	uint8_t i = 0;
	for (i = 0; i < SEQ_LEN && ptr[i] == seq[i]; i++)
		;

	return (i == SEQ_LEN);
}

inline int match_seq_it(const char * ptr, uint8_t curPos) {
	const char seq[SEQ_LEN] = { SEQ_ARR };
	uint8_t i = curPos;

	if (curPos >= SEQ_LEN)
		return 1;

	for (i = curPos; i < SEQ_LEN && ptr[i] == seq[i]; i++)
		;

	return (i == SEQ_LEN);
}

inline int match_seq_input(const uint8_t * ptr, erim_input_t * in) {
	uint8_t i = 0;
	for (i = 0; i < in->seq_len && ptr[i] == in->seq[i]; i++)
		;

	return (i == in->seq_len);
}

int ba_search_seq(elfObject* eo, int it, Elf64_Phdr * phdr, void * e) {
	erim_t * et = (erim_t *) e;

	SWS_ARG_CHK(!eo || !phdr || !e);

	//	printf("iterating over it %d phdr %p\n", it, phdr->p_vaddr);

	if (phdr->p_type != PT_LOAD) {
		return EO_SUCCESS;
	}
// program hdr has no size
	if (!phdr->p_filesz) {
		return EO_SUCCESS;
	}

	if (phdr->p_flags & PF_X) {

		et->inspected_segments++;
		et->executable_memory += phdr->p_memsz;

		//printf("found executable %d\n", it);
		char * addr = eo->loadedSegmentPtr[it];
		int i = 0;

		for (i = 0; i < phdr->p_memsz; ++i) {
			if (match_seq_input((uint8_t *) (addr + i), &et->in)) {
				erim_result_t * newr = malloc(sizeof(erim_result_t));
				memset(newr, 0, sizeof(erim_result_t));
				newr->next = et->res;
				newr->phdr = phdr;
				newr->segment = it;
				newr->code = addr;
				newr->code_length = phdr->p_memsz;
				newr->location = i + phdr->p_offset;
				newr->segment = (unsigned int) it;
				newr->vm_location = i + phdr->p_vaddr;
				newr->seg_location = i + phdr->p_offset;

				et->res = newr;

				if(et->in.mode != ERIM_MODE_LOCATION)
					et->md->check(et->md, &et->in, newr);
			}
		}

	}

	return EO_SUCCESS;
}

int match_xrstor(uint8_t * addr) {

	if (addr[0] == 0x0F 
	    && addr[1] == 0xAE
	    && (addr[2] & 0xC0) != 0xC0
	    && (addr[2] & 0x38) == 0x28)
		return 1;

	return 0;
}

int ba_search_xrstor(elfObject * eo, int it, Elf64_Phdr * phdr, void * e) {
	erim_t * et = (erim_t *) e;

	SWS_ARG_CHK(!eo || !phdr || !e);

	//	printf("iterating over it %d phdr %p\n", it, phdr->p_vaddr);

	if (phdr->p_type != PT_LOAD) {
		return EO_SUCCESS;
	}

	if(phdr->p_flags & PF_X) {

	  //  	  printf("found executable load\n");
	  
	  char * addr = eo->loadedSegmentPtr[it];
	  int i = 0;
	  
	  for (i = 0; i < phdr->p_memsz; ++i) {

	    if (match_xrstor((uint8_t *) (addr + i))) {
	      
	      //    printf("found xrstor at %p %d\n", (addr+i), i);
	      
	      erim_result_t * newr = malloc(sizeof(erim_result_t));
	      memset(newr, 0, sizeof(erim_result_t));
	      newr->next = et->res;
	      newr->phdr = phdr;
	      newr->segment = it;
	      newr->code = addr;
	      newr->code_length = phdr->p_memsz;
	      newr->location =  i + phdr->p_offset;
	      newr->vm_location = i + phdr->p_vaddr;
	      newr->seg_location = i + phdr->p_offset;
	      
	      et->res = newr;
	      
	      if(et->in.mode != ERIM_MODE_LOCATION) {
		et->md->check(et->md, &et->in, newr);
	      }
	    }
	  }
	}
	
	return EO_SUCCESS;
}

void prt_seq(uint8_t * seq, uint8_t seq_len) {
	uint8_t it = 0;
	prt("Looking for sequence: 0x");
	for (it = 0; it < seq_len; ++it) {
		prt("%02x", seq[it]);
	}
	prt("\n");
}

int read_hex_from_str(const char * str, uint8_t str_len, uint8_t * hex) {
	uint8_t it = 0;
	int ret = 0;
	for (it = 0; it * 2 < str_len; it++) {
		ret |= sscanf(str + (it * 2), "%2hhx", &hex[it]) < 1;
	}

	return ret;
}

int erim_init(int argc, char ** argv, erim_t * e) {

	char * seq_str = NULL;
	uint16_t seq_str_len = 0;
	int ret = 0;
	char * filename = argv[1];
	char * hex = argv[2];
	char * disas = argv[3];
	char * mode = argv[4];
	char * flag = argv[5];

	SWS_CHK(argc < 4, "Usage: %s <elf 64 object> <seq of bytes in hex> "
		"<disassembly/rewrite module (0,1<-preferable)> [<analysis/full> <seq/xrstor>]\n",
		argv[0]);



	e->in.filename = filename;
	/*
	 * load elf object into intermediate structure
	 */
	if ((e->eo_load_return = eo_load(e->in.filename, &e->in.eo)) != EO_SUCCESS) {
	  //		SWS_CHK(ret == EO_NO_PHDR, "%s NO PHDR found\n", filename);

		//		fprintf(stderr, "%s couldn't load elf object ret=%d\n", filename, ret);

		//prt_xml(e);
		
		return e->eo_load_return;
	}

	seq_str = hex;
	seq_str_len = strnlen(seq_str, 255);
	SWS_CHK((seq_str_len % 2 == 1),
			"argument two is no hex string 2 numbers per byte\n");
	e->in.seq_len = seq_str_len / 2;
	e->in.seq = malloc(sizeof(uint8_t) * e->in.seq_len);

	SWS_CHK(read_hex_from_str(seq_str, seq_str_len, e->in.seq) != SWS_SUCCESS,
			"Failed to read hex sequence\n");
	//	prt_seq(e->in.seq, e->in.seq_len);

	e->in.disas_id = atoi(disas);
	SWS_CHK(!(e->md = disas_init(e->in.disas_id)), "Disas init failed");

	if (argc > 4 && strncmp("analysis", mode, 8) == 0)
		e->in.mode = ERIM_MODE_ANALYSIS;
	else if(argc > 4 && strncmp("location", mode, 8) == 0)
		e->in.mode = ERIM_MODE_LOCATION;
	else
		e->in.mode = ERIM_MODE_FULL;

	if(argc > 5 && strncmp("seq", flag, 3) == 0) {
	  e->in.flag = ERIM_FLAG_SEQ;
	} else if(argc > 5 && strncmp("xrstor", flag, 6) == 0) {
	  e->in.flag = ERIM_FLAG_XRSTOR;
	} else {
	  e->in.flag = ERIM_FLAG_BOTH;
	}

	return SWS_SUCCESS;
}

void prt_binary(char *src, unsigned int length, char *print_buf,
		unsigned int pb_len) {
	int it = 0;
	memset(print_buf, '\0', pb_len);
	for (it = 0; it < length; it++) {
		sprintf(print_buf + (2 * it), "%02X", *(unsigned char *) (src + it));
	}
	return;
}

void prt_erim_result(erim_result_t * res) {
	char binary[255];
	prt_binary(res->raw_bytes, res->raw_bytes_len, binary, 255);

	printf(
			"location=%llx vmlocation=%llx executable=%d "
					"disas_failed=%d seq_spans_insn=%d insn=%s%s binary=%s (%d) num_funcs=%d "
					"num_points=%d point_type=%d offset=%d\n", res->location,
			res->vm_location, res->flags.executable & 0x1,
			res->flags.disas_failed & 0x1, res->flags.seq_spans_insn & 0x1,
			res->insn_text[0], res->insn_text[1], binary, res->raw_bytes_len,
			res->num_funcs, res->num_points, res->point_type,
			res->offset_to_point);
}

void prt_human(erim_t * e) {
	int count = 0;
	erim_result_t * r = e->res;
	for (; r; count++, r = r->next)
		;

	printf("%s numseg=%d executablebytes=%lld numwrpkru=%d\n", e->in.filename,
			e->inspected_segments, e->executable_memory, count);

	for (r = e->res; r; r = r->next) {
		prt_erim_result(r);
	}
}

static void prt_xml_erim_result(erim_t * e, erim_result_t * res, int tabs) {
	char binary[255];
	prt_binary(res->raw_bytes, res->raw_bytes_len, binary, 255);

	offprt(tabs, "<AnalyzedWRPKRU>\n");
	tabs++;
	offprt(tabs, "<offset>%lld</offset>\n", res->location);
	offprt(tabs, "<segment>%d</segment>\n", res->segment);
	offprt(tabs, "<segoffset>%llu</segoffset>\n", res->seg_location);
	offprt(tabs, "<section>%d</section>\n", res->section);
	if(e->in.mode != ERIM_MODE_LOCATION)
		offprt(tabs, "<sectionName>%s</sectionName>\n",
			e->in.eo.sectionHdrStrings + res->shdr->sh_name);
	offprt(tabs, "<sectionOffset>%lld</sectionOffset>\n", res->sec_location);
	offprt(tabs, "<vmOffset>%lld</vmOffset>\n", res->vm_location);
	offprt(tabs, "<executableSection>%s</executableSection>\n",
			(res->flags.executable) ? "true" : "false");
	offprt(tabs, "<disasFailed>%s</disasFailed>\n",
			(res->flags.disas_failed) ? "true" : "false");
	offprt(tabs, "<binary>%s</binary>\n", binary);
	offprt(tabs, "<insnDisasFailed>%s</insnDisasFailed>\n",
			(res->flags.disas_failed) ? "true" : "false");
	offprt(tabs, "<fullSeqOperand>%s</fullSeqOperand>\n",
			(res->flags.seq_spans_insn) ? "true" : "false");
	offprt(tabs, "<blockInCfg>%s</blockInCfg>\n",
			(res->flags.block_in_cfg) ? "true" : "false");
	offprt(tabs, "<offsetInOperand>%d</offsetInOperand>\n", 0);
	offprt(tabs, "<operandIt>%d</operandIt>\n", 0);
	offprt(tabs, "<operandType>%d</operandType>\n", 0);
	offprt(tabs, "<nextOpType>%d</nextOpType>\n", 0);
	offprt(tabs, "<abo reference=\"../../..\" />\n");
	// insns
	offprt(tabs, "<insns class=\"linked-list\">\n");
	tabs++;
	if (res->flags.seq_spans_insn) {
		offprt(tabs, "<string>%s</string>\n", res->insn_text[0]);
		offprt(tabs, "<string>%s</string>\n", res->insn_text[1]);
	} else {
		offprt(tabs, "<string>%s</string>\n", res->insn_text[0]);
	}
	tabs--;
	offprt(tabs, "</insns>\n");

	tabs--;
	offprt(tabs, "</AnalyzedWRPKRU>\n");
}

static void prt_xml(erim_t * e) {
	int count = 0;
	erim_result_t * r = e->res;
	for (; r; count++, r = r->next)
		;

	offprt(0, "<AnalyzedBinaryObject>\n");
	offprt(1, "<filename>%s</filename>\n", e->in.filename);
	offprt(1, "<loadFailed>%s</loadFailed>\n", (e->eo_load_return != SWS_SUCCESS) ? "True" : "False");
	offprt(1, "<noPhdr>%s</noPhdr>\n", (e->eo_load_return & EO_NO_PHDR != 0) ? "True" : "False");
	offprt(1, "<failureCode>%d</failureCode>\n", e->eo_load_return);
	offprt(1, "<numSegments>%d</numSegments>\n", e->inspected_segments);
	offprt(1, "<executableBytes>%lld</executableBytes>\n", e->executable_memory);
	offprt(1, "<numWRPKRU>%d</numWRPKRU>\n", count);

	offprt(1, "<wrpkruSet class=\"linked-list\">\n");
	for (r = e->res; r; r = r->next) {
		prt_xml_erim_result(e, r, 2);
	}
	offprt(1, "</wrpkruSet>\n");

	offprt(0, "</AnalyzedBinaryObject>\n");

}

void my_wrpkru_test(int in) {
	register int test asm ("eax") = in;
	if((test & 0x0000000C))
     test = 5;
     //		printf("test");
	else
		return;
}


int main(int argc, char **argv) {

	erim_t e;

	memset(&e, 0, sizeof(e));

	if(erim_init(argc, argv, &e) == SWS_SUCCESS) {
	  if(e.in.flag & ERIM_FLAG_SEQ)
	    eo_iterate_segments(&e.in.eo, ba_search_seq, &e);
	  if(e.in.flag & ERIM_FLAG_XRSTOR)
	    eo_iterate_segments(&e.in.eo, ba_search_xrstor, &e);
	}

	prt_xml(&e);

	// rewrite executable if WRPKRU found
	if (e.res && e.in.mode == ERIM_MODE_FULL) {
		if(e.md->rewrite(e.md, &e.in, e.res) == SWS_SUCCESS) {
			e.md->writeFile(e.md, e.in.filename);
			erim_t newe;
			erim_result_t *res = NULL;
			char out[256];
			char mode[20] = "location";
			sprintf(out, "%s.erim", e.in.filename);
			memset(&newe, 0, sizeof(newe));
			argv[1] = out;
			argv[4] = mode;
			erim_init(argc, argv, &newe);
			eo_iterate_segments(&newe.in.eo, ba_search_xrstor, &newe);

			if(newe.res) {
			  FILE * f = fopen(out, "rb+");
			  if(!f)
			    return EXIT_FAILURE;
			  
			  for(res = newe.res; res; res = res->next) {
			    char nop = 0x90;
			    fseek(f, res->location, SEEK_SET);
			    fwrite(&nop, 1, 1, f);
			  }

			  fclose(f);
			}
		}
	}

	return EXIT_SUCCESS;
}

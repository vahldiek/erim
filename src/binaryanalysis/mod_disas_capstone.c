/*
 * mod_disas_captstone.c
 *
 *  Created on: Jan 23, 2017
 *      Author: vahldiek
 */

#include <elf_object.h>
#include <capstone/capstone.h>
#include <common.h>
#include <ba_erim.h>
#include <mod_disas.h>

typedef struct mod_disas_cap {
	csh detail;
	csh simple;
} mod_disas_cap_t;

static Elf64_Shdr * findSection(elfObject * eo, long long loc,
		erim_result_t * res) {
	Elf64_Shdr * curSection = &eo->sectionHdr[0];
	unsigned int sectionIt = 0;
	// need to skip to section that includes the sequence, don't just start at the beginning of segment
	for (sectionIt = 0;
			sectionIt < eo->numSections
					&& curSection->sh_offset + curSection->sh_size < loc;
			curSection++, sectionIt++)
		;

	if (sectionIt < eo->numSections) {
		// found the correct sectoin
		res->section = sectionIt;
		res->shdr = curSection;
		return curSection;
	}

	return NULL ;
}

static int check_not_exec_section(mod_disas_cap_t * c, erim_t * e, erim_result_t * res,
		Elf64_Shdr * curSection) {
	cs_insn * insn = NULL;
	size_t len = res->code_length;
	uint64_t addrit = 0L;

	const uint8_t * tmpcode = (uint8_t *)(res->code + res->location);

	// try disassembly after insn
	insn = (cs_insn *)cs_malloc(c->simple);
	if (cs_disasm_iter(c->simple, &tmpcode, &len, &addrit, insn)) {
		res->flags.disas_failed = 0;
	} else {
		res->flags.disas_failed = 1;
	}
	cs_free(insn, 1);

	// prt binary
//	const uint8_t * start = (loc > 10) ? code + loc - 10 : code + loc;
//	unsigned int length = ((loc > 10) ? 10 : 0) + SEQ_LEN
//			+ ((curSection->sh_size > 10 + SEQ_LEN + 10) ? 10 : 0);

	return SWS_SUCCESS;
}

int mod_disas_cap_check(mod_disas_t * md, erim_t * e, erim_result_t * res) {
	mod_disas_cap_t * c = NULL;
	cs_insn * insn = NULL;
	uint64_t addrit = 0L;
	const uint8_t * code = NULL;
	Elf64_Shdr * curSection = NULL;
	const uint8_t * lastInstr = NULL;
//	unsigned int offset = 0;
	uint64_t leftlen = 0;

	SWS_ARG_CHK(!md || !e || !res);

	c = (mod_disas_cap_t *) md->mod_specific;
	code = (uint8_t*)res->code;
	leftlen = res->code_length;

	curSection = findSection(&e->in.eo, res->location, res);
	SWS_CHK(curSection == NULL, "Couldn't find corresponding section");

	if (!(curSection->sh_flags & SHF_EXECINSTR)) {
		res->flags.executable = 0;
		return check_not_exec_section(c, e, res, curSection);
	} else {
		res->flags.executable = 1;
	}

	// offset code ptr to section start
	code += curSection->sh_offset;
	res->sec_location = res->location - (long long) curSection->sh_offset;
	leftlen -= curSection->sh_offset;

	insn = (cs_insn*) cs_malloc(c->simple);
	// disassemble to the instruction where sequence starts
	for (;
			cs_disasm_iter(c->simple, &code, &leftlen, &addrit, insn)
					&& (long long) (insn->address + insn->size) < res->location;
			lastInstr = code)
		;

	leftlen += insn->size;
	addrit = 0;
//	offset = lastInstr - (uint8_t *) res->code;
	code = lastInstr;
	cs_free(insn, 1);

	if (lastInstr == NULL ) {
		lastInstr = code;
	}

	insn = (cs_insn*) cs_malloc(c->detail);
	if (!cs_disasm_iter(c->detail, &lastInstr, &leftlen, &addrit, insn)) {
		res->flags.disas_failed = 1;
		return SWS_SUCCESS;
	} else {
		res->flags.disas_failed = 0;
	}

	return SWS_SUCCESS;
}

int mod_disas_cap_fini(mod_disas_t * md) {
	mod_disas_cap_t * c = NULL;

	SWS_ARG_CHK(!md);

	c = (mod_disas_cap_t *) md->mod_specific;

	SWS_CHK(cs_close(&c->detail) != CS_ERR_OK, "Fini capstone failed");
	SWS_CHK(cs_close(&c->simple) != CS_ERR_OK, "Fini capstone failed");

	return SWS_SUCCESS;
}

int mod_disas_cap_init(mod_disas_t * md) {
	mod_disas_cap_t * c = NULL;

	SWS_ARG_CHK(!md);

	md->check = (mod_disas_check) mod_disas_cap_check;
	md->rewrite = NULL;
	md->fini = (mod_disas_fini) mod_disas_cap_fini;

	md->mod_specific = malloc(sizeof(mod_disas_cap_t));
	c = (mod_disas_cap_t *) md->mod_specific;

	cs_open(CS_ARCH_X86, CS_MODE_64, (csh*) &c->detail);
	cs_option(c->detail, CS_OPT_DETAIL, CS_OPT_ON);
	cs_open(CS_ARCH_X86, CS_MODE_64, &c->simple);

	return SWS_SUCCESS;
}


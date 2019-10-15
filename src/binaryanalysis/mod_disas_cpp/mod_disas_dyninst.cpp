/*
 * mod_disas_dyntstone.c
 *
 *  Created on: Jan 23, 2017
 *      Author: vahldiek
 */

#include <cstdlib>
#include <elf_object.h>
#include <common.h>
#include <ba_erim.h>
#include <mod_disas.h>
#include <iostream>
#include <stdio.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_function.h"
#include "BPatch_point.h"
#include "BPatch_basicBlock.h"
#include "BPatch_object.h"
#include "BPatch_flowGraph.h"
#include "BPatch_instruction.h"
#include "CodeObject.h"
#include "InstructionDecoder.h"
#include "CFG.h"
#include "PatchMgr.h"
#include "Point.h"
#include "PatchCFG.h"
#include "PatchCommon.h"
#include "PatchModifier.h"
#include "PatchObject.h"
#include "mapped_object.h"
#include "DynObject.h"
#include "DynAddrSpace.h"
#include "addressSpace.h"
#include "block.h"
#include "function.h"
#include "Register.h"
#include "Visitor.h"
#include "Instruction.h"
#include "Operand.h"
#include "snippetGen.h"
#include "Expression.h"
#include <iomanip>

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

typedef struct mod_disas_dyn {
	BPatch_binaryEdit *appBin;
	CodeRegion * region;
} mod_disas_dyn_t;

#ifdef __cplusplus
extern "C" {
#endif

int mod_disas_dyn_check(mod_disas_t * md, erim_input_t * in,
		erim_result_t * res);
int mod_disas_dyn_rewrite(mod_disas_t * md, erim_input_t * in,
		erim_result_t * res);
int mod_disas_dyn_writeFile(mod_disas_t * md, char * filename);
int mod_disas_dyn_fini(mod_disas_t * md);

BPatch bpatch;

void errorcallback(BPatchErrorLevel level, int num, const char * const *params) {
	char line[256];

	const char *msg = bpatch.getEnglishErrorString(num);
	bpatch.formatErrorString(line, sizeof(line), msg, params);

	if (num != 100) { //ccw 9 mar 2004
		printf("Error #%d (level %d): %s\n", num, level, line);
	}

	// We consider some errors fatal.
	if (num == 101) {
		exit(-1);
	}
}

int mod_disas_dyn_init(mod_disas_t * md) {
	mod_disas_dyn_t * c = NULL;

	SWS_ARG_CHK(!md);

	md->check = (mod_disas_check) mod_disas_dyn_check;
	md->rewrite = (mod_disas_rewrite) mod_disas_dyn_rewrite;
	md->writeFile = (mod_disas_writeFile) mod_disas_dyn_writeFile;
	md->fini = (mod_disas_fini) mod_disas_dyn_fini;

	md->mod_specific = malloc(sizeof(mod_disas_dyn_t));
	c = (mod_disas_dyn_t *) md->mod_specific;
	c->appBin = NULL;
	c->region = NULL;

#ifdef DYNINST_DBG
	bpatch.registerErrorCallback(errorcallback);
#endif

	return SWS_SUCCESS;
}

int mod_disas_dyn_fini(mod_disas_t * md) {
	mod_disas_dyn_t * c = NULL;

	SWS_ARG_CHK(!md);

	c = (mod_disas_dyn_t *) md->mod_specific;

//	SWS_ARG_CHK(cs_close(&c->detail) != CS_ERR_OK, "Fini dynstone failed");
//	SWS_ARG_CHK(cs_close(&c->simple) != CS_ERR_OK, "Fini dynstone failed");

	return SWS_SUCCESS;
}

static int check_for_seq(uint8_t * data, const uint8_t ** opstart,
		uint8_t * seq, uint8_t seq_len, uint8_t * curpos) {
	int i = 0;

	for (i = 0; i < 8 && data[i] == **opstart; i++, (*opstart)++) {
		if (data[i] == seq[*curpos]) {
			if (*curpos + 1 == seq_len) { // last byte was a match and found all bytes in seq --> found it
				(*opstart)++;
				*curpos += 1;
				return i + 1;
			}

			// continue in seq if match
			*curpos += 1;
		} else { // not equal
			//reset seq ptr on no match
			*curpos = 0;
		}
	}

	(*opstart)++;

	return (*curpos > 0) ? i + 1 : 0;
}

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

	return NULL;
}

static int check_not_exec_section(erim_result_t * res,
		Elf64_Shdr * curSection) {
	size_t len = res->code_length;
	uint64_t addrit = 0L;

	const uint8_t * tmpcode = (const uint8_t *) (res->code + res->location);

// try disassembly after insn
//	insn = cs_malloc(cshandlesimple);
//	if (cs_disasm_iter(cshandlesimple, &tmpcode, &len, &addrit, insn)) {
//		res->flags.disas_failed = 0;
//	} else {
//		res->flags.disas_failed = 1;
//	}
//	cs_free(insn, 1);

// prt binary
//	const uint8_t * start = (loc > 10) ? code + loc - 10 : code + loc;
//	unsigned int length = ((loc > 10) ? 10 : 0) + SEQ_LEN
//			+ ((curSection->sh_size > 10 + SEQ_LEN + 10) ? 10 : 0);

	return SWS_SUCCESS;
}

CodeRegion * find_region(std::vector<CodeRegion *> regions,
		unsigned long long location) {
	for (auto const& r : regions) {
//		cout << hex << r->low() << " " << hex << r->high() << "\n";
		if (r->low() <= location && r->high() >= location)
			return r;
	}

	return NULL;
}

unsigned int prt_insn(Instruction::Ptr insn, char * buf, unsigned int len) {
	string insn_text = insn->format();
	strncpy(buf, insn_text.c_str(), len);

	return insn_text.size();
}

Instruction::Ptr find_insn(mod_disas_dyn_t * c, erim_input_t * in,
		erim_result_t * res, int64_t location, Address * crtAddr) {

	Instruction::Ptr insn;
	CodeRegion * r = NULL;

	if (!c->region) {
		SymtabCodeSource *sts;
		CodeObject *co;
		SymtabAPI::Symtab *symTab;
		std::string binaryPathStr(in->filename);
		bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
		if (isParsable == false) {
			const char *error = "error: file can not be parsed";
			cout << error;
			return NULL;
		}
		sts = new SymtabCodeSource(in->filename);
		co = new CodeObject(sts);
		//parse the binary given as a command line arg
		co->parse();
		c->region = find_region(co->cs()->regions(), location);
		if (!c->region)
			return NULL;
	}

	r = c->region;
	InstructionDecoder decoder((void *) r->low(),
			InstructionDecoder::maxInstructionLength, r->getArch());
	*crtAddr = r->low();
	while (*crtAddr <= r->high()) {
		if (!r->isCode(*crtAddr)) {
			(*crtAddr)++;
			continue;
		}
		insn = decoder.decode(
				(unsigned char *) r->getPtrToInstruction(*crtAddr));
		if (!insn) {
			// failed disas till location
			res->flags.disas_failed = 1;
			break;
		}

		if (*crtAddr <= location && *crtAddr + insn->size() >= location) {
			// found the instruction
			break;
		}

		// continue to next instruction
		*crtAddr += insn->size();
	}

	return insn;
}

unsigned long int distance(BPatch_basicBlock* b, unsigned long int addr) {

	if (!b)
		return UINT64_MAX;

	Address start = b->getStartAddress(), end = b->getEndAddress();

	if (!(start <= addr && end > addr))
		return UINT64_MAX;

	return addr - start;
}

bool blockContains(BPatch_basicBlock * b, unsigned long int addr) {
	if (!b)
		return false;

	Address start = b->getStartAddress(), end = b->getEndAddress();

	return start <= addr && end > addr;
}
  
string disassembleBlock(PatchBlock *block) {
	PatchBlock::Insns insns;
	PatchBlock::Insns::iterator j;
	Instruction::Ptr iptr;
	unsigned long int addr;
	char buffer[64];
	string str("");

	block->getInsns(insns);
//	InstructionDecoder decoder((void *) block->start(),
//			InstructionDecoder::maxInstructionLength, a);
	for (j = insns.begin(); j != insns.end(); j++) {

		// get instruction bytes
		addr = (*j).first;
		sprintf(buffer, "%08lx\t", (unsigned long) addr);
		str.append(buffer);
		str.append(block->getInsn(addr)->format());
		str.append("\n");
	}
	return str;
}

static void replaceAll(std::string& str, const std::string& from, const std::string& to) {
  if(from.empty())
    return;
  size_t start_pos = 0;
  while((start_pos = str.find(from, start_pos)) != std::string::npos) {
    str.replace(start_pos, from.length(), to);
    start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
  }
}
  
static string disassembleBlockSeq(PatchBlock * b, string indent, int end) {
  string str("");

  if(!b)
    return str;
  
  string dis = disassembleBlock(b);
  replaceAll(dis, "\n", "\n" + indent);
  str.append(indent + "block:\n");
  str.append(indent + dis);

  if(end < 1)
    return str;
  
  for(auto t : b->targets()) {
    str.append(disassembleBlockSeq(t->trg(), indent + "\t", end-1));
  }
  return str;
}
  
  //string disassemleFunc(PatchFunction * func) {
  //return mydisassembleBlockSeq(func->entry, "");
  //}
  
void find_points_via_imagepoints(BPatch_binaryEdit * appBin,
		unsigned long long int location) {
	BPatch_point * closest = NULL;
	std::vector<BPatch_point *> points;
	if (appBin->getImage()->findPoints(location, points)) {
//		cout << "IP: found " << points.size() << "points\n";

		closest = NULL;
		for (auto const& p : points) {
			if (p->getBlock()) {
//				cout << "IP: blk s " << p->getBlock()->getStartAddress() << "-"
//						<< p->getBlock()->getEndAddress() << "\n";
				if (blockContains(p->getBlock(), location)) {
					//							(distance(p->getBlock(), res->vm_location)
					//									< distance(closest->getBlock(), res->vm_location))) {
					closest = p;
				}
			}
		}

//		if (closest) {
//			cout << location << " IP: foudn block\n";
//		} else {
//			cerr << location << " IP: couldn't find point\n";
//		}
	}
}

void find_points_via_objpoints(BPatch_binaryEdit * appBin,
		unsigned long long int location) {
	vector<BPatch_object *> objects;
	appBin->getImage()->getObjects(objects);
	for (auto obj : objects) {

		vector<BPatch_point *> points;
		obj->findPoints(location, points);

//		if (!points.empty()) {
//			cout << location << " OP: could find block\n";
//		} else {
//			cout << location << " OP: couldn't find block\n";
//		}

	}
}

BPatch_basicBlock * find_points_via_modules(BPatch_binaryEdit * appBin,
		unsigned long long int location, BPatch_function ** f) {
	vector<BPatch_module *>*modules = appBin->getImage()->getModules();
	vector<BPatch_module *>::iterator moduleIter;
	BPatch_module *defaultModule;
	BPatch_basicBlock * result = NULL;

	int bbIndex = 0;
	int funcIndex = 0;
	for (moduleIter = modules->begin(); moduleIter != modules->end();
			++moduleIter) {

		vector<BPatch_function *>*allFunctions = (*moduleIter)->getProcedures();
		vector<BPatch_function *>::iterator funcIter;

		/* Insert snippets at the entry of every function */
		for (funcIter = allFunctions->begin(); funcIter != allFunctions->end();
				++funcIter) {
			BPatch_function *curFunc = *funcIter;
			set<BPatch_basicBlock *> blks;
			curFunc->getCFG()->getAllBasicBlocks(blks);

			for (auto blk : blks) {
				if (blockContains(blk, location)) {
					if (f)
						*f = curFunc;
					result = blk;
				}
			}
		}
	}
//
//	if (result)
//		cout << location << " M: found block " << result->getStartAddress()
//				<< " " << result->getEndAddress() << "\n";
//	else
//		cout << location << " M: couldn't find point\n";

	return result;
}

BPatch_point * find_points_via_point(BPatch_binaryEdit * appBin,
		unsigned long long int location, BPatch_function ** f) {
	vector<BPatch_module *>*modules = appBin->getImage()->getModules();
	vector<BPatch_module *>::iterator moduleIter;
	BPatch_module *defaultModule;
	BPatch_point * result = NULL;

	int bbIndex = 0;
	int funcIndex = 0;
	for (moduleIter = modules->begin(); moduleIter != modules->end();
			++moduleIter) {

		vector<BPatch_function *>*allFunctions = (*moduleIter)->getProcedures();
		vector<BPatch_function *>::iterator funcIter;

		/* Insert snippets at the entry of every function */
		for (funcIter = allFunctions->begin(); funcIter != allFunctions->end();
				++funcIter) {
			BPatch_function *curFunc = *funcIter;
			BPatch_point * p = curFunc->findPoint(location);
			if (p) {
				*f = curFunc;
				result = p;
			}

		}
	}
//
//	if (result)
//		cout << location << " M: found block " << result->getStartAddress()
//				<< " " << result->getEndAddress() << "\n";
//	else
//		cout << location << " M: couldn't find point\n";

	return result;
}

void find_points_via_as(BPatch_binaryEdit * appBin,
		unsigned long long int location) {

//	vector<AddressSpace *> ases;
//	appBin->getAS(ases);
//	vector<func_instance *> funcs;
//	block_instance * closest = NULL;
//	for (auto as : ases) {
//		set<block_instance *> blks;
//		as->findBlocksByAddr(location, blks, false);
//		for (auto blk : blks) {
//			if (blk->start() <= location && blk->end() > location)
//				closest = blk;
//		}
//	}
//	if (closest) {
//		cout << location << " AS: found block\n";
//	} else {
//		cout << location << " AS: couldn't find point\n";
//	}

}

void find_points_via_functionpoints(BPatch_binaryEdit * appBin,
		unsigned long long int location) {
	BPatch_point * closest = NULL;
	vector<BPatch_function*> locUsers;
	appBin->findFunctionsByAddr(location, locUsers);

	for (auto const& f : locUsers) {

		BPatch_Vector<BPatch_point *> fp;
		f->getAllPoints(fp);

		if(fp.size() > 0) {

			closest = NULL;

			for (auto const& p : fp) {
				if(p->getBlock())
//				cout << "FP: blk s " << p->getBlock()->getStartAddress() << "-" << p->getBlock()->getEndAddress() << "\n";
				if(blockContains(p->getBlock(), location)) {
					//							(distance(p->getBlock(), res->vm_location)
					//									< distance(closest->getBlock(), res->vm_location))) {
					closest = p;
				}
			}
		}
	}

//	if (closest) {
//		cout << location << " FP: found block\n";
//	} else {
//		cout << location << " FP: couldn't find point\n";
//	}
}

int mod_disas_dyn_check(mod_disas_t * md, erim_input_t * in,
		erim_result_t * res) {
	mod_disas_dyn_t * c = NULL;
	uint64_t addrit = 0L;
	const uint8_t * code = NULL;
	Elf64_Shdr * curSection = NULL;
	const uint8_t * lastInstr = NULL;
	unsigned int offset = 0;
	uint64_t leftlen = 0;
	uint64_t location = 0;
	Instruction::Ptr insn;
	CodeRegion * r;
	Address crtAddr;
	BPatch_binaryEdit * appBin = NULL;

	SWS_ARG_CHK(!md || !in || !res);

	c = (mod_disas_dyn_t *) md->mod_specific;
	code = (const uint8_t *) res->code;
	leftlen = res->code_length;
	location = res->vm_location;

	curSection = findSection(&in->eo, res->location, res);
	SWS_CHK(curSection == NULL, "Couldn't find corresponding section");

	if (!(curSection->sh_flags & SHF_EXECINSTR)) {
		res->flags.executable = 0;
		return check_not_exec_section(res, curSection);
	} else {
		res->flags.executable = 1;

		if (!c->appBin)
		c->appBin = bpatch.openBinary(in->filename);

		appBin = c->appBin;
		vector<BPatch_function*> locUsers;
		appBin->findFunctionsByAddr(location, locUsers);

		for (auto const& f : locUsers) {
			BPatch_Vector<BPatch_point *> * fp = f->findPoint(BPatch_allLocations);
			void * start = NULL, * end = NULL;
			f->getAddressRange(start, end);

			res->num_funcs = fp->size();

			BPatch_point * closest = NULL;
			if(fp->size() > 0) {
				closest = (*fp)[0];

				res->num_points += fp->size();
				for (auto const& p : *fp) {
					if(closest->getAddress() < p->getAddress() && (unsigned long long)p->getAddress() < location) {
						closest = p;
					}
				}

				if(closest) {
					if(res->offset_to_point == 0
							|| location - (unsigned long long) closest->getAddress() < res->offset_to_point) {
						res->point_type = closest->getPointType();
						res->offset_to_point = location - (unsigned long long) closest->getAddress();
					}
				}
			}
		}
	}

	insn = find_insn(c, in, res, location, &crtAddr);
	if (!insn)
	return SWS_COND_ERROR;

	r = c->region;

	if (crtAddr <= location && crtAddr + insn->size() >= location) {
		res->raw_bytes_len = res->insn_len[0] = insn->size();
		res->insn_addr[0] = crtAddr;

		// instruction found - we're at the instruction currently
		if (location - crtAddr + in->seq_len <= insn->size()) {
			// seq is within instruction size
			res->flags.seq_spans_insn = 0;

			prt_insn(insn, res->insn_text[0], sizeof(res->insn_text[0]));
			memcpy(res->raw_bytes, insn->ptr(), insn->size());
		} else {
			// seq spans two instructions
			res->flags.seq_spans_insn = 1;

			InstructionDecoder decoder((void *) r->low(),
					InstructionDecoder::maxInstructionLength, r->getArch());
			Instruction::Ptr insn2 = decoder.decode(
					(unsigned char *) r->getPtrToInstruction(
							crtAddr + insn->size()));

			res->insn_len[1] = insn2->size();
			res->insn_addr[1] = crtAddr + insn->size();
			res->raw_bytes_len += insn2->size();

			prt_insn(insn, res->insn_text[0], sizeof(res->insn_text[0]));
			prt_insn(insn2, res->insn_text[1], sizeof(res->insn_text[1]));

			memcpy(res->raw_bytes, insn->ptr(), insn->size());
			memcpy(res->raw_bytes + insn->size(), insn2->ptr(), insn2->size());
		}
	}

//	 check if block is in cfg
	BPatch_basicBlock * b = NULL;
	if(appBin) {
		vector<BPatch_point *> points;
		appBin->getImage()->findPoints((Address)res->vm_location, points);
		if(points.size() > 0) {
			b = points[0]->getBlock();
		}
	}
	res->flags.block_in_cfg = b != NULL;

	if(! res->flags.block_in_cfg) {
		b = find_points_via_modules(c->appBin, res->vm_location,
				NULL);
	}
	res->flags.block_in_cfg = b != NULL;

	if(! res->flags.block_in_cfg) {
		vector<BPatch_point *> points;
		vector<BPatch_point *> points2;
		c->appBin->getImage()->findPoints((Address)res->insn_addr[0], points);
		c->appBin->getImage()->findPoints((Address)res->insn_addr[1], points2);

		if(points.size() > 0) {
			res->flags.block_in_cfg = (unsigned long int)blockContains(points[0]->getBlock(), res->insn_addr[0]) && points[0]->getFunction();
		} else if(points2.size() > 0) {
			res->flags.block_in_cfg = (unsigned long int)blockContains(points2[0]->getBlock(), res->insn_addr[0]) && points2[0]->getFunction();
		} else {
			res->flags.block_in_cfg = false;
		}
	}

//	insn = cs_malloc(cshandle);
//	if (!cs_disasm_iter(cshandle, &lastInstr, &leftlen, &addrit, insn)) {
//		res->flags.disas_failed = 1;
//		return SWS_SUCCESS;
//	} else {
//		res->flags.disas_failed = 0;
//	}

	return SWS_SUCCESS;
}

bool overwriteBlock(PatchBlock *block, unsigned char val) {
	ParseAPI::Block *b = block->block();
	Offset off = b->start();
	ParseAPI::SymtabCodeRegion *r =
	dynamic_cast<ParseAPI::SymtabCodeRegion*>(b->region());
	if (r == NULL)
	return false;
	Offset region_off = (Offset) r->getPtrToInstruction(off)
	- (Offset) r->symRegion()->getPtrToRawData();
	bool success = false;
	while (off++ < b->end()) {
		success = r->symRegion()->patchData(region_off++, (void*) &val, 1);
		if (!success)
		return false;
	}
	return true;
}

  class NOPSnippet : public PatchAPI::Snippet {

public:

	virtual bool generate(Point *pt, Buffer &buf) {

		char nop = 0x90;
		buf.copy((void *)&nop, 1);

		return true;

	}
};

class PopRdxSnippet : public PatchAPI::Snippet {

public:

	virtual bool generate(Point *pt, Buffer &buf) {

		char pop = 0x5a;
		buf.copy((void *)&pop, 1);

		return true;

	}
};

class PushRdxSnippet : public PatchAPI::Snippet {

public:

  unsigned long long movValue = 0;
  unsigned int addValue = 0;
  
	virtual bool generate(Point *pt, Buffer &buf) {

	  unsigned char pushmovabs[3] = {0x52, 0x48, 0xba};
	  unsigned char add[3] = {0x48, 0x81, 0xc2};
		
	  buf.copy((void *)&pushmovabs, 3);
	  buf.copy((void *)&movValue, 8);
	  buf.copy((void *)&add, 3);
	  buf.copy((void *)&addValue, 4);
	  
	  return true;
	  
	}
};

class PushEdxSnippet : public PatchAPI::Snippet {

public:

  unsigned int movValue = 0;
  unsigned int addValue = 0;
  
	virtual bool generate(Point *pt, Buffer &buf) {

	  unsigned char pushmov[4] = {0x52, 0x48, 0xC7, 0xC2};
	  unsigned char add[3] = {0x48, 0x81, 0xc2};
		
	  buf.copy((void *)&pushmov, 4);
	  buf.copy((void *)&movValue, 4);
	  buf.copy((void *)&add, 3);
	  buf.copy((void *)&addValue, 4);
	  
	  return true;
	  
	}
};

typedef struct modrm {
  char mode : 2;
  char reg :3;
  char regmem :3;
} modrm;

// multiply register by 2
class Mul2IncrSnippet : public PatchAPI::Snippet {
public:

  char regNum;
  char width; // leads to prefix 0x48 (wide)
  char incr; // check to increment

  virtual bool generate(Point *pt, Buffer &buf) {
    int bufPtr = 0;
    char prefix = 0x48;
    char add = 0x01;
    modrm rm = {.mode = 3, .reg = regNum, .regmem = regNum};
    char reverse_rm = 0, i, temp;
    unsigned char x[4] = {0x48, 0x83, 0x00, 0x01};

    for (i = 0; i < 8; i++) {
      temp = (*((char*)&rm) & (1 << i));
      if(temp)
	reverse_rm |= (1 << ((8 - 1) - i));
    }
        
    // insert add
    if(width == 8) {
      buf.copy((void *)&prefix, 1);
    }
    buf.copy((void *)&add, 1);
    buf.copy((void *)&reverse_rm, 1);

    x[2] = reverse_rm;
    if(incr && width == 8) {
      buf.copy((void *)x, 4);
    } else if (incr && width == 4) {
      buf.copy((void *)&x[1], 3);
    }      
    
  }
  
};
  
// overwrite byte sequence
class ByteSnippet : public PatchAPI::Snippet {
public:

  char toInsert[24];
  unsigned int len = 0;

  virtual bool generate(Point *pt, Buffer &buf) {

    if(len > 24)
      return false;
    
    buf.copy((void*)toInsert, len);
    
    return true;
  }
  
};
  
// Insert snippet between start and end
static int insertSnippet(PatchBlock * start, PatchBlock * end, PatchBlock * newBlock) {
  int success;
  vector<PatchEdge*> targets, sources;
  vector<PatchEdge*>::const_iterator i;
  vector<PatchEdge*>::iterator j;
  
  targets = start->targets();
  sources = end->sources();
  
  assert(start->targets().size() == 1);
  success = PatchAPI::PatchModifier::redirect(targets[0], newBlock);
  assert(success);
	
  assert(newBlock->targets().size() == 1);
  success = PatchAPI::PatchModifier::redirect(newBlock->targets()[0], end);
  assert(success);
}

// swap patch blocks
static int swapNewSnippet(PatchBlock * o, PatchBlock *n) {
  int succes = 0;
  vector<PatchEdge*> targets, sources;

  targets = o->targets();
  sources = o->sources();

  for(auto e : sources) {
    PatchAPI::PatchModifier::redirect(e, n);
  }

  int i = 0;
  for(auto e : targets) {
    PatchAPI::PatchModifier::redirect(n->targets()[i++], e->trg());
  }
}

// insert pop instruction
static PatchAPI::InsertedCode::Ptr insertPop(PatchFunction * func) {
  PopRdxSnippet * spop = new PopRdxSnippet();
  PatchAPI::SnippetPtr spopptr = PatchAPI::Snippet::create(spop);
  return PatchAPI::PatchModifier::insert(func->obj(), spopptr,
						  NULL);
}
  
/*
 *Different Push operations
 */
static PatchAPI::InsertedCode::Ptr insertPR(PatchFunction * func, unsigned long long movVal, unsigned int addVal) {
  PushRdxSnippet * spush = new PushRdxSnippet();
  spush->movValue = movVal;
  spush->addValue = addVal;
  PatchAPI::SnippetPtr spushptr = PatchAPI::Snippet::create(spush);
  return PatchAPI::PatchModifier::insert(func->obj(), spushptr,
						  NULL);
}

static PatchAPI::InsertedCode::Ptr insertPE(PatchFunction * func, unsigned int movVal, unsigned int addVal) {
  PushEdxSnippet * spush = new PushEdxSnippet();
  spush->movValue = movVal;
  spush->addValue = addVal;
  PatchAPI::SnippetPtr spushptr = PatchAPI::Snippet::create(spush);
  return PatchAPI::PatchModifier::insert(func->obj(), spushptr,
						  NULL);
}

// create register expression
static BPatch_registerExpr * findRegister(const char *name, BPatch_addressSpace * as){
  std::vector<BPatch_register> registers;
  
  if(!as->getRegisters(registers)){
    cout << "Could not retrive registers. Register access may not be available on this platform.";
    return NULL;
  }
  
  for(unsigned int i = 0; i < registers.size(); i++){
    BPatch_register r = registers[i];
    if(r.name() == name){
      return new BPatch_registerExpr(r);
    }
  }
  
  cout << "Register " << name << " not found";
  return NULL;
}

// translate register name into register id
static int regIdByName(const char * name) {
  switch(name[1]) {
  case 'A':  case 'a':
    return 0;
  case 'C':  case 'c':
    return 1;
  case 'D':  case 'd':
    switch(name[2]) {
    case 'X':    case 'x':
      return 2;
    case 'I':    case 'i':
      return 7;
    }
  case 'B':  case 'b':
    switch(name[2]) {
    case 'X':    case 'x':
      return 3;
    case 'P':    case 'p':
      return 5;
    }
  case 'S':  case 's':
    switch(name[2]) {
    case 'P':    case 'p':
      return 4;
    case 'I':    case 'i':
      return 6;
    }
  case '8':
    return 0;
  case '9':
    return 1;
  case '1':
    switch(name[2]) {
    case '0':
      return 2;
    case '1':
      return 3;
    case '2':
      return 4;
    case '3':
      return 5;
    case '4':
      return 6;
    case '5':
      return 7;
    }
  default:
    printf("couldn't find register\n");
    return 0;
  }
}
  
/* split_immediate
 *
 * Alter immediates which fully or partially have the sequence to be removed in them
 * The immediate is translated into a computation that combines multiple immediate values
 * into the final result in the target register.
 *
 * Example: 
 *	Instruction which emmits 0f01ef:
 * 	mov rax, 0x000f01ef (sewquence to be removed 0f01ef)
 *	
 *	split immediate will alter the mov instruction
 *	mov rax, 0x000780f7 (half of 0x000f01ef)
 *	add rax, 0x000780f8 (half of 0x000f01ef + 1 to compensate for integer division)
 *
 */
static int split_immediate(BPatch_basicBlock * b, BPatch_function * f, PatchBlock * blk, PatchFunction * func, erim_result_t * res, CodeRegion * r, BPatch_binaryEdit * appBin) {

  int success = 0;

  Instruction::Ptr insn = blk->getInsn(res->insn_addr[0]);

  // find out if it is a mov
  Operation op = insn->getOperation();
  entryID id = op.getID();
  cout << op.format() << " " << op.getID() << endl;

  PatchBlock * insnBlk = PatchAPI::PatchModifier::split(blk, res->insn_addr[0], false,
							blk->end());
  PatchBlock * endBlk = PatchAPI::PatchModifier::split(insnBlk, res->insn_addr[0] + res->insn_len[0],
					     false, insnBlk->end());


  
  std::cout << disassembleBlockSeq(blk, "", 6) << std::endl;
  
  if(id > 277 && id < 318) {

    std::vector<Operand> operands;
    Operand read;
    Operand write;

    std::set<RegisterAST::Ptr> writeSet;
    char bytes[24];
    unsigned int len = 0;
    memset(bytes, 0, 16);

    insn->getWriteSet(writeSet);
    insn->getOperands(operands);
    len = insn->size();

    memcpy(bytes, insn->ptr(), len);

    printf("raw bytes len %d\n", len);
    
    if(operands.size() > 2)
      return 1;

    for(auto o : operands) {
      if(o.isRead())
	read = o;
      if(o.isWritten())
	write = o;
    }

    cout << read.getValue()->format() << endl;
    cout << write.getValue()->format() << endl;


    csh c;
    cs_open(CS_ARCH_X86, CS_MODE_64, &c);
    cs_option(c, CS_OPT_DETAIL, CS_OPT_ON);
    
    size_t size = insn->size();
    uint64_t addrit = 0;
    uint8_t * code = (uint8_t*)insn->ptr();
    cs_insn * capInsn = cs_malloc(c);
    if(cs_disasm_iter(c, (const uint8_t **) &code, &size, &addrit, capInsn)) {
      // success
      printf("found %s\n", capInsn->mnemonic);
      if(capInsn->detail) {
	// detailed analysis worked
	cs_x86 * details = (cs_x86*) &capInsn->detail->x86;
	cs_x86_encoding * e = &details->encoding;

	PatchBlock * newMov = NULL;
	Mul2IncrSnippet * mis = new Mul2IncrSnippet();

	// differentiate by immediate siza (here 4 bytes)	
	if(read.getValue()->size() == 4) {

	  int * valPtr = (int*) &bytes[e->imm_offset];
	  int oldVal = *valPtr;
	  int halfed = oldVal / 2;
	  int addOne = oldVal % 2;

	  mis->width = 4;
	  
	  if(addOne)
	    mis->incr = 1;

	  cout << oldVal << " " << halfed << " " << addOne << endl;

	  memcpy(&bytes[e->imm_offset], &halfed, sizeof(halfed));
	  // overwrite existing immediate with half of the immediate
	  ByteSnippet * bs = new ByteSnippet();
	  bs->len = len;
	  memcpy(bs->toInsert, bytes, len);
	  PatchAPI::SnippetPtr bsptr = PatchAPI::Snippet::create(bs);
	
	  newMov = PatchAPI::PatchModifier::insert(func->obj(), bsptr, NULL)->entry();
	  
	} else if (read.getValue()->size() == 8) { // now split an immeidate of 8 bytes

	  unsigned long long * valPtr = (unsigned long long*) &bytes[e->imm_offset];
	  unsigned long long oldVal = *valPtr;
	  unsigned long long  halfed = oldVal / 2;
	  unsigned long long addOne = oldVal % 2;

	  mis->width = 8;
	  
	  if(addOne)
	    mis->incr = 1;
	  
	  cout << oldVal << " " << halfed << " " << addOne << endl;

	  memcpy(&bytes[e->imm_offset], &halfed, sizeof(halfed));

	  ByteSnippet * bs = new ByteSnippet();
	  bs->len = len;
	  memcpy(bs->toInsert, bytes, len);
	  PatchAPI::SnippetPtr bsptr = PatchAPI::Snippet::create(bs);

	  newMov = PatchAPI::PatchModifier::insert(func->obj(), bsptr, NULL)->entry();
	  
	} else {
	  // never observed issues with immediates of different size
	  // TODO: implement for smaller immediates as well.
	}
	
	insertSnippet(blk, endBlk, newMov);
	
	//	swapNewSnippet(insnBlk, newMov);
	
	mis->regNum = regIdByName(write.getValue()->format().c_str());
	
	// add second half of the immediate
	PatchAPI::SnippetPtr misptr = PatchAPI::Snippet::create(mis);
	PatchBlock * mul = PatchAPI::PatchModifier::insert(func->obj(), misptr, NULL)->entry();
	insertSnippet(newMov, endBlk, mul);


	cout << "num sources " << insnBlk->sources().size() << endl;
	
	std::vector<PatchBlock*> toRemove {insnBlk};
	PatchAPI::PatchModifier::remove(toRemove, true);
	
      }
    }
    
    
  } else {

  //cout << "lets rewrite\n";
  //cout << disassembleBlock(blk) << "\n";
  //cout << blk->targets().size() << "\n";
  
    //  PatchBlock * insnBlk = PatchModifier::split(blk, res->insn_addr[0], false,
    //						      blk->end());

  //cout << disassembleBlockSeq(blk, "", 6) << endl;
  
  //PatchBlock * endBlk = PatchModifier::split(insnBlk, res->insn_addr[0] + res->insn_len[0],
    //					     false, insnBlk->end());

  //  cout << disassembleBlockSeq(blk, "", 6) << endl;
  
  /*  cout << "first" << endl << disassembleBlock(blk) << endl << "second" << endl
       << disassembleBlock(insnBlk) << endl
       << "third" << endl << disassembleBlock(endBlk) << endl;
  */

    //  insertSnippet(blk, insnBlk, insertPE(func, 0, 0)->entry());
    //  insertSnippet(insnBlk, endBlk, insertPop(func)->entry());
  
  }  

  /*

  */

  /*
  vector<BPatch_point *> points;
  appBin->getImage()->findPoints((Address)res->insn_addr[0], points);
  
  if(points.size() > 0 && blockContains(points[0]->getBlock(), res->insn_addr[0])) {
    cout << "found point via insn addr" <<endl;

    Instruction::Ptr i = points[0]->getInsnAtPoint();
    cout << i->format() << endl;
  }

  BPatch_insnExpr ie = BPatch_insnExpr((BPatch_instruction *)points[0]->getMemoryAccess());
  BPatch_arithExpr newStoreAddr(BPatch_plus,
				BPatch_effectiveAddressExpr(),
				BPatch_regExpr(x86_64::edx));
  ie.overrideStoreAddress(newStoreAddr);
  
  appBin->replaceCode(points[0], &ie);

*/
  
  /*  
  static RegisterAST * rdx(new RegisterAST(x86_64::edx));
  std::vector<Operand> ops;
  insn->getOperands(ops);

  for(auto iter = ops.begin(); iter != ops.end(); ++ iter) {
    Expression::Ptr e = (*iter).getValue();
    if((*iter).isRead()) {
      e->bind(&*e, rdx->eval());
      break;
    }
  }
  */
  /*  vector<BPatch_point *> points;
  appBin->getImage()->findPoints(, points);
  
  if(points.size() > 0 && blockContains(points[0]->getBlock(), res->vm_location)) {
    printf("is the right point to use\n");
    }*/

  //  b = find_points_via_modules(c->appBin, res->vm_location,
  //			      NULL);

  
  /*  
  */
  
  std::cout << disassembleBlockSeq(blk, "", 6) << std::endl;
  
  return 0;
}
  
/*
 * insert_nop
 *
 * Insert a NOP instruction 
 */
static int insert_nop(PatchBlock * blk, PatchFunction * func, Address splitEnd, CodeRegion * r) {
	bool success = true;

//	cout << "lets rewrite\n";
//	cout << disassembleBlock(blk) << "\n";
//	cout << blk->targets().size() << "\n";

	Address blkstart = blk->start(), blkend = blk->end();

	PatchBlock * secondBlk = PatchAPI::PatchModifier::split(blk, splitEnd, false,
			blk->end());

	BPatch_nullExpr nop;
	NOPSnippet * snop = new NOPSnippet();
	PatchAPI::SnippetPtr snopptr = PatchAPI::Snippet::create(snop);
	PatchAPI::InsertedCode::Ptr icode = PatchAPI::PatchModifier::insert(func->obj(), snopptr,
			NULL);

	PatchBlock * newBlock = icode->entry();
	vector<PatchEdge*> targets, sources;
	vector<PatchEdge*>::const_iterator i;
	vector<PatchEdge*>::iterator j;

	targets = blk->targets();
	sources = blk->sources();

// its somewhere in the middle
	if(splitEnd != blkstart && splitEnd != blkend) {
		assert(blk->targets().size() == 1);
		success = PatchAPI::PatchModifier::redirect(targets[0], newBlock);
		assert(success);

		assert(icode->exits().size() == 1);
		success = PatchAPI::PatchModifier::redirect(*icode->exits().begin(), secondBlk);
		assert(success);

//		cout << "first blk:\n";
//		cout << disassembleBlock(newBlock);
//		cout << "\nsecond blk:\n";
//		cout << disassembleBlock(secondBlk);
	} else if(splitEnd == blkstart) {
		// it tries to split of the first byte
		for (auto s : sources) {
			success = PatchAPI::PatchModifier::redirect(s, newBlock);
			assert(success);
		}

		success = PatchAPI::PatchModifier::redirect(*icode->exits().begin(), blk);
		assert(success);

//		cout << "first blk:\n";
//		cout << disassembleBlock(blk);
//		cout << "second blk:\n";
//		cout << disassembleBlock(newBlock);
	} else if(splitEnd == blkend) {
		// it tries to split after the last byte
		for (auto t : targets) {
			success = PatchAPI::PatchModifier::redirect(*icode->exits().begin(), t->trg());
			assert(success);
			success = PatchAPI::PatchModifier::redirect(t, newBlock);
			assert(success);
		}

//		cout << "first blk:\n";
//		cout << disassembleBlock(newBlock);
//		cout << "second blk:\n";
//		cout << disassembleBlock(blk);
	} else {
		// error splitend outside of blk
		return SWS_COND_ERROR;
	}

	return SWS_SUCCESS;
}

/*
 * rewrite_span_occurrence
 *
 * Rewrites sequences that span multiple instructions by simply 
 * placing a nop instruction inbetween the two instructions creating
 * the sequence.
 *
 */
int rewrite_span_occurrence(BPatch_basicBlock * b, BPatch_function * f,
		erim_result_t * res, CodeRegion * r) {
	PatchBlock * blk = PatchAPI::convert(b);
	PatchFunction * func = PatchAPI::convert(f);

	return insert_nop(blk, func, res->insn_addr[1], r);
}

class PrintVisitor : public Visitor {
public :
  PrintVisitor () {};
  ~ PrintVisitor () {};
  virtual void visit ( BinaryFunction * b ) {};
  virtual void visit ( Immediate * i ) {
    cout << "Visiting Immediate: " << i << endl ;
  }
  virtual void visit ( RegisterAST * r ) {}
  virtual void visit ( Dereference * d ) {};
};
  
/*
 * rewrite_single_insn
 *
 * Rewrites single instruction that holds sequence
 *
 * Options to rewrite:
 * 1) Instruction uses RIP for calculations such as jmp (RIP) + 0x0f01ef
 *    In this case it is enough to move the instrution which changes
 *    the RIP and hence, also the offset
 * 2) Split the immeidate that leads to the sequence
 *
 */
int rewrite_single_insn(BPatch_basicBlock * b, BPatch_function * f,
			erim_result_t * res, CodeRegion * r, BPatch_binaryEdit * appBin) {
	int ret = SWS_COND_ERROR;
	PatchBlock * blk = PatchAPI::convert(b);
	PatchFunction * func = PatchAPI::convert(f);

	Instruction::Ptr insn = blk->getInsn(res->insn_addr[0]);
	static RegisterAST::Ptr rip(new RegisterAST(x86_64::rip));

	// check if rip based issue
	if(insn->isRead(rip)) {
	  // move instruction to change offset that leads to sequence
	  //		cout << "rip access, try to break it\n";
	  ret = insert_nop(blk, func, res->insn_addr[0], r);
	} else {
	  // immediate that leads to sequence has to be split
	  cout << insn->format() << endl;
	  
	  PrintVisitor pv;

	  ret = split_immediate(b, f, blk, func, res, r, appBin);
	  
	  //	  SWS_LOG("Rewrite Rule not implemented");
	  //	  ret = false;
	}
	
	return ret;
}

void find_points_via_patchmgd(BPatch_binaryEdit * appBin, erim_result_t * res) {

	PatchMgrPtr mgr = PatchAPI::convert(appBin->getImage());

}

/*
 * mod_disas_dyn_rewrite
 *
 * Rewrite all sequences found in res for the input binary in
 *
 */
int mod_disas_dyn_rewrite(mod_disas_t * md, erim_input_t * in,
		erim_result_t * res) {

	mod_disas_dyn_t * c = NULL;
	erim_result_t * r = NULL;
	int ret = SWS_COND_ERROR;

	SWS_ARG_CHK(!md || !in || !res);

	c = (mod_disas_dyn_t *) md->mod_specific;

	if (!c->appBin)
	c->appBin = bpatch.openBinary(in->filename);

	BPatch_binaryEdit * appBin = c->appBin;

	appBin->beginInsertionSet();

	//interate over all sequences found
	for (; res; res = res->next) {

		// if not in cfg don't try to rewrite it
		if(!res->flags.block_in_cfg) {
			continue;
		}

//		find_points_via_functionpoints(appBin, res->vm_location);
//		find_points_via_imagepoints(appBin, res->vm_location);
//		find_points_via_objpoints(appBin, res->vm_location);
//		find_points_via_modules(appBin,
//				res->vm_location, &f);
//		BPatch_point * p = find_points_via_point(appBin, (res->flags.seq_spans_insn) ?
//				res->insn_addr[1] : res->insn_addr[0], &f);
		/*cout << "___________\n";
		 find_points_via_functionpoints(appBin, res->seg_location);
		 find_points_via_imagepoints(appBin, res->seg_location);
		 find_points_via_objpoints(appBin, res->seg_location);
		 find_points_via_modules(appBin, res->seg_location);
		 cout << "___________\n";
		 find_points_via_functionpoints(appBin, res->location);
		 find_points_via_imagepoints(appBin, res->location);
		 find_points_via_objpoints(appBin, res->location);
		 find_points_via_modules(appBin, res->location);*/
//		vector<BPatch_point *> points;
//		appBin->getImage()->findPoints((Address)res->insn_addr[1], points);
//		if(points.size() > 0) {
////			cout << points[0]->getAddress() << "\n";
//
//			f = points[0]->getFunction();
//			b = points[0]->getBlock();
//		} else {
//			b = find_points_via_modules(c->appBin, res->vm_location,
//					NULL);
//			if(b) {
//				BPatch_point * p = b->findEntryPoint();
//				f = p->getFunction();
//			}
//		}
//
//		if(b && f) {
//			if (res->flags.seq_spans_insn) {
//				ret = rewrite_span_occurrence(b, f, res, c->region);
//				//		rewrite_span_occurrence2(appBin, res);
//			}
//			else if (!res->flags.seq_spans_insn) {
//				// intra instruction
//				ret = rewrite_single_insn(b,f, res, c->region);
//			}
//		}
//

		// Find a point to access the sequence, ths is a requirement to be able to rewrite
		BPatch_function * f = NULL;
		BPatch_basicBlock * b = NULL;
		vector<BPatch_point *> points;
		// try to find point using vm location
		appBin->getImage()->findPoints((Address)res->vm_location, points);
		if(points.size() > 0) {
			cout << points[0]->getAddress() << "\n";

			f = points[0]->getFunction();
			b = points[0]->getBlock();
			printf("found point immediately\n");
			// try to find it through global search
		} else if (!f || !b) {
			b = find_points_via_modules(c->appBin, res->vm_location,
					NULL);
			if(b) {
				BPatch_point * p = b->findEntryPoint();
				f = p->getFunction();
			}
			printf("found block via modules\n");
		}
		// try to find it at the instruction addresses
		if(!b || !f) {
			vector<BPatch_point *> points;
			vector<BPatch_point *> points2;
			c->appBin->getImage()->findPoints((Address)res->insn_addr[0], points);
			c->appBin->getImage()->findPoints((Address)res->insn_addr[1], points2);

			if(points.size() > 0 && blockContains(points[0]->getBlock(), res->insn_addr[0])) {

				f = points[0]->getFunction();
				b = points[0]->getBlock();
			}
			if(!b && points2.size() > 0 && blockContains(points2[0]->getBlock(), res->insn_addr[0])) {

				f = points[0]->getFunction();
				b = points[0]->getBlock();
			}
			printf("found insn addresses\n");
		}

		// if points were found -> rewrite
		if(b && f) {
			// Differencitate the case of the seq. spanning two instructions 
			if (res->flags.seq_spans_insn) {
	  		  ret = rewrite_span_occurrence(b, f, res, c->region);
			} else if (!res->flags.seq_spans_insn) {
			  // or wihtin a single instruction
			  ret = rewrite_single_insn(b,f, res, c->region, appBin);
			}
		}

	}

	return ret;
}

int mod_disas_dyn_writeFile(mod_disas_t * md, char * filename) {

	char output[256];
	mod_disas_dyn_t * c = NULL;
	SWS_ARG_CHK(!md || !filename);

	c = (mod_disas_dyn_t *) md->mod_specific;

	SWS_ARG_CHK(!c->appBin);

	sprintf(output, "%s.erim", filename);

	c->appBin->finalizeInsertionSet(false, NULL);
	c->appBin->writeFile(output);

	return SWS_SUCCESS;
}

#ifdef __cplusplus
}
#endif

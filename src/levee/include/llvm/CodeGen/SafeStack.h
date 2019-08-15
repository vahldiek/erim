//===--- llvm/CodeGen/SafeStack.h - Safe Stack Protector --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CODEGEN_FCFIDBLSTACKPROTECTOR_H
#define LLVM_CODEGEN_FCFIDBLSTACKPROTECTOR_H

namespace llvm {

class AllocaInst;
class DataLayout;

/// Check whether a given alloca instructino (AI) should be put on the safe
/// stack or not. The function analyzes all uses of AI and checks whether it is
/// only accessed in a memory safe way (as decided statically).
bool IsSafeStackAlloca(AllocaInst *AI, DataLayout *DL);

} // namespace llvm

#endif // LLVM_CODEGEN_FCFIDBLSTACKPROTECTOR_H

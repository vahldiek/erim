//===-- SafeStack.cpp - Safe Stack Insertion ------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This pass splits the stack into the safe stack (kept as-is for LLVM backend)
// and the unsafe stack (explicitly allocated and managed through the runtime
// support library).
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "safe-stack"
#include "llvm/CodeGen/SafeStack.h"
#include "llvm/Support/Debug.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/DebugInfo.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Target/TargetLowering.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_os_ostream.h"

// Uncomment the following to enable the runtime stats collection
// instrumentation. Remember to enable in safestack.cc in compiler-rt as well
// Both switches must be active or not at the same time!
//#define SAFE_STACK_PROFILE_STATS

// Default alignment of the unsafe stack
#define UNSAFE_STACK_ALIGNMENT 16

using namespace llvm;

#if 0
static cl::opt<unsigned> SafeStackArrayLimit("safe-stack-array-limit",
        cl::Hidden, cl::desc("Maximum size of array on safe stack"),
        cl::init(128));
#endif

namespace llvm {

cl::opt<bool> ShowStats("safe-stack-stats",
      cl::desc("Show safe stack protection compile-time statistics"),
      cl::init(false));

STATISTIC(NumFunctions, "Total number of functions");
STATISTIC(NumUnsafeStackFunctions, "Number of functions with unsafe stack");
STATISTIC(NumUnsafeStackRestorePointsFunctions,
          "Number of functions that use setjmp or exceptions");

STATISTIC(NumAllocas, "Total number of allocas");
STATISTIC(NumUnsafeStaticAllocas, "Number of unsafe static allocas");
STATISTIC(NumUnsafeDynamicAllocas, "Number of unsafe dynamic allocas");
STATISTIC(NumUnsafeStackRestorePoints, "Number of setjmps and landingpads");

// Validate the result of Module::getOrInsertFunction called for a runtime
// interface function. If the instrumented module defines a function
// with the same name, their prototypes must match, otherwise
// getOrInsertFunction returns a bitcast.
static Function *CheckInterfaceFunction(Constant *FuncOrBitcast) {
  if (isa<Function>(FuncOrBitcast))
    return cast<Function>(FuncOrBitcast);

  FuncOrBitcast->dump();
  report_fatal_error("trying to redefine a safe stack"
                     " runtime interface function");
}

/// Check whether a given alloca instructino (AI) should be put on the safe
/// stack or not. The function analyzes all uses of AI and checks whether it is
/// only accessed in a memory safe way (as decided statically).
bool IsSafeStackAlloca(AllocaInst *AI, DataLayout *) {
  // Go through all uses of this alloca and check whether all accesses to the
  // allocated object are statically known to be memory safe and, hence, the
  // object can be placed on the safe stack.

#if 0
  // Placing large objects on the same stack as small locals and register spills
  // reduces locality of memory accesses and increases the cache preasure.

  // Avoid placing variable-size arrays on the safe stack, as such arrays are
  // typically large.
  if (!isa<ConstantInt>(AI->getArraySize()))
    return false;

  // Avoid placing large arrays on the safe stack.
  if (cast<ConstantInt>(AI->getArraySize())->getZExtValue() *
        DL->getTypeAllocSize(AI->getAllocatedType()) > SafeStackArrayLimit)
    return false;
#endif

  SmallPtrSet<Value*, 16> Visited;
  SmallVector<Instruction*, 8> WorkList;
  WorkList.push_back(AI);

  // A DFS search through all uses of the alloca in bitcasts/PHI/GEPs/etc.
  while (!WorkList.empty()) {
    Instruction *V = WorkList.pop_back_val();
    for (Value::use_iterator UI = V->use_begin(),
                             UE = V->use_end(); UI != UE; ++UI) {
      Use *U = &UI.getUse();
      Instruction *I = cast<Instruction>(U->getUser());
      assert(V == U->get());

      switch (I->getOpcode()) {
      case Instruction::Load:
        // Loading from a pointer is safe
        break;
      case Instruction::VAArg:
        // "va-arg" from a pointer is safe
        break;
      case Instruction::Store:
        if (V == I->getOperand(0))
          // Stored the pointer - conservatively assume it may be unsafe
          return false;
        // Storing to the pointee is safe
        break;

      case Instruction::GetElementPtr:
        if (!cast<GetElementPtrInst>(I)->hasAllConstantIndices())
          // GEP with non-constant indices can lead to memory errors
          return false;

        // We assume that GEP on static alloca with constant indices is safe,
        // otherwise a compiler would detect it and warn during compilation.

        if (!isa<ConstantInt>(AI->getArraySize()))
          // However, if the array size itself is not constant, the access
          // might still be unsafe at runtime.
          return false;

        /* fallthough */

      case Instruction::BitCast:
      case Instruction::PHI:
      case Instruction::Select:
        // The object can be safe or not, depending on how the result of the
        // BitCast/PHI/Select/GEP/etc. is used.
        if (Visited.insert(I))
          WorkList.push_back(cast<Instruction>(I));
        break;

      case Instruction::Call:
      case Instruction::Invoke: {
        CallSite CS(I);

        // Given we don't care about information leak attacks at this point,
        // the object is considered safe if a pointer to it is passed to a
        // function that only reads memory nor returns any value. This function
        // can neither do unsafe writes itself nor capture the pointer (or
        // return it) to do unsafe writes to it elsewhere. The function also
        // shouldn't unwind (a readonly function can leak bits by throwing an
        // exception or not depending on the input value).
        if (CS.onlyReadsMemory() /* && CS.doesNotThrow()*/ &&
            I->getType()->isVoidTy())
          continue;

        // LLVM 'nocapture' attribute is only set for arguments whose address
        // is not stored, passed around, or used in any other non-trivial way.
        // We assume that passing a pointer to an object as a 'nocapture'
        // argument is safe.
        // FIXME: a more precise solution would require an interprocedural
        // analysis here, which would look at all uses of an argument inside
        // the function being called.
        CallSite::arg_iterator B = CS.arg_begin(), E = CS.arg_end();
        for (CallSite::arg_iterator A = B; A != E; ++A)
          if (A->get() == V && !CS.doesNotCapture(A - B))
            // The parameter is not marked 'nocapture' - unsafe
            return false;
        continue;
      }

      default:
        // The object is unsafe if it is used in any other way.
        return false;
      }
    }
  }

  // All uses of the alloca are safe, we can place it on the safe stack.
  return true;
}

} // namespace llvm

namespace {
  /// The SafeStackInserter pass splits the stack of each function into the
  /// safe stack, which is only accessed through memory safe dereferences
  /// (as determined statically), and the unsafe stack, which contains all
  /// local variables that are accessed in unsafe ways.
  class SafeStackInserter : public ModulePass {
    /// Thread-local variable that stores the unsafe stack pointer
    Value *UnsafeStackPtr;

    DataLayout *DL;
    AliasAnalysis *AA;
    const TargetLoweringBase *TLI;

    bool haveFunctionsWithSafeStack(Module &M) {
      for (Module::iterator It = M.begin(), Ie = M.end(); It != Ie; ++It) {
        if (It->hasFnAttribute(Attribute::SafeStack))
          return true;
      }
      return false;
    }

    bool doPassInitialization(Module &M);
    bool doPassFinalization(Module &M);
    bool runOnFunction(Function &F);

  public:
    static char ID; // Pass identification, replacement for typeid.
    SafeStackInserter(): ModulePass(ID), TLI(0) {
      initializeSafeStackInserterPass(*PassRegistry::getPassRegistry());
    }

    SafeStackInserter(const TargetLoweringBase *tli): ModulePass(ID), TLI(tli) {
      initializeSafeStackInserterPass(*PassRegistry::getPassRegistry());
    }

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addRequired<AliasAnalysis>();
      AU.addRequired<DataLayout>();
    }

    virtual bool runOnModule(Module &M) {
      DEBUG(dbgs() << "[SafeStack] Module: "
                   << M.getModuleIdentifier() << "\n");

      // Does the module have any functions that require safe stack?
      if (!haveFunctionsWithSafeStack(M)) {
        DEBUG(dbgs() << "[SafeStack] no functions to instrument\n");
        return false; // Nothing to do
      }

      DL = &getAnalysis<DataLayout>();
      AA = &getAnalysis<AliasAnalysis>();

      assert(TLI != NULL && "SafeStackInserter requires TargetLibraryInfo");

      // Add module-level code (e.g., runtime support function prototypes)
      doPassInitialization(M);

      // Add safe stack instrumentation to all functions that need it
      for (Module::iterator It = M.begin(), Ie = M.end(); It != Ie; ++It) {
        Function &F = *It;
        DEBUG(dbgs() << "[SafeStack] Function: " << F.getName() << "\n");

        if (!F.hasFnAttribute(Attribute::SafeStack)) {
          DEBUG(dbgs() << "[SafeStack] safestack is disabled"
                          " for this function\n");
          continue;
        }

        if (F.isDeclaration()) {
          DEBUG(dbgs() << "[SafeStack] function definition is not available\n");
          continue;
        }

        if (F.getName().startswith("llvm.") ||
            F.getName().startswith("__llvm__")) {
          DEBUG(dbgs() << "[SafeStack] skipping an intrinsic function\n");
          continue;
        }

        {
          // Make sure the regular stack protector won't run on this function
          // (safestack attribute takes precedence)
          AttrBuilder B;
          B.addAttribute(Attribute::StackProtect)
              .addAttribute(Attribute::StackProtectReq)
              .addAttribute(Attribute::StackProtectStrong);
          F.removeAttributes(AttributeSet::FunctionIndex, AttributeSet::get(
                F.getContext(), AttributeSet::FunctionIndex, B));
        }

        if (AA->onlyReadsMemory(&F)) {
          // XXX: we don't protect against information leak attacks for now
          DEBUG(dbgs() << "[SafeStack] function only reads memory\n");
          continue;
        }

        runOnFunction(F);
      }

      // Finalization (mostly for statistics)
      doPassFinalization(M);
      return true;
    }

#ifdef SAFE_STACK_PROFILE_STATS
  // Stats generation code (to be rewritten)
  private:
    Function *RegisterProfileTableFunc;
    GlobalVariable *ProfileTable;
    SmallVector<std::string, 32> ProfileNames;

#if 0
    static void PrintDebugLoc(LLVMContext &Ctx, const DebugLoc& DbgLoc,
                              raw_ostream &Outs) {
      if (DbgLoc.isUnknown()) {
        Outs << "<debug info not available>";
        return;
      }

      MDNode *Scope, *InlinedAt;
      DbgLoc.getScopeAndInlinedAt(Scope, InlinedAt, Ctx);

      StringRef Filename = DIScope(Scope).getFilename();
      Filename = sys::path::filename(Filename);

      Outs << Filename << ':' << DbgLoc.getLine();

      if (DbgLoc.getCol() != 0)
        Outs << ':' << DbgLoc.getCol();

      if (InlinedAt) {
        Outs << " @ ";
        PrintDebugLoc(Ctx, DebugLoc::getFromDILocation(InlinedAt), Outs);
      }
    }
#endif

    bool doStatsInitialization(Module &M) {
      // We don't know the size of the array, hence we have to use indirection
      LLVMContext &Ctx = M.getContext();
      Type *STy = StructType::get(Type::getInt64Ty(Ctx),
                                  Type::getInt8PtrTy(Ctx), NULL);
      ProfileTable = new GlobalVariable(M, STy, false,
                                        GlobalValue::InternalLinkage, NULL);

      RegisterProfileTableFunc = CheckInterfaceFunction(
            M.getOrInsertFunction("__llvm__safestack_register_profile_table",
                                  Type::getVoidTy(Ctx),
                                  Type::getInt8PtrTy(Ctx),
                                  DL->getIntPtrType(Ctx), NULL));
      return true;
    }

    template<typename _IRBuilder>
    Value *insertProfilePoint(_IRBuilder &IRB, Instruction *I,
                              Twine Kind, Value *Num = NULL) {
      size_t n = ProfileNames.size();
      Value *Idx[2] = { IRB.getInt64(n), IRB.getInt32(0) };
      Value *P = IRB.CreateGEP(ProfileTable, Idx);

      Value *Inc = Num ? IRB.CreateZExt(Num, IRB.getInt64Ty())
                       : IRB.getInt64(1);
      IRB.CreateAtomicRMW(AtomicRMWInst::Add, P, Inc, Monotonic);

      std::string _s; raw_string_ostream os(_s);
      os << I->getParent()->getParent()->getName() << "\t";

      DebugLoc DL = I->getDebugLoc();
      if (DL.isUnknown()) os << "?" << n;
      else {
        os << DIScope(DL.getScope(I->getContext())).getFilename()
           << ":" << DL.getLine() << ":" << DL.getCol();
        for (DebugLoc InlinedAtDL = DL;;) {
          InlinedAtDL = DebugLoc::getFromDILocation(
                InlinedAtDL.getInlinedAt(I->getContext()));
          if (InlinedAtDL.isUnknown())
            break;
          os << " @ ";
          os << DIScope(InlinedAtDL.getScope(I->getContext())).getFilename()
             << ":" << InlinedAtDL.getLine() << ":" << InlinedAtDL.getCol();
        }
      }

      os << "\t" << Kind;
      ProfileNames.push_back(os.str());

      return P;
    }

    template<typename _IRBuilder>
    void incrementProfilePoint(_IRBuilder &IRB, Value *P) {
      IRB.CreateAtomicRMW(AtomicRMWInst::Add, P, IRB.getInt64(1), Monotonic);
    }

    bool doStatsFinalization(Module &M) {
      // Create the profile table
      LLVMContext &Ctx = M.getContext();
      Type *Int64Ty = Type::getInt64Ty(Ctx);
      Type *VoidPtrTy = Type::getInt8PtrTy(Ctx);

      StructType *PfItemTy = StructType::get(Int64Ty, VoidPtrTy, NULL);
      ArrayType *PfArrayTy = ArrayType::get(PfItemTy, ProfileNames.size());

      SmallVector<Constant*, 32> PfArrayArgs;

      for (size_t i = 0; i < ProfileNames.size(); ++i) {
        Constant *Str = ConstantDataArray::getString(Ctx, ProfileNames[i]);
        GlobalVariable *GV = new GlobalVariable(M, Str->getType(), true,
                                                GlobalValue::InternalLinkage,
                                                Str);
        GV->setUnnamedAddr(true);

        Constant* A[] = {
          ConstantInt::get(Int64Ty, 0),
          ConstantExpr::getPointerCast(GV, VoidPtrTy)
        };

        PfArrayArgs.push_back(ConstantStruct::get(PfItemTy, A));
      }

      GlobalVariable *PfArray =
          new GlobalVariable(M, PfArrayTy, false,
                             GlobalValue::PrivateLinkage,
                             ConstantArray::get(PfArrayTy, PfArrayArgs),
                             "__llvm__safestack_module_profile_table");

      ProfileTable->replaceAllUsesWith(
          ConstantExpr::getBitCast(PfArray, PfItemTy->getPointerTo()));
      ProfileTable->eraseFromParent();

      // Create ctor function
      Function *F = Function::Create(
          FunctionType::get(Type::getVoidTy(Ctx), false),
          GlobalValue::InternalLinkage, "__llvm__safestack_module_profile_ctor", &M);

      SmallVector<Value*, 2> Args;
      Args.push_back(ConstantExpr::getBitCast(PfArray, VoidPtrTy));
      Args.push_back(ConstantInt::get(Int64Ty, ProfileNames.size()));

      BasicBlock *BB = BasicBlock::Create(Ctx, Twine(), F);
      CallInst::Create(RegisterProfileTableFunc, Args, Twine(), BB);
      ReturnInst::Create(Ctx, BB);

      appendToGlobalCtors(M, F, 9999);

      return true;
    }
#else
    template<class _IRBuilder>
    Value *insertProfilePoint(_IRBuilder&, Instruction*,
                              Twine, Value* V = NULL) { return NULL; }
    template<typename _IRBuilder>
    void incrementProfilePoint(_IRBuilder&, Value*) {}
    bool doStatsInitialization(Module &M) { return false; }
    bool doStatsFinalization(Module &M) { return false; }
#endif
  };

} // end anonymous namespace

char SafeStackInserter::ID = 0;
INITIALIZE_PASS(SafeStackInserter, "safe-stack",
                "Safe Stack instrumentation pass", false, false)

Pass *llvm::createSafeStackInserterPass(const TargetLoweringBase *tli) {
  return new SafeStackInserter(tli);
}

bool SafeStackInserter::doPassInitialization(Module &M) {
  Type *Int8Ty = Type::getInt8Ty(M.getContext());
  unsigned AddressSpace, Offset;
  bool Changed = false;

  // Check where the unsafe stack pointer is stored on this architecture
  if (TLI->getUnsafeStackPtrLocation(AddressSpace, Offset)) {
    // The unsafe stack pointer is stored at a fixed location
    // (usually in the thread control block)
    Constant *OffsetVal =
      ConstantInt::get(Type::getInt32Ty(M.getContext()), Offset);

    UnsafeStackPtr = ConstantExpr::getIntToPtr(OffsetVal,
                        PointerType::get(Int8Ty->getPointerTo(), AddressSpace));
  } else {
    // The unsafe stack pointer is stored in a global variable with a magic name
    // FIXME: make the name start with "llvm."
    UnsafeStackPtr = dyn_cast_or_null<GlobalVariable>(
          M.getNamedValue("__llvm__unsafe_stack_ptr"));

    if (!UnsafeStackPtr) {
      // The global variable is not defined yet, define it ourselves
        UnsafeStackPtr = new GlobalVariable(
              /*Module=*/ M, /*Type=*/ Int8Ty->getPointerTo(),
              /*isConstant=*/ false, /*Linkage=*/ GlobalValue::ExternalLinkage,
              /*Initializer=*/ 0, /*Name=*/ "__llvm__unsafe_stack_ptr");

      cast<GlobalVariable>(UnsafeStackPtr)->setThreadLocal(true);

      // TODO: should we place the unsafe stack ptr global in a special section?
      // UnsafeStackPtr->setSection(".llvm.safestack");

      Changed = true;
    } else {
      // The variable exists, check its type and attributes
      if (UnsafeStackPtr->getType() != Int8Ty->getPointerTo()) {
        report_fatal_error("__llvm__unsafe_stack_ptr must have void* type");
      }

      if (!cast<GlobalVariable>(UnsafeStackPtr)->isThreadLocal()) {
        report_fatal_error("__llvm__unsafe_stack_ptr must be thread-local");
      }

      // TODO: check other attributes?
    }
  }

  Changed |= doStatsInitialization(M);
  return Changed;
}

static void PrintStat(raw_ostream &OS, Statistic &S) {
  OS << format("%8u %s - %s\n", S.getValue(), S.getName(), S.getDesc());
}

bool SafeStackInserter::doPassFinalization(Module &M) {
  bool Changed = doStatsFinalization(M);

  if (ShowStats) {
    outs() << "SafeStack Compilation Statistics:\n";

    PrintStat(outs(), NumFunctions);
    PrintStat(outs(), NumUnsafeStackFunctions);
    PrintStat(outs(), NumUnsafeStackRestorePointsFunctions);

    PrintStat(outs(), NumAllocas);
    PrintStat(outs(), NumUnsafeStaticAllocas);
    PrintStat(outs(), NumUnsafeDynamicAllocas);
    PrintStat(outs(), NumUnsafeStackRestorePoints);
  }

  return Changed;
}

bool SafeStackInserter::runOnFunction(Function &F) {
  ++NumFunctions;

  SmallVector<AllocaInst*, 16> StaticAlloca;
  SmallVector<AllocaInst*, 4> DynamicAlloca;
  SmallVector<ReturnInst*, 4> Returns;

  // Collect all points where stack gets unwinded and needs to be restored
  // This is only necessary because the runtime (setjmp and unwind code) is
  // not aware of the unsafe stack and won't unwind/restore it prorerly.
  // To work around this problem without changing the runtime, we insert
  // instrumentation to restore the unsafe stack pointer when necessary.
  SmallVector<Instruction*, 4> StackRestorePoints;

  Type *StackPtrTy = Type::getInt8PtrTy(F.getContext());
  Type *IntPtrTy = DL->getIntPtrType(F.getContext());
  Type *Int32Ty = Type::getInt32Ty(F.getContext());

  // Find all static and dynamic alloca instructions that must be moved to the
  // unsafe stack, all return instructions and stack restore points
  for (inst_iterator It = inst_begin(&F), Ie = inst_end(&F); It != Ie; ++It) {
    Instruction *I = &*It;

    if (AllocaInst *AI = dyn_cast<AllocaInst>(I)) {
      ++NumAllocas;

      if (IsSafeStackAlloca(AI, DL))
        continue;

      if (AI->isStaticAlloca()) {
        ++NumUnsafeStaticAllocas;
        StaticAlloca.push_back(AI);
      } else {
        ++NumUnsafeDynamicAllocas;
        DynamicAlloca.push_back(AI);
      }

    } else if (ReturnInst *RI = dyn_cast<ReturnInst>(I)) {
      Returns.push_back(RI);

    } else if (CallInst *CI = dyn_cast<CallInst>(I)) {
      // setjmps require stack restore
      if (CI->getCalledFunction() && CI->canReturnTwice())
          //CI->getCalledFunction()->getName() == "_setjmp")
        StackRestorePoints.push_back(CI);

    } else if (LandingPadInst *LP = dyn_cast<LandingPadInst>(I)) {
      // Excpetion landing pads require stack restore
      StackRestorePoints.push_back(LP);
    }
  }

  if (StaticAlloca.empty() && DynamicAlloca.empty() &&
      StackRestorePoints.empty())
    return false; // Nothing to do in this function

  if (!StaticAlloca.empty() || !DynamicAlloca.empty())
    ++NumUnsafeStackFunctions; // This function has the unsafe stack

  if (!StackRestorePoints.empty())
    ++NumUnsafeStackRestorePointsFunctions;

  IRBuilder<> IRB(F.getEntryBlock().getFirstInsertionPt());

  // The top of the unsafe stack after all unsafe static allocas are allocated
  Value *StaticTop = NULL;

  if (!StaticAlloca.empty()) {
    // We explicitly compute and set the unsafe stack layout for all unsafe
    // static alloca instructions. We safe the unsafe "base pointer" in the
    // prologue into a local variable and restore it in the epilogue.

    // Load the current stack pointer (we'll also use it as a base pointer)
    // FIXME: use a dedicated register for it ?
    Instruction *BasePointer = IRB.CreateLoad(UnsafeStackPtr, false,
                                              "unsafe_stack_ptr");
    assert(BasePointer->getType() == StackPtrTy);

    insertProfilePoint(IRB, IRB.GetInsertPoint(), "usp_load_prologue");

    for (SmallVectorImpl<ReturnInst*>::iterator It = Returns.begin(),
                                          Ie = Returns.end(); It != Ie; ++It) {
      IRB.SetInsertPoint(*It);
      IRB.CreateStore(BasePointer, UnsafeStackPtr);
      insertProfilePoint(IRB, *It, "usp_store_ret");
    }

    // Allocate space for every unsafe static AllocaInst on the unsafe stack
    int64_t StaticOffset = 0; // Current stack top
    for (SmallVectorImpl<AllocaInst*>::iterator It = StaticAlloca.begin(),
                                      Ie = StaticAlloca.end(); It != Ie; ++It) {
      AllocaInst *AI = *It;
      IRB.SetInsertPoint(AI);

      ConstantInt *CArraySize = cast<ConstantInt>(AI->getArraySize());
      Type *Ty = AI->getAllocatedType();

      uint64_t Size = DL->getTypeAllocSize(Ty) * CArraySize->getZExtValue();
      if (Size == 0) Size = 1; // Don't create zero-sized stack objects.

      // Ensure the object is properly aligned
      unsigned Align =
        std::max((unsigned)DL->getPrefTypeAlignment(Ty), AI->getAlignment());
      assert(Align <= UNSAFE_STACK_ALIGNMENT); // XXX: can it every happen?

      // Add alignment
      StaticOffset += Size;
      StaticOffset = (StaticOffset + Align - 1) / Align * Align;

      Value *Off = IRB.CreateGEP(BasePointer, // BasePointer is i8*
                      ConstantInt::get(Int32Ty, -StaticOffset));
      Value *NewAI = IRB.CreateBitCast(Off, AI->getType(), AI->getName());
      if (AI->hasName() && isa<Instruction>(NewAI))
        cast<Instruction>(NewAI)->takeName(AI);

      // Replace alloc with the new location
      AI->replaceAllUsesWith(NewAI);
      AI->eraseFromParent();
    }

    // Re-align BasePointer so that our callees would see it aligned as expected
    // FIXME: no need to update BasePointer in leaf functions
    StaticOffset = (StaticOffset + UNSAFE_STACK_ALIGNMENT - 1)
                    / UNSAFE_STACK_ALIGNMENT * UNSAFE_STACK_ALIGNMENT;

    // Update shadow stack pointer in the function epilogue
    IRB.SetInsertPoint(cast<Instruction>(BasePointer->getNextNode()));

    StaticTop = IRB.CreateGEP(BasePointer,
           ConstantInt::get(Int32Ty, -StaticOffset), "unsafe_stack_static_top");
    IRB.CreateStore(StaticTop, UnsafeStackPtr);
  }

  IRB.SetInsertPoint(
          StaticTop ? cast<Instruction>(StaticTop)->getNextNode()
                    : (Instruction*) F.getEntryBlock().getFirstInsertionPt());

  // Safe stack object that stores the current unsafe stack top. It is updated
  // as unsafe dynamic (non-constant-sized) allocas are allocated and freed.
  // This is only needed if we need to restore stack pointer after longjmp
  // or exceptions.
  // FIXME: a better alternative is to store the unsafe stack pointer before
  // setjmp / invoke instructions.
  AllocaInst *DynamicTop = NULL;

  if (!StackRestorePoints.empty()) {
    // We need the current value of the shadow stack pointer to restore
    // after longjmp or exception catching.

    // XXX: in the future, this should be handled by the longjmp/exception
    // runtime itself

    if (!DynamicAlloca.empty()) {
      // If we also have dynamic alloca's, the stack pointer value changes
      // throughout the function. For now we store it in an allca.
      DynamicTop = IRB.CreateAlloca(StackPtrTy, 0, "unsafe_stack_dynamic_ptr");
    }

    if (!StaticTop) {
      // We need to original unsafe stack pointer value, even if there are
      // no unsafe static allocas
      StaticTop = IRB.CreateLoad(UnsafeStackPtr, false, "unsafe_stack_ptr");
      insertProfilePoint(IRB, IRB.GetInsertPoint(), "static_top_load");
    }

    if (!DynamicAlloca.empty()) {
      IRB.CreateStore(StaticTop, DynamicTop);
      insertProfilePoint(IRB, DynamicTop, "dsp_store_prologue");
    }
  }

  // Handle dynamic alloca now
  for (SmallVectorImpl<AllocaInst*>::iterator It = DynamicAlloca.begin(),
                                    Ie = DynamicAlloca.end(); It != Ie; ++It) {
    AllocaInst *AI = *It;
    IRB.SetInsertPoint(AI);

    // Compute the new SP value (after AI)
    Value *ArraySize = AI->getArraySize();
    if (ArraySize->getType() != IntPtrTy)
      ArraySize = IRB.CreateIntCast(ArraySize, IntPtrTy, false);

    Type *Ty = AI->getAllocatedType();
    uint64_t TySize = DL->getTypeAllocSize(Ty);
    Value *Size = IRB.CreateMul(ArraySize, ConstantInt::get(IntPtrTy, TySize));

    Value *SP = IRB.CreatePtrToInt(IRB.CreateLoad(UnsafeStackPtr), IntPtrTy);
    SP = IRB.CreateSub(SP, Size);
    insertProfilePoint(IRB, IRB.GetInsertPoint(), "usp_update_dynalloc");

    // Align the SP value to satisfy the AllocaInst, type and stack alignments
    unsigned Align = std::max(
      std::max((unsigned)DL->getPrefTypeAlignment(Ty), AI->getAlignment()),
      (unsigned) UNSAFE_STACK_ALIGNMENT);

    assert(isPowerOf2_32(Align));
    Value *NewTop = IRB.CreateIntToPtr(
        IRB.CreateAnd(SP, ConstantInt::get(IntPtrTy, ~uint64_t(Align-1))),
        StackPtrTy);

    // Save the stack pointer
    IRB.CreateStore(NewTop, UnsafeStackPtr);
    if (DynamicTop) {
      IRB.CreateStore(NewTop, DynamicTop);
      insertProfilePoint(IRB, IRB.GetInsertPoint(), "dsp_update_dynalloc");
    }

    Value *NewAI = IRB.CreateIntToPtr(SP, AI->getType());
    if (AI->hasName() && isa<Instruction>(NewAI))
      NewAI->takeName(AI);

    AI->replaceAllUsesWith(NewAI);
    AI->eraseFromParent();
  }

  if (!DynamicAlloca.empty()) {
    // Now go through the instructions again, replacing stacksave/stackrestore
    for (inst_iterator It = inst_begin(&F), Ie = inst_end(&F); It != Ie;) {
      Instruction *I = &*(It++);
      IntrinsicInst *II = dyn_cast<IntrinsicInst>(I);
      if (!II)
        continue;

      if (II->getIntrinsicID() == Intrinsic::stacksave) {
        IRB.SetInsertPoint(II);
        Instruction *LI = IRB.CreateLoad(UnsafeStackPtr);
        insertProfilePoint(IRB, II, "usp_load_stacksave");
        LI->takeName(II);
        II->replaceAllUsesWith(LI);
        II->eraseFromParent();
      } else if (II->getIntrinsicID() == Intrinsic::stackrestore) {
        IRB.SetInsertPoint(II);
        Instruction *SI = IRB.CreateStore(II->getArgOperand(0), UnsafeStackPtr);
        insertProfilePoint(IRB, II, "usp_store_stackrestore");
        SI->takeName(II);
        assert(II->use_empty());
        II->eraseFromParent();
      }
    }
  }

  // Restore current stack pointer after longjmp/exception catch
  for (SmallVectorImpl<Instruction*>::iterator I = StackRestorePoints.begin(),
                                    E = StackRestorePoints.end(); I != E; ++I) {
    ++NumUnsafeStackRestorePoints;

    IRB.SetInsertPoint(cast<Instruction>((*I)->getNextNode()));
    Value *CurrentTop = DynamicTop ? IRB.CreateLoad(DynamicTop) : StaticTop;
    IRB.CreateStore(CurrentTop, UnsafeStackPtr);
    insertProfilePoint(IRB, *I, "usp_store_rpoint");
  }

  return true;
}

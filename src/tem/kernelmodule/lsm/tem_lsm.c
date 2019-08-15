#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <uapi/asm-generic/mman-common.h>
#include <linux/kallsyms.h>

#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nuno O. Duarte");
MODULE_AUTHOR("Anjo Vahldiek-Oberwagner");
MODULE_DESCRIPTION("LSM module to restrict access to create executable memory to trusted components (defined by ERIM)");
MODULE_VERSION("0.1");

#define __rdpkru()                              \
  ({                                            \
    unsigned int eax, edx;                      \
    unsigned int ecx = 0;                       \
    unsigned int pkru;                          \
    asm volatile(".byte 0x0f,0x01,0xee\n\t"     \
                 : "=a" (eax), "=d" (edx)       \
                 : "c" (ecx));                  \
    pkru = eax;                                 \
    pkru;                                       \
  })
#define ERIM_TRUSTED_PKRU (0x55555550)
#define isTrustedComponent (__rdpkru() == ERIM_TRUSTED_PKRU) ? 1 : 0

static int mmap_alter_prot_impl(struct file *mmap_file, unsigned long *prot, vm_flags_t *vm_flags)
{
  if(current->erim == 1 && *prot & PROT_EXEC && !isTrustedComponent) {
    *prot = *prot & ~PROT_EXEC;
  }
  return 0;
}

static int file_mprotect_alter_prot_impl(struct vm_area_struct *vma, unsigned long reqprot, unsigned long * prot)
{

  if(current->erim == 1 && (reqprot & VM_EXEC) && !(vma->vm_flags & VM_EXEC) && !isTrustedComponent) {
    *prot = *prot & ~PROT_EXEC;
  }
  return 0;
}


static int check_signal_impl(int sig, struct k_sigaction *act) {

  if(current->erim == 1 && sig == SIGSEGV && !isTrustedComponent) {
      return -EPERM;
  }
  return 0;
}


static struct security_hook_list tem_hooks[] = {
  LSM_HOOK_INIT(mmap_alter_prot, mmap_alter_prot_impl),
  LSM_HOOK_INIT(file_mprotect_alter_prot, file_mprotect_alter_prot_impl),
  LSM_HOOK_INIT(check_signal, check_signal_impl),
};


static int __init tem_lsm_init(void){
  security_add_hooks(tem_hooks, ARRAY_SIZE(tem_hooks));
  printk(KERN_INFO "tem LSM: Module initialized!\n");
  return 0;
}


static void __exit tem_lsm_exit(void){
  security_delete_hooks(tem_hooks, ARRAY_SIZE(tem_hooks));
  printk(KERN_INFO "TEM LSM: Module terminated!\n");
}


module_init(tem_lsm_init);
module_exit(tem_lsm_exit);

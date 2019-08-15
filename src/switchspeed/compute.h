#ifndef __COMPUTE_H_
#define __COMPUTE_H_

// DEFINE BEFORE INCLUDING!!!
#ifndef COMPUTE_IT
#define COMPUTE_IT 3
#endif

#define COMPUTE_ALLOC 	int _compute_h_f[COMPUTE_IT+1]

#define COMPUTE_INIT  \
{	\
	int __c_it = 0;\
	for (__c_it = 0; __c_it < COMPUTE_IT+1; __c_it++)\
		_compute_h_f[__c_it] = __c_it; \
}

#define COMPUTE_ADD					\
  {							\
    int __c_it =0;					\
    for (__c_it = 0; __c_it < COMPUTE_IT; __c_it++) {	\
      _compute_h_f[__c_it]++;					\
    }							\
  }

#define COMPUTE_DEP					\
  {							\
    int __c_it =0;					\
    for (__c_it = 1; __c_it < COMPUTE_IT+1; __c_it++) {	\
      _compute_h_f[__c_it]+=_compute_h_f[__c_it-1];				\
    }							\
  }

#define COMPUTE COMPUTE_DEP

#endif

#define SIGSEGV_EXC_STATE_TYPE i386_exception_state_t
#define SIGSEGV_EXC_STATE_FLAVOR i386_EXCEPTION_STATE
#define SIGSEGV_EXC_STATE_COUNT i386_EXCEPTION_STATE_COUNT
#define SIGSEGV_EXC_STATE_FAULT(exc_state) (exc_state).faultvaddr
#define SIGSEGV_THREAD_STATE_TYPE i386_thread_state_t
#define SIGSEGV_THREAD_STATE_FLAVOR i386_THREAD_STATE
#define SIGSEGV_THREAD_STATE_COUNT i386_THREAD_STATE_COUNT
#define SIGSEGV_STACK_POINTER(thr_state) (thr_state).esp
#define SIGSEGV_PROGRAM_COUNTER(thr_state) (thr_state).eip

/* Adjust stack pointer so we can push an arg */
INLINE unsigned long fix_stack_ptr(unsigned long sp)
{
	  return sp - (sp & 0xf);
}

INLINE void pass_arg0(SIGSEGV_THREAD_STATE_TYPE *thr_state, CELL arg)
{
	*(CELL *)thr_state->esp = arg;
	thr_state->esp -= CELLS;
}
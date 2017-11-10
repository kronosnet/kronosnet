/* Repeated inclusions define this differently */
#undef REMAP_PROTO

#ifdef CANARY

/* Canary uses fake prototype to make "calls" uniform */
#ifdef CANARY_CALL
#define REMAP_PROTO(ret,name,args) name() +
#else
#define REMAP_PROTO(ret,name,args) char name(void);
#endif /* CANARY_CALL */

#else
#define REMAP_PROTO(ret,name,args) ret (*_int_ ## name)args;

#endif /* CANARY */

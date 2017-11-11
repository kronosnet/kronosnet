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

#ifdef REMAP_FAIL
#define REMAP_PROTO(ret,name,args) _int_ ## name = NULL;
#else
#ifdef REMAP_WITH
#define REMAP_PROTO(ret,name,args) if (!(_int_ ## name = REMAP_WITH(#name))) goto fail;
#else
/* Provide the plain prototype as well for validation */
#define REMAP_PROTO(ret,name,args) ret (*_int_ ## name)args; \
				   ret name args;
#endif /* REMAP_WITH */
#endif /* REMAP_FAIL */

#endif /* CANARY */

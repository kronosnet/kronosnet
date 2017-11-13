#include "remap.h"

/*
 * nss3
 */
REMAP_PROTO(CK_MECHANISM_TYPE,PK11_GetBestWrapMechanism,(PK11SlotInfo *slot))
REMAP_PROTO(PK11SlotInfo *,PK11_GetBestSlot,
            (CK_MECHANISM_TYPE type, void *wincx))
REMAP_PROTO(int,PK11_GetBestKeyLength,
            (PK11SlotInfo *slot, CK_MECHANISM_TYPE type))
REMAP_PROTO(SECStatus,PK11_DigestFinal,
            (PK11Context *context, unsigned char *data,
             unsigned int *outLen, unsigned int length))
REMAP_PROTO(void,SECITEM_FreeItem,(SECItem *zap, PRBool freeit))
REMAP_PROTO(SECStatus,NSS_NoDB_Init,(const char *configdir))
REMAP_PROTO(SECStatus,NSS_Shutdown,(void))
REMAP_PROTO(SECStatus,PK11_DigestBegin,(PK11Context *cx))
REMAP_PROTO(SECStatus,PK11_DigestOp,
            (PK11Context *context, const unsigned char *in, unsigned len))
REMAP_PROTO(void,PK11_DestroyContext,(PK11Context *context, PRBool freeit))
REMAP_PROTO(SECStatus,PK11_Finalize,(PK11Context *context))
REMAP_PROTO(SECStatus,PK11_CipherOp,
            (PK11Context *context, unsigned char *out, int *outlen,
             int maxout, const unsigned char *in, int inlen))
REMAP_PROTO(PK11SymKey *,PK11_UnwrapSymKey,
            (PK11SymKey *key, CK_MECHANISM_TYPE wraptype, SECItem *param,
             SECItem *wrapppedKey, CK_MECHANISM_TYPE target,
             CK_ATTRIBUTE_TYPE operation, int keySize))
REMAP_PROTO(void,PK11_FreeSymKey,(PK11SymKey *key))
REMAP_PROTO(PK11Context *,PK11_CreateContextBySymKey,
            (CK_MECHANISM_TYPE type,
             CK_ATTRIBUTE_TYPE operation,
             PK11SymKey *symKey, SECItem *param))
REMAP_PROTO(SECStatus,PK11_GenerateRandom,(unsigned char *data, int len))
REMAP_PROTO(SECItem *,PK11_ParamFromIV,(CK_MECHANISM_TYPE type, SECItem *iv))
REMAP_PROTO(void,PK11_FreeSlot,(PK11SlotInfo *slot))
REMAP_PROTO(int,PK11_GetBlockSize,(CK_MECHANISM_TYPE type, SECItem *params))
REMAP_PROTO(PK11SymKey *,PK11_KeyGen,
            (PK11SlotInfo *slot, CK_MECHANISM_TYPE type,
             SECItem *param, int keySize, void *wincx))

/*
 * nspr4
 */
REMAP_PROTO(PRStatus,PR_Cleanup,(void))
REMAP_PROTO(const char *,PR_ErrorToString,
            (PRErrorCode code, PRLanguageCode language))
REMAP_PROTO(PRErrorCode,PR_GetError,(void))
REMAP_PROTO(PRBool,PR_Initialized,(void))

/*
 * plds4
 */
REMAP_PROTO(void,PL_ArenaFinish,(void))

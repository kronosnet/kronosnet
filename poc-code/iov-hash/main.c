/* Example code to illustrate DES enccryption/decryption using NSS.
 * The example skips the details of obtaining the Key & IV to use, and
 * just uses a hardcoded Key & IV.
 * Note: IV is only needed if Cipher Blocking Chaining (CBC) mode of encryption
 *       is used
 *
 * The recommended approach is to store and transport WRAPPED (encrypted)
 * DES Keys (IVs can be in the clear). However, it is a common (and dangerous)
 * practice to use raw DES Keys. This example shows the use of a RAW key.
 */


#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <blapit.h>

/* example Key & IV */
unsigned char gKey[] = {0xe8, 0xa7, 0x7c, 0xe2, 0x05, 0x63, 0x6a, 0x31};
unsigned char gIV[] = {0xe4, 0xbb, 0x3b, 0xd3, 0xc3, 0x71, 0x2e, 0x58};

int main(int argc, char **argv)
{
  CK_MECHANISM_TYPE  hashMech;
  PK11SlotInfo*      slot = NULL;
  PK11SymKey*        SymKey = NULL;
  SECItem            SecParam;
  PK11Context*       HashContext = NULL;
  SECItem            keyItem;
  SECStatus          rv, rv1, rv2;
  unsigned char      buf1[1024], buf2[1024];
  char		     data[1024];
  unsigned int	     i;
  unsigned int       tmp2_outlen;

  /* Initialize NSS
 *    * If your application code has already initialized NSS, you can skip it
 *       * here.
 *          * This code uses the simplest of the Init functions, which does not
 *             * require a NSS database to exist
 *                */
  rv = NSS_NoDB_Init(".");
  if (rv != SECSuccess)
  {
    fprintf(stderr, "NSS initialization failed (err %d)\n",
            PR_GetError());
    goto out;
  }

  /* choose mechanism: CKM_DES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC..... 
 *    * Note that some mechanisms (*_PAD) imply the padding is handled for you
 *       * by NSS. If you choose something else, then data padding is the
 *          * application's responsibility
 *             */
  hashMech = CKM_SHA_1_HMAC;
  slot = PK11_GetBestSlot(hashMech, NULL);
  /* slot = PK11_GetInternalKeySlot(); is a simpler alternative but in
 *    * theory, it *may not* return the optimal slot for the operation. For
 *       * DES ops, Internal slot is typically the best slot
 *          */
  if (slot == NULL)
  {
    fprintf(stderr, "Unable to find security device (err %d)\n",
            PR_GetError());
    goto out;
  }

  /* NSS passes blobs around as SECItems. These contain a pointer to
 *    * data and a length. Turn the raw key into a SECItem. */
  keyItem.type = siBuffer;
  keyItem.data = gKey;
  keyItem.len = sizeof(gKey);

  /* Turn the raw key into a key object. We use PK11_OriginUnwrap
 *    * to indicate the key was unwrapped - which is what should be done
 *       * normally anyway - using raw keys isn't a good idea */
  SymKey = PK11_ImportSymKey(slot, hashMech, PK11_OriginUnwrap, CKA_SIGN,
                             &keyItem, NULL);
  if (SymKey == NULL)
  {
    fprintf(stderr, "Failure to import key into NSS (err %d)\n",
            PR_GetError());
    goto out;
  }

  SecParam.type = siBuffer;
  SecParam.data = 0;
  SecParam.len = 0;

  /* sample data we'll hash */
  strcpy(data, "Hash me!");
  fprintf(stderr, "Clear Data: %s\n", data);

  /* ========================= START SECTION ============================= */
  /* If using the the same key and iv over and over, stuff before this     */
  /* section and after this section needs to be done only ONCE             */

  /* Create cipher context */
  HashContext = PK11_CreateContextBySymKey(hashMech, CKA_SIGN,
                                          SymKey, &SecParam);

  if (!HashContext) {
    fprintf(stderr, "no hash context today?\n");
    goto out;
  }

  if (PK11_DigestBegin(HashContext) != SECSuccess) {
    fprintf(stderr, "hash doesn't begin?\n");
    goto out;
  }

  rv1 = PK11_DigestOp(HashContext, (unsigned char *)data, strlen(data)+1);

  rv2 = PK11_DigestFinal(HashContext, buf2, &tmp2_outlen, SHA1_BLOCK_LENGTH);

  PK11_DestroyContext(HashContext, PR_TRUE);
  if (rv1 != SECSuccess || rv2 != SECSuccess)
    goto out;

  fprintf(stderr, "Hash Data: ");
  for (i=0; i<tmp2_outlen; i++)
    fprintf(stderr, "%02x ", buf2[i]);
  fprintf(stderr, "\n");

  /* =========================== END SECTION ============================= */

  /* ========================= START SECTION ============================= */
  /* If using the the same key and iv over and over, stuff before this     */
  /* section and after this section needs to be done only ONCE             */

  memset(buf1, 0, sizeof(buf1));
  memset(buf2, 0, sizeof(buf2));

  /* Create cipher context */
  HashContext = PK11_CreateContextBySymKey(hashMech, CKA_SIGN,
                                          SymKey, &SecParam);

  if (!HashContext) {
    fprintf(stderr, "no hash context today?\n");
    goto out;
  }

  if (PK11_DigestBegin(HashContext) != SECSuccess) {
    fprintf(stderr, "hash doesn't begin?\n");
    goto out;
  }

  rv1 = PK11_DigestOp(HashContext, (unsigned char *)data, 5);
  rv1 = PK11_DigestOp(HashContext, (unsigned char *)data+5, 4);

  rv2 = PK11_DigestFinal(HashContext, buf2, &tmp2_outlen, SHA1_BLOCK_LENGTH);

  PK11_DestroyContext(HashContext, PR_TRUE);
  if (rv1 != SECSuccess || rv2 != SECSuccess)
    goto out;

  fprintf(stderr, "Hash Data: ");
  for (i=0; i<tmp2_outlen; i++)
    fprintf(stderr, "%02x ", buf2[i]);
  fprintf(stderr, "\n");

  /* =========================== END SECTION ============================= */

 
out:
  if (SymKey)
    PK11_FreeSymKey(SymKey);

 return 0;

}

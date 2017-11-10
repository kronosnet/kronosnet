/* Transform the binary into dependencies like:
 * dpkg-shlibdeps -pcrypto -dRecommends -xlibc6 -elibknet/crypto_canary -O | sed 's/,/ |/g' >>debian/substvars
 */

#include "config.h"

char NSS_NoDB_Init(void);
char EVP_EncryptInit_ex(void);

int main (void)
{
  return
#ifdef BUILDCRYPTONSS
    NSS_NoDB_Init() +
#endif
#ifdef BUILDCRYPTOOPENSSL
    EVP_EncryptInit_ex() +
#endif
    0;
}

/* Transform the binary into dependencies like:
 * dpkg-shlibdeps -pcrypto -dRecommends -xlibc6 -elibknet/crypto_canary -O | sed 's/,/ |/g' >>debian/substvars
 */

#include "config.h"

#define CANARY

#include "crypto_nss_remap.h"
#include "crypto_openssl_remap.h"

#define CANARY_CALL

int main (void)
{
  return
#ifdef BUILDCRYPTONSS
#include "crypto_nss_remap.h"
#endif
#ifdef BUILDCRYPTOOPENSSL
#include "crypto_openssl_remap.h"
#endif
    0;
}

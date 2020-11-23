#ifndef __CORE_UTILS_SLIP10_H__
#define __CORE_UTILS_SLIP10_H__

#include <stdint.h>

#define BIP32_HARDENED (1UL << 31)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets bip32 path from string
 *
 * @param[in] str A bip32 path string
 * @param[out] path The output path
 * @return int 0 on successful
 */
int slip10_parse_path(char str[], uint32_t path[]);

#ifdef __cplusplus
}
#endif

#endif

#ifndef TLSN_MOBILE_H
#define TLSN_MOBILE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t tlsn_mobile_abi_version(void);
char *tlsn_mobile_create_evidence(const char *request_json);
typedef void (*tlsn_mobile_callback)(void *context, char *result_json);
uint64_t tlsn_mobile_notarize(
    const char *request_json,
    tlsn_mobile_callback callback,
    void *context
);
void tlsn_mobile_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif

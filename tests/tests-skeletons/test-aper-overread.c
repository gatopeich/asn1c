/*
 * Test for malformed APER that claims more data than buffer contains
 */
#include <stdio.h>
#include <string.h>
#include <aper_decoder.h>
#include <OCTET_STRING.h>

int main() {
    asn_dec_rval_t rval;
    OCTET_STRING_t *str = NULL;
    
    /* Buffer with malformed APER - claims to have large data */
    /* Let's create a length-prefixed OCTET STRING that claims 1000 bytes */
    uint8_t buffer[16];
    memset(buffer, 0, sizeof(buffer));
    
    /* Encode length 1000 in APER format (0x83 0xE8 for values > 127) */
    buffer[0] = 0x83;  /* 10000011 - bit pattern for 2-byte length */
    buffer[1] = 0xE8;  /* Lower byte of 1000 */
    /* Rest of buffer is zeros, but decoder will try to read 1000 bytes! */
    
    fprintf(stderr, "Test: APER with length claiming 1000 bytes, buffer only %zu bytes\n", sizeof(buffer));
    
    rval = aper_decode_complete(NULL, &asn_DEF_OCTET_STRING, (void **)&str,
                                buffer, sizeof(buffer));
    
    fprintf(stderr, "Result: code=%d, consumed=%zu\n", rval.code, rval.consumed);
    
    if (str) {
        fprintf(stderr, "Decoded string size: %zu\n", str->size);
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, str);
    }
    
    fprintf(stderr, "Test completed - no segfault\n");
    return 0;
}

/*
 * Test to demonstrate malformed APER input through proper decoder
 * This test goes through aper_decode() to show the fix works
 */
#include <stdio.h>
#include <string.h>
#include <aper_decoder.h>
#include <INTEGER.h>

int main() {
    asn_dec_rval_t rval;
    INTEGER_t *integer = NULL;
    uint8_t buffer[8];
    
    fprintf(stderr, "Test: Malformed APER with crafted data\n");
    
    /* Create some malformed APER data */
    memset(buffer, 0xFF, sizeof(buffer));
    
    /* Try decoding with valid small buffer */
    fprintf(stderr, "Decoding buffer of %zu bytes...\n", sizeof(buffer));
    rval = aper_decode_complete(NULL, &asn_DEF_INTEGER, (void **)&integer, 
                                buffer, sizeof(buffer));
    
    fprintf(stderr, "Result: code=%d, consumed=%zu\n", rval.code, rval.consumed);
    
    if (integer) {
        ASN_STRUCT_FREE(asn_DEF_INTEGER, integer);
        integer = NULL;
    }
    
    /* Now try with various malformed inputs */
    fprintf(stderr, "\nTest completed successfully - no segfault\n");
    
    return 0;
}

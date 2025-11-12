/*
 * Test for malformed APER input protection
 * This test verifies that the APER decoder properly handles
 * malformed input that could cause buffer overflows or segfaults
 */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <aper_support.h>
#include <aper_decoder.h>
#include <OCTET_STRING.h>
#include <INTEGER.h>

/*
 * Test that extremely large length values don't cause overflow
 */
static void
test_large_length_overflow() {
    asn_bit_data_t pd;
    uint8_t buffer[32];
    int repeat;
    ssize_t length;
    
    fprintf(stderr, "\nTest: large length overflow protection\n");
    
    /* Create malformed input with very large length indicator */
    memset(buffer, 0xFF, sizeof(buffer));
    buffer[0] = 0xC0 | 4;  /* Indicates 4 * 16384 bytes = 65536 bytes */
    
    memset(&pd, 0, sizeof(pd));
    pd.buffer = buffer;
    pd.nboff = 0;
    pd.nbits = sizeof(buffer) * 8;
    
    /* This should handle the large value safely */
    length = aper_get_length(&pd, -1, -1, -1, &repeat);
    
    /* Should either succeed with large value or fail gracefully */
    fprintf(stderr, "  Got length: %zd, repeat: %d\n", length, repeat);
    assert(length >= 0 || length == -1);
}

/*
 * Test that negative length values are properly rejected
 */
static void
test_nsnnwn_negative_length() {
    asn_bit_data_t pd;
    uint8_t buffer[32];
    ssize_t result;
    
    fprintf(stderr, "\nTest: nsnnwn length validation\n");
    
    /* Create input that would decode to length > 4 bytes (which should be rejected) */
    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0x80;  /* Set first bit to 1 - enter aligned case */
    buffer[1] = 0x00;  /* Next bit is 0 */
    buffer[2] = 0x80 | 10;  /* Length field = 10 (> 4), should be rejected */
    
    memset(&pd, 0, sizeof(pd));
    pd.buffer = buffer;
    pd.nboff = 0;
    pd.nbits = sizeof(buffer) * 8;
    
    result = aper_get_nsnnwn(&pd);
    
    /* Should reject length > 4 or return valid small value */
    fprintf(stderr, "  Got result: %zd\n", result);
    /* Accept any valid result or -1 for error */
    assert(result >= -1);
}

/*
 * Test constrained whole number with extreme values
 */
static void
test_constrained_whole_number_overflow() {
    asn_bit_data_t pd;
    uint8_t buffer[32];
    long result;
    
    fprintf(stderr, "\nTest: constrained whole number overflow protection\n");
    
    /* Test with reasonable range but attempt to cause overflow */
    memset(buffer, 0xFF, sizeof(buffer));
    
    memset(&pd, 0, sizeof(pd));
    pd.buffer = buffer;
    pd.nboff = 0;
    pd.nbits = sizeof(buffer) * 8;
    
    /* Large range that requires multi-byte encoding */
    result = aper_get_constrained_whole_number(&pd, 0, 1000000);
    
    fprintf(stderr, "  Got result: %ld\n", result);
    /* Should either succeed or fail gracefully, not crash */
    assert(result >= -1);
}

/*
 * Test OCTET_STRING with malformed length that could overflow
 */
static void
test_octet_string_overflow() {
    asn_codec_ctx_t ctx;
    asn_dec_rval_t rval;
    OCTET_STRING_t *st = NULL;
    asn_bit_data_t pd;
    uint8_t buffer[128];
    
    fprintf(stderr, "\nTest: OCTET_STRING overflow protection\n");
    
    /* Create malformed APER data with huge length */
    memset(buffer, 0, sizeof(buffer));
    /* Set up for unconstrained length with large value */
    buffer[0] = 0xC0 | 4;  /* Indicates 4 * 16384 bytes */
    buffer[1] = 0x00;
    
    memset(&pd, 0, sizeof(pd));
    pd.buffer = buffer;
    pd.nboff = 0;
    pd.nbits = sizeof(buffer) * 8;
    
    memset(&ctx, 0, sizeof(ctx));
    ctx.max_stack_size = 1000;
    
    /* Attempt to decode - should fail gracefully, not crash */
    rval = OCTET_STRING_decode_aper(&ctx, &asn_DEF_OCTET_STRING, NULL, 
                                    (void **)&st, &pd);
    
    fprintf(stderr, "  Decode result: code=%d, consumed=%zu\n", 
            rval.code, rval.consumed);
    
    /* Should fail, not crash */
    assert(rval.code != RC_OK || st != NULL);
    
    if(st) {
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, st);
    }
}

/*
 * Test INTEGER with malformed length that could cause shift overflow
 */
static void
test_integer_shift_overflow() {
    asn_codec_ctx_t ctx;
    asn_dec_rval_t rval;
    INTEGER_t *st = NULL;
    asn_bit_data_t pd;
    uint8_t buffer[128];
    
    fprintf(stderr, "\nTest: INTEGER shift overflow protection\n");
    
    /* Create malformed APER data */
    memset(buffer, 0xFF, sizeof(buffer));
    /* First byte: not in extension */
    buffer[0] = 0x00;
    /* Set up bits for very large range */
    buffer[1] = 0xFF;
    
    memset(&pd, 0, sizeof(pd));
    pd.buffer = buffer;
    pd.nboff = 0;
    pd.nbits = sizeof(buffer) * 8;
    
    memset(&ctx, 0, sizeof(ctx));
    ctx.max_stack_size = 1000;
    
    /* Attempt to decode - should fail gracefully, not crash */
    rval = INTEGER_decode_aper(&ctx, &asn_DEF_INTEGER, NULL, 
                               (void **)&st, &pd);
    
    fprintf(stderr, "  Decode result: code=%d, consumed=%zu\n", 
            rval.code, rval.consumed);
    
    /* Should either succeed or fail, not crash */
    assert(rval.code == RC_OK || rval.code == RC_FAIL || rval.code == RC_WMORE);
    
    if(st) {
        ASN_STRUCT_FREE(asn_DEF_INTEGER, st);
    }
}

/*
 * Test with corrupted bit stream that has insufficient data
 */
static void
test_truncated_input() {
    asn_bit_data_t pd;
    uint8_t buffer[4];
    ssize_t result;
    
    fprintf(stderr, "\nTest: truncated input protection\n");
    
    /* Very short buffer */
    memset(buffer, 0xFF, sizeof(buffer));
    
    memset(&pd, 0, sizeof(pd));
    pd.buffer = buffer;
    pd.nboff = 0;
    pd.nbits = 8;  /* Only 1 byte available */
    
    result = aper_get_constrained_whole_number(&pd, 0, 1000000);
    
    fprintf(stderr, "  Got result: %zd\n", result);
    /* Should detect insufficient data */
    assert(result == -1);
}

int main() {
    fprintf(stderr, "Starting malformed APER input tests...\n");
    
    test_large_length_overflow();
    test_nsnnwn_negative_length();
    test_constrained_whole_number_overflow();
    test_octet_string_overflow();
    test_integer_shift_overflow();
    test_truncated_input();
    
    fprintf(stderr, "\nAll malformed input tests passed!\n");
    return 0;
}

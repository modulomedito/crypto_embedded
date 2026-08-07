/*============================================================================*/
/**
 * @file       crypto_aes_test.c
 * @brief      AES algorithm tests (Unity framework)
 * @copyright  Copyright (C) 2026. MIT License.
 */
/*============================================================================*/
#include "unity.h"
#include "crypto_aes.h"
#include <string.h>

/*============================================================================*/
/* KAT VECTORS (FIPS-197 / SP 800-38A) */
/*============================================================================*/
// 128-bit ECB Encrypt: 64 bytes plain, 16 bytes key → 80 bytes cipher (+pad)
static const uint8_t kat_128_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};
static const uint8_t kat_128_plain[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};
static const uint8_t kat_128_cipher[80] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
    0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
    0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
    0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
    0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
    0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
    0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,
    0xa2, 0x54, 0xbe, 0x88, 0xe0, 0x37, 0xdd, 0xd9,
    0xd7, 0x9f, 0xb6, 0x41, 0x1c, 0x3f, 0x9d, 0xf8,
};
// 192-bit key
static const uint8_t kat_192_key[24] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};
static const uint8_t kat_192_cipher[32] = {
    0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
    0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
    0xda, 0xa0, 0xaf, 0x07, 0x4b, 0xd8, 0x08, 0x3c,
    0x8a, 0x32, 0xd4, 0xfc, 0x56, 0x3c, 0x55, 0xcc,
};
// 256-bit key
static const uint8_t kat_256_key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};
static const uint8_t kat_256_cipher[32] = {
    0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
    0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
    0x4c, 0x45, 0xdf, 0xb3, 0xb3, 0xb4, 0x84, 0xec,
    0x35, 0xb0, 0x51, 0x2d, 0xc8, 0xc1, 0xc4, 0xd6,
};
// CBC test vectors (SP 800-38A F.2.1)
static const uint8_t cbc_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t cbc_128_cipher[64] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
    0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
    0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
    0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
};
// CTR test vectors (SP 800-38A F.5.1)
static const uint8_t ctr_iv[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};
static const uint8_t ctr_128_cipher[64] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
    0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
    0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
    0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
    0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
    0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
    0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
};

/*============================================================================*/
/* HELPER MACROS */
/*============================================================================*/
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

/*============================================================================*/
/* SYNC ECB KAT (migrated from crypto_aes_test.h) */
/*============================================================================*/
void test_aes_ecb_enc_128(void)
{
    uint8_t cipher[80] = {0};
    crypto_aes_Ret ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        kat_128_plain, sizeof(kat_128_plain),
        kat_128_key, sizeof(kat_128_key),
        NULL, 0, cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_cipher, cipher, sizeof(kat_128_cipher));
}

void test_aes_ecb_dec_128(void)
{
    uint8_t plain[64] = {0};
    crypto_aes_Ret ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        kat_128_cipher, sizeof(kat_128_cipher),
        kat_128_key, sizeof(kat_128_key),
        NULL, 0, plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_plain, plain, sizeof(kat_128_plain));
}

void test_aes_ecb_enc_192(void)
{
    uint8_t cipher[32] = {0};
    crypto_aes_Ret ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_192, crypto_aes_Mode_Ecb,
        kat_128_plain, 16, /* 1 block */
        kat_192_key, sizeof(kat_192_key),
        NULL, 0, cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_192_cipher, cipher, sizeof(kat_192_cipher));
}

void test_aes_ecb_dec_192(void)
{
    uint8_t plain[16] = {0};
    crypto_aes_Ret ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_192, crypto_aes_Mode_Ecb,
        kat_192_cipher, sizeof(kat_192_cipher),
        kat_192_key, sizeof(kat_192_key),
        NULL, 0, plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_plain, plain, 16);
}

void test_aes_ecb_enc_256(void)
{
    uint8_t cipher[32] = {0};
    crypto_aes_Ret ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_256, crypto_aes_Mode_Ecb,
        kat_128_plain, 16,
        kat_256_key, sizeof(kat_256_key),
        NULL, 0, cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_256_cipher, cipher, sizeof(kat_256_cipher));
}

void test_aes_ecb_dec_256(void)
{
    uint8_t plain[16] = {0};
    crypto_aes_Ret ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_256, crypto_aes_Mode_Ecb,
        kat_256_cipher, sizeof(kat_256_cipher),
        kat_256_key, sizeof(kat_256_key),
        NULL, 0, plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_plain, plain, 16);
}

/*============================================================================*/
/* ASYNC (HANDLE) API KAT — migrated from tc7 */
/*============================================================================*/
void test_aes_async_ecb_enc_128(void)
{
    crypto_aes_Handle h;
    uint8_t cipher[80] = {0};
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key),
        NULL, 0, cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);

    // Split into 8-byte chunks
    for (uint32_t off = 0; off < sizeof(kat_128_plain); off += 8) {
        ret = crypto_aes_Handle_update(&h, &kat_128_plain[off], 8);
        TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    }
    ret = crypto_aes_Handle_finalize(&h);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_cipher, cipher, sizeof(kat_128_cipher));
}

/*============================================================================*/
/* SYNC CBC/CTR KAT */
/*============================================================================*/
void test_aes_cbc_enc_128(void)
{
    uint8_t cipher[80] = {0};
    crypto_aes_Ret ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        kat_128_plain, sizeof(kat_128_plain),
        kat_128_key, sizeof(kat_128_key),
        cbc_iv, sizeof(cbc_iv), cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    /* Verify first 64 bytes against NIST SP 800-38A F.2.1 vector */
    TEST_ASSERT_EQUAL_MEMORY(cbc_128_cipher, cipher, sizeof(cbc_128_cipher));
    /* Roundtrip: decrypt back and verify plaintext */
    uint8_t plain[64] = {0};
    ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        cipher, 80,
        kat_128_key, sizeof(kat_128_key),
        cbc_iv, sizeof(cbc_iv), plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_plain, plain, sizeof(kat_128_plain));
}

void test_aes_cbc_dec_128(void)
{
    /* Encrypt first, then decrypt. Verifies decrypt handles padded input correctly. */
    uint8_t cipher[80] = {0};
    crypto_aes_Ret ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        kat_128_plain, sizeof(kat_128_plain),
        kat_128_key, sizeof(kat_128_key),
        cbc_iv, sizeof(cbc_iv), cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    uint8_t plain[64] = {0};
    ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        cipher, 80,
        kat_128_key, sizeof(kat_128_key),
        cbc_iv, sizeof(cbc_iv), plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_plain, plain, sizeof(kat_128_plain));
}

void test_aes_ctr_enc_128(void)
{
    uint8_t cipher[64] = {0};
    crypto_aes_Ret ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ctr,
        kat_128_plain, sizeof(kat_128_plain),
        kat_128_key, sizeof(kat_128_key),
        ctr_iv, sizeof(ctr_iv), cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(ctr_128_cipher, cipher, sizeof(ctr_128_cipher));
}

void test_aes_ctr_dec_128(void)
{
    /* CTR decrypt is same as encrypt */
    uint8_t plain[64] = {0};
    crypto_aes_Ret ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ctr,
        ctr_128_cipher, sizeof(ctr_128_cipher),
        kat_128_key, sizeof(kat_128_key),
        ctr_iv, sizeof(ctr_iv), plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_plain, plain, sizeof(kat_128_plain));
}

/*============================================================================*/
/* HANDLE_INIT ERROR PATHS */
/*============================================================================*/
void test_aes_handle_init_null_self(void)
{
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        NULL, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_null_key(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        NULL, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_null_output(void)
{
    crypto_aes_Handle h;
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, NULL, 32);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_invalid_keylen(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, (crypto_aes_KeyLen)99, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_keybuf_small_128(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_128_key, 15, NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_keybuf_small_192(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_192, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_192_key, 23, NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_keybuf_small_256(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_256, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_256_key, 31, NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_invalid_mode(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, (crypto_aes_Mode)99,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_invalid_dir(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        (crypto_aes_Direction)99,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_cbc_null_iv(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_ctr_null_iv(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ctr,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_iv_capacity_small(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), cbc_iv, 15, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_init_output_small_enc_ecb(void)
{
    crypto_aes_Handle h;
    uint8_t out[15]; /* < 16 bytes, check fails */
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_BufferTooSmall, ret);
}

void test_aes_handle_init_output_small_enc_cbc(void)
{
    crypto_aes_Handle h;
    uint8_t out[15];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), cbc_iv, sizeof(cbc_iv),
        out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_BufferTooSmall, ret);
}

/* Encrypt ECB with Ok output capacity, then Decrypt ECB — output capacity check
 * is only for ECB/CBC encrypt, not decrypt. Test separately below. */
void test_aes_handle_init_output_ok_dec(void)
{
    crypto_aes_Handle h;
    uint8_t out[32];
    /* Decrypt with 16-byte output is OK (padding happens in encrypt, not decrypt setup) */
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Decrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
}

/*============================================================================*/
/* HANDLE_UPDATE ERROR PATHS */
/*============================================================================*/
void test_aes_handle_update_null_self(void)
{
    crypto_aes_Ret ret = crypto_aes_Handle_update(NULL, kat_128_plain, 16);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_update_null_input(void)
{
    crypto_aes_Handle h;
    uint8_t out[80];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    ret = crypto_aes_Handle_update(&h, NULL, 16);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

void test_aes_handle_update_empty(void)
{
    crypto_aes_Handle h;
    uint8_t out[80];
    crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    crypto_aes_Ret ret = crypto_aes_Handle_update(&h, kat_128_plain, 0);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
}

/*============================================================================*/
/* HANDLE_FINALIZE ERROR PATHS */
/*============================================================================*/
void test_aes_handle_finalize_null_self(void)
{
    crypto_aes_Ret ret = crypto_aes_Handle_finalize(NULL);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

/*============================================================================*/
/* SYNC ENCRYPT/DECRYPT ERROR PATHS */
/*============================================================================*/
void test_aes_encrypt_buffer_too_small(void)
{
    uint8_t cipher[15]; /* < 16 bytes, too small for ECB/CBC + padding */
    crypto_aes_Ret ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        kat_128_plain, sizeof(kat_128_plain),
        kat_128_key, sizeof(kat_128_key),
        NULL, 0, cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_BufferTooSmall, ret);
}

void test_aes_decrypt_invalid_init(void)
{
    /* Bad key capacity causes Handle_init to fail inside decrypt */
    uint8_t plain[64];
    crypto_aes_Ret ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        kat_128_cipher, sizeof(kat_128_cipher),
        kat_128_key, 10, /* too small */
        NULL, 0, plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

/*============================================================================*/
/* STREAMING TESTS */
/*============================================================================*/
void test_aes_streaming_cbc_enc(void)
{
    crypto_aes_Handle h;
    uint8_t cipher[80] = {0};
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key),
        cbc_iv, sizeof(cbc_iv), cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    /* feed 8 bytes at a time */
    for (uint32_t off = 0; off < sizeof(kat_128_plain); off += 8) {
        ret = crypto_aes_Handle_update(&h, &kat_128_plain[off], 8);
        TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    }
    ret = crypto_aes_Handle_finalize(&h);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    /* Verify first 64 bytes match NIST KAT; padding follows */
    TEST_ASSERT_EQUAL_MEMORY(cbc_128_cipher, cipher, sizeof(cbc_128_cipher));
    /* Roundtrip verify */
    uint8_t plain[64] = {0};
    ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        cipher, 80,
        kat_128_key, sizeof(kat_128_key),
        cbc_iv, sizeof(cbc_iv), plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_plain, plain, sizeof(kat_128_plain));
}

void test_aes_streaming_cbc_dec(void)
{
    /* Encrypt first to get full padded ciphertext, then decrypt streaming */
    uint8_t cipher[80] = {0};
    crypto_aes_encrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        kat_128_plain, sizeof(kat_128_plain),
        kat_128_key, sizeof(kat_128_key),
        cbc_iv, sizeof(cbc_iv), cipher, sizeof(cipher));

    crypto_aes_Handle h;
    uint8_t plain[64] = {0};
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Cbc,
        crypto_aes_Direction_Decrypt,
        kat_128_key, sizeof(kat_128_key),
        cbc_iv, sizeof(cbc_iv), plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    for (uint32_t off = 0; off < 80; off += 8) {
        ret = crypto_aes_Handle_update(&h, &cipher[off], 8);
        TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    }
    ret = crypto_aes_Handle_finalize(&h);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_plain, plain, sizeof(kat_128_plain));
}

void test_aes_streaming_ecb_dec(void)
{
    /* Decrypt streaming ECB: exercises decrypt-delay for ECB mode */
    crypto_aes_Handle h;
    uint8_t plain[64] = {0};
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Decrypt,
        kat_128_key, sizeof(kat_128_key),
        NULL, 0, plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    for (uint32_t off = 0; off < sizeof(kat_128_cipher); off += 8) {
        ret = crypto_aes_Handle_update(&h, &kat_128_cipher[off], 8);
        TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    }
    ret = crypto_aes_Handle_finalize(&h);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(kat_128_plain, plain, sizeof(kat_128_plain));
}

void test_aes_streaming_ctr_xcrypt(void)
{
    crypto_aes_Handle h;
    uint8_t cipher[64] = {0};
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ctr,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key),
        ctr_iv, sizeof(ctr_iv), cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    /* feed 8 at a time */
    for (uint32_t off = 0; off < sizeof(kat_128_plain); off += 8) {
        ret = crypto_aes_Handle_update(&h, &kat_128_plain[off], 8);
        TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    }
    ret = crypto_aes_Handle_finalize(&h);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_MEMORY(ctr_128_cipher, cipher, sizeof(ctr_128_cipher));
}

void test_aes_ctr_partial_block(void)
{
    /* CTR with input length not a multiple of 16 — exercises buf_len < 16 path
     * in finalize */
    crypto_aes_Handle h;
    uint8_t out[64] = {0};
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ctr,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key),
        ctr_iv, sizeof(ctr_iv), out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    /* feed 10 bytes — not block-aligned */
    ret = crypto_aes_Handle_update(&h, kat_128_plain, 10);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    ret = crypto_aes_Handle_finalize(&h);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
}

void test_aes_encrypt_ctr_no_padding_check(void)
{
    /* CTR mode skips the padding buffer check in encrypt() */
    uint8_t cipher[64] = {0};
    crypto_aes_Ret ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ctr,
        kat_128_plain, sizeof(kat_128_plain),
        kat_128_key, sizeof(kat_128_key),
        ctr_iv, sizeof(ctr_iv), cipher, sizeof(cipher));
    /* 64 output capacity, 64 input — CTR doesn't need +16 headroom */
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
}

void test_aes_finalize_decrypt_unaligned(void)
{
    /* If finalize sees buf_len != 0 && != 16 during ECB/CBC decrypt, it
     * returns CipherTextNotAligned. Feed 10 bytes to decrypt handle, don't
     * fill a full block, then finalize. */
    crypto_aes_Handle h;
    uint8_t out[64];
    crypto_aes_Ret ret = crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Decrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    /* feed 10 bytes — not block-aligned, not 0 */
    ret = crypto_aes_Handle_update(&h, kat_128_cipher, 10);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_Ok, ret);
    ret = crypto_aes_Handle_finalize(&h);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_CipherTextNotAligned, ret);
}

void test_aes_finalize_enc_ecb_output_overflow(void)
{
    /* Encrypt ECB via Handle API: output only 16 bytes, but padding block
     * needs another 16 → finalize returns BufferTooSmall */
    crypto_aes_Handle h;
    uint8_t out[16];
    crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key), NULL, 0, out, sizeof(out));
    crypto_aes_Handle_update(&h, kat_128_plain, 16);
    crypto_aes_Ret ret = crypto_aes_Handle_finalize(&h);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_BufferTooSmall, ret);
}

/* ---- reachable coverage gaps ---- */

/* encrypt: Handle_init fails (line 234) */
void test_aes_encrypt_handle_init_fails(void)
{
    uint8_t cipher[32];
    /* key capacity = 15 (too small for AES128) passes encrypt's pre-size check
     * (32 >= 16+16=32) but fails Handle_init */
    crypto_aes_Ret ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        kat_128_plain, 16,
        kat_128_key, 15, /* too small */
        NULL, 0, cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

/* encrypt: Handle_update fails (line 239) */
void test_aes_encrypt_null_input(void)
{
    uint8_t cipher[32];
    crypto_aes_Ret ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        NULL, 16, /* NULL input → Handle_update returns InvalidArg */
        kat_128_key, sizeof(kat_128_key),
        NULL, 0, cipher, sizeof(cipher));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_InvalidArg, ret);
}

/* decrypt finalize: bad PKCS#7 padding (lines 567-568, 593) */
void test_aes_finalize_decrypt_bad_padding(void)
{
    /* Encrypt 16 bytes → 32 bytes output, corrupt last byte of padding block */
    uint8_t cipher[32];
    crypto_aes_encrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        kat_128_plain, 16,
        kat_128_key, sizeof(kat_128_key),
        NULL, 0, cipher, sizeof(cipher));
    /* Flip a byte in the encrypted padding block (last block = bytes 16-31) */
    cipher[30] ^= 0xFF; /* corrupt last block before the pad value byte */

    uint8_t plain[16];
    crypto_aes_Ret ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_128, crypto_aes_Mode_Ecb,
        cipher, 32,
        kat_128_key, sizeof(kat_128_key),
        NULL, 0, plain, sizeof(plain));
    TEST_ASSERT_EQUAL(crypto_aes_Ret_CipherTextNotAligned, ret);
}

/* CTR finalize: output buffer overflow (line 582) */
void test_aes_ctr_finalize_overflow(void)
{
    crypto_aes_Handle h;
    uint8_t out[32]; /* 32 bytes — update processes 2 full blocks, then finalize
                       * has 2 partial bytes that overflow to 34 */
    crypto_aes_Handle_init(
        &h, crypto_aes_KeyLen_128, crypto_aes_Mode_Ctr,
        crypto_aes_Direction_Encrypt,
        kat_128_key, sizeof(kat_128_key),
        ctr_iv, sizeof(ctr_iv), out, sizeof(out));
    /* Feed 34 bytes → 2 full blocks (processed in update), 2 bytes remain */
    crypto_aes_Handle_update(&h, kat_128_plain, 34);
    /* Finalize: buf_len=2, capacity=32, result_len=32, 32+2=34 > 32 */
    crypto_aes_Ret ret = crypto_aes_Handle_finalize(&h);
    TEST_ASSERT_EQUAL(crypto_aes_Ret_BufferTooSmall, ret);
}

/*============================================================================*/
/* TEST GROUP RUNNER */
/*============================================================================*/
void run_aes_tests(void)
{
    /* KAT — ECB sync */
    RUN_TEST(test_aes_ecb_enc_128);
    RUN_TEST(test_aes_ecb_dec_128);
    RUN_TEST(test_aes_ecb_enc_192);
    RUN_TEST(test_aes_ecb_dec_192);
    RUN_TEST(test_aes_ecb_enc_256);
    RUN_TEST(test_aes_ecb_dec_256);

    /* KAT — async */
    RUN_TEST(test_aes_async_ecb_enc_128);

    /* KAT — CBC/CTR sync */
    RUN_TEST(test_aes_cbc_enc_128);
    RUN_TEST(test_aes_cbc_dec_128);
    RUN_TEST(test_aes_ctr_enc_128);
    RUN_TEST(test_aes_ctr_dec_128);

    /* Handle_init error paths */
    RUN_TEST(test_aes_handle_init_null_self);
    RUN_TEST(test_aes_handle_init_null_key);
    RUN_TEST(test_aes_handle_init_null_output);
    RUN_TEST(test_aes_handle_init_invalid_keylen);
    RUN_TEST(test_aes_handle_init_keybuf_small_128);
    RUN_TEST(test_aes_handle_init_keybuf_small_192);
    RUN_TEST(test_aes_handle_init_keybuf_small_256);
    RUN_TEST(test_aes_handle_init_invalid_mode);
    RUN_TEST(test_aes_handle_init_invalid_dir);
    RUN_TEST(test_aes_handle_init_cbc_null_iv);
    RUN_TEST(test_aes_handle_init_ctr_null_iv);
    RUN_TEST(test_aes_handle_init_iv_capacity_small);
    RUN_TEST(test_aes_handle_init_output_small_enc_ecb);
    RUN_TEST(test_aes_handle_init_output_small_enc_cbc);
    RUN_TEST(test_aes_handle_init_output_ok_dec);

    /* Handle_update error paths */
    RUN_TEST(test_aes_handle_update_null_self);
    RUN_TEST(test_aes_handle_update_null_input);
    RUN_TEST(test_aes_handle_update_empty);

    /* Handle_finalize error paths */
    RUN_TEST(test_aes_handle_finalize_null_self);

    /* Sync encrypt/decrypt error paths */
    RUN_TEST(test_aes_encrypt_buffer_too_small);
    RUN_TEST(test_aes_decrypt_invalid_init);

    /* Streaming */
    RUN_TEST(test_aes_streaming_cbc_enc);
    RUN_TEST(test_aes_streaming_cbc_dec);
    RUN_TEST(test_aes_streaming_ecb_dec);
    RUN_TEST(test_aes_streaming_ctr_xcrypt);
    RUN_TEST(test_aes_ctr_partial_block);
    RUN_TEST(test_aes_encrypt_ctr_no_padding_check);
    RUN_TEST(test_aes_finalize_decrypt_unaligned);

    /* Additional coverage gap tests */
    RUN_TEST(test_aes_encrypt_handle_init_fails);
    RUN_TEST(test_aes_encrypt_null_input);
    RUN_TEST(test_aes_finalize_decrypt_bad_padding);
    RUN_TEST(test_aes_ctr_finalize_overflow);
}

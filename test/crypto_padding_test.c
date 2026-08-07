/*============================================================================*/
/**
 * @file       crypto_padding_test.c
 * @brief      PKCS#7 padding tests (Unity framework)
 * @copyright  Copyright (C) 2026. MIT License.
 */
/*============================================================================*/
#include "unity.h"
#include "crypto_padding.h"
#include <string.h>

static const uint8_t g_data[20] = "0123456789abcdefghij";
static const uint8_t g_block_size = 16;

/*============================================================================*/
/* PKCS7 PAD */
/*============================================================================*/
void test_pad_normal(void)
{
    uint8_t out[32];
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_pad(
        g_data, 10, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_UINT32(16, out_len);
    TEST_ASSERT_EQUAL_MEMORY(g_data, out, 10);
    /* last 6 bytes = 0x06 (pad value) */
    for (uint32_t i = 10; i < 16; i++) {
        TEST_ASSERT_EQUAL_UINT8(6, out[i]);
    }
}

void test_pad_block_aligned(void)
{
    /* Exactly 16 bytes input → full block of padding (16 * 0x10) */
    uint8_t out[32];
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_pad(
        g_data, 16, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_UINT32(32, out_len);
    TEST_ASSERT_EQUAL_MEMORY(g_data, out, 16);
    for (uint32_t i = 16; i < 32; i++) {
        TEST_ASSERT_EQUAL_UINT8(16, out[i]);
    }
}

void test_pad_empty(void)
{
    /* 0 bytes input → 16 bytes of padding (16 * 0x10) */
    uint8_t out[32];
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_pad(
        g_data, 0, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_UINT32(16, out_len);
    for (uint32_t i = 0; i < 16; i++) {
        TEST_ASSERT_EQUAL_UINT8(16, out[i]);
    }
}

void test_pad_null_input(void)
{
    uint8_t out[32];
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_pad(
        NULL, 10, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_InvalidArg, ret);
}

void test_pad_null_output(void)
{
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_pad(
        g_data, 10, g_block_size, NULL, 32, &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_InvalidArg, ret);
}

void test_pad_null_output_len(void)
{
    uint8_t out[32];
    crypto_padding_Ret ret = crypto_padding_pkcs7_pad(
        g_data, 10, g_block_size, out, sizeof(out), NULL);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_InvalidArg, ret);
}

void test_pad_buffer_too_small(void)
{
    uint8_t out[14]; /* need 16 bytes for 10 bytes input + 6 bytes padding */
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_pad(
        g_data, 10, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_BufferTooSmall, ret);
}

void test_pad_pad_val_1(void)
{
    /* 15 bytes input with block_size=16 → pad_val = 1 */
    uint8_t out[16];
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_pad(
        g_data, 15, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_UINT32(16, out_len);
    TEST_ASSERT_EQUAL_UINT8(1, out[15]);
}

/*============================================================================*/
/* PKCS7 UNPAD */
/*============================================================================*/
void test_unpad_normal(void)
{
    /* First pad 10 bytes, then unpad */
    uint8_t padded[32];
    uint32_t padded_len = 0;
    crypto_padding_pkcs7_pad(
        g_data, 10, g_block_size, padded, sizeof(padded), &padded_len);

    uint8_t out[32];
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        padded, padded_len, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_UINT32(10, out_len);
    TEST_ASSERT_EQUAL_MEMORY(g_data, out, 10);
}

void test_unpad_block_aligned(void)
{
    /* Exactly 16 bytes pad = 32 bytes padded */
    uint8_t padded[32];
    uint32_t padded_len = 0;
    crypto_padding_pkcs7_pad(
        g_data, 16, g_block_size, padded, sizeof(padded), &padded_len);

    uint8_t out[32];
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        padded, padded_len, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_UINT32(16, out_len);
    TEST_ASSERT_EQUAL_MEMORY(g_data, out, 16);
}

void test_unpad_null_input(void)
{
    uint8_t out[32];
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        NULL, 16, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_InvalidArg, ret);
}

void test_unpad_null_output(void)
{
    uint8_t padded[16];
    uint32_t out_len = 0;
    memset(padded, 1, 16);
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        padded, 16, g_block_size, NULL, 32, &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_InvalidArg, ret);
}

void test_unpad_null_output_len(void)
{
    uint8_t padded[16];
    uint8_t out[32];
    memset(padded, 1, 16);
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        padded, 16, g_block_size, out, sizeof(out), NULL);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_InvalidArg, ret);
}

void test_unpad_zero_input(void)
{
    uint8_t out[32];
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        g_data, 0, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_BadPadding, ret);
}

void test_unpad_input_not_aligned(void)
{
    uint8_t data[17];
    uint8_t out[32];
    uint32_t out_len = 0;
    memset(data, 0x01, sizeof(data));
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        data, 17, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_BadPadding, ret);
}

void test_unpad_pad_val_zero(void)
{
    uint8_t padded[32];
    uint32_t out_len = 0;
    uint8_t out[32];
    /* manually craft: last byte = 0x00 */
    memset(padded, 0x00, 16);
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        padded, 16, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_BadPadding, ret);
}

void test_unpad_pad_val_exceeds_block(void)
{
    uint8_t padded[32];
    uint32_t out_len = 0;
    uint8_t out[32];
    /* last byte = 17 > block_size (16) */
    memset(padded, 17, 16);
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        padded, 16, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_BadPadding, ret);
}

void test_unpad_bad_padding_bytes(void)
{
    uint8_t padded[32];
    uint32_t out_len = 0;
    uint8_t out[32];
    /* pad_val = last byte = 0x05, so bytes [27,31] must ALL equal 0x05.
     * Put a bad byte inside the padding range (position 28). */
    memset(padded, 0x05, 32);
    padded[28] = 0x04; /* wrong byte within the last-5-bytes padding range */
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        padded, 32, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_BadPadding, ret);
}

void test_unpad_buffer_too_small(void)
{
    /* 16-byte input, pad_val=1, result=15 bytes, output only 14 bytes */
    uint8_t padded[16];
    uint32_t out_len = 0;
    uint8_t out[14];
    memset(padded, 0x01, sizeof(padded)); /* pad_val = 1, all bytes = 1 */
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        padded, 16, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_BufferTooSmall, ret);
}

/*============================================================================*/
/* ROUNDTRIP */
/*============================================================================*/
void test_padding_roundtrip_7(void)
{
    /* odd length 7 */
    uint8_t padded[32];
    uint32_t padded_len = 0;
    crypto_padding_pkcs7_pad(
        g_data, 7, g_block_size, padded, sizeof(padded), &padded_len);

    uint8_t out[32];
    uint32_t out_len = 0;
    crypto_padding_Ret ret = crypto_padding_pkcs7_unpad(
        padded, padded_len, g_block_size, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL(crypto_padding_Ret_Ok, ret);
    TEST_ASSERT_EQUAL_UINT32(7, out_len);
    TEST_ASSERT_EQUAL_MEMORY(g_data, out, 7);
}

/*============================================================================*/
/* RUNNER */
/*============================================================================*/
void run_padding_tests(void)
{
    RUN_TEST(test_pad_normal);
    RUN_TEST(test_pad_block_aligned);
    RUN_TEST(test_pad_empty);
    RUN_TEST(test_pad_null_input);
    RUN_TEST(test_pad_null_output);
    RUN_TEST(test_pad_null_output_len);
    RUN_TEST(test_pad_buffer_too_small);
    RUN_TEST(test_pad_pad_val_1);

    RUN_TEST(test_unpad_normal);
    RUN_TEST(test_unpad_block_aligned);
    RUN_TEST(test_unpad_null_input);
    RUN_TEST(test_unpad_null_output);
    RUN_TEST(test_unpad_null_output_len);
    RUN_TEST(test_unpad_zero_input);
    RUN_TEST(test_unpad_input_not_aligned);
    RUN_TEST(test_unpad_pad_val_zero);
    RUN_TEST(test_unpad_pad_val_exceeds_block);
    RUN_TEST(test_unpad_bad_padding_bytes);
    RUN_TEST(test_unpad_buffer_too_small);

    RUN_TEST(test_padding_roundtrip_7);
}

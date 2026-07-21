//==============================================================================
/// @file       crypto_aes_test.h
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      Test of AES algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==============================================================================
//==============================================================================
// GUARD START
//==============================================================================
#ifndef CRYPTO_AES_TEST_H
#define CRYPTO_AES_TEST_H
#ifdef __cplusplus
extern "C" {
#endif
//==============================================================================
// INCLUDE
//==============================================================================
#include "crypto_aes.h"
#include <string.h>

//==============================================================================
// PUBLIC TYPEDEF
//==============================================================================

//==============================================================================
// PUBLIC MACRO
//==============================================================================
#define CRYPTO_AES_TEST_PRINTF (0U)

#if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
#include <stdio.h>
#endif // #if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)

//==============================================================================
// PUBLIC ENUM
//==============================================================================

//==============================================================================
// PUBLIC STRUCT
//==============================================================================

//==============================================================================
// PUBLIC UNION
//==============================================================================

//==============================================================================
// PUBLIC VARIABLE DECLARATION
//==============================================================================

//==============================================================================
// PUBLIC FUNCTION DECLARATION
//==============================================================================
static int32_t crypto_aes_test_tc1(void) {
    uint8_t plain_buf[64] = {
        0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U, //
        0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU, //
        0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU, //
        0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U, //
        0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U, //
        0xe5U, 0xfbU, 0xc1U, 0x19U, 0x1aU, 0x0aU, 0x52U, 0xefU, //
        0xf6U, 0x9fU, 0x24U, 0x45U, 0xdfU, 0x4fU, 0x9bU, 0x17U, //
        0xadU, 0x2bU, 0x41U, 0x7bU, 0xe6U, 0x6cU, 0x37U, 0x10U, //
    };
    // clang-format off
    uint8_t key_buf[128 / 8] = {
        0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U, //
        0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU, //
    };
    // clang-format on
    uint8_t expected_cipher_buf[80] = {
        0x3aU, 0xd7U, 0x7bU, 0xb4U, 0x0dU, 0x7aU, 0x36U, 0x60U, //
        0xa8U, 0x9eU, 0xcaU, 0xf3U, 0x24U, 0x66U, 0xefU, 0x97U, //
        0xf5U, 0xd3U, 0xd5U, 0x85U, 0x03U, 0xb9U, 0x69U, 0x9dU, //
        0xe7U, 0x85U, 0x89U, 0x5aU, 0x96U, 0xfdU, 0xbaU, 0xafU, //
        0x43U, 0xb1U, 0xcdU, 0x7fU, 0x59U, 0x8eU, 0xceU, 0x23U, //
        0x88U, 0x1bU, 0x00U, 0xe3U, 0xedU, 0x03U, 0x06U, 0x88U, //
        0x7bU, 0x0cU, 0x78U, 0x5eU, 0x27U, 0xe8U, 0xadU, 0x3fU, //
        0x82U, 0x23U, 0x20U, 0x71U, 0x04U, 0x72U, 0x5dU, 0xd4U, //
        0xa2U, 0x54U, 0xbeU, 0x88U, 0xe0U, 0x37U, 0xddU, 0xd9U, //
        0xd7U, 0x9fU, 0xb6U, 0x41U, 0x1cU, 0x3fU, 0x9dU, 0xf8U, //
    };
    uint8_t cipher_buf[80];
    memset(cipher_buf, 0U, sizeof(cipher_buf));

    crypto_aes_Ret aes_ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_128,
        crypto_aes_Mode_Ecb,
        plain_buf,
        sizeof(plain_buf) / sizeof(plain_buf[0]),
        key_buf,
        sizeof(key_buf) / sizeof(key_buf[0]),
        NULL,
        0U,
        cipher_buf,
        sizeof(cipher_buf) / sizeof(cipher_buf[0])
    );
    if (aes_ret != crypto_aes_Ret_Ok) {
#if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        return __LINE__;
    }

    int32_t ret =
        memcmp(expected_cipher_buf, cipher_buf, sizeof(expected_cipher_buf));
    if (ret != 0) {
#if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        printf("\ncipher_buf:\n");
        for (uint32_t a = 0; a < 10U; a++) {
            printf(
                "%02x %02x %02x %02x %02x %02x %02x %02x\n",
                cipher_buf[(a * 8) + 0],
                cipher_buf[(a * 8) + 1],
                cipher_buf[(a * 8) + 2],
                cipher_buf[(a * 8) + 3],
                cipher_buf[(a * 8) + 4],
                cipher_buf[(a * 8) + 5],
                cipher_buf[(a * 8) + 6],
                cipher_buf[(a * 8) + 7]
            );
        }
#endif // #if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        return __LINE__;
    }

    return 0;
}

static int32_t crypto_aes_test_tc2(void) {
    uint8_t cipher_buf[80] = {
        0x3aU, 0xd7U, 0x7bU, 0xb4U, 0x0dU, 0x7aU, 0x36U, 0x60U, //
        0xa8U, 0x9eU, 0xcaU, 0xf3U, 0x24U, 0x66U, 0xefU, 0x97U, //
        0xf5U, 0xd3U, 0xd5U, 0x85U, 0x03U, 0xb9U, 0x69U, 0x9dU, //
        0xe7U, 0x85U, 0x89U, 0x5aU, 0x96U, 0xfdU, 0xbaU, 0xafU, //
        0x43U, 0xb1U, 0xcdU, 0x7fU, 0x59U, 0x8eU, 0xceU, 0x23U, //
        0x88U, 0x1bU, 0x00U, 0xe3U, 0xedU, 0x03U, 0x06U, 0x88U, //
        0x7bU, 0x0cU, 0x78U, 0x5eU, 0x27U, 0xe8U, 0xadU, 0x3fU, //
        0x82U, 0x23U, 0x20U, 0x71U, 0x04U, 0x72U, 0x5dU, 0xd4U, //
        0xa2U, 0x54U, 0xbeU, 0x88U, 0xe0U, 0x37U, 0xddU, 0xd9U, //
        0xd7U, 0x9fU, 0xb6U, 0x41U, 0x1cU, 0x3fU, 0x9dU, 0xf8U, //
    };
    // clang-format off
    uint8_t key_buf[128 / 8] = {
        0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
        0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU,
    };
    // clang-format on
    uint8_t expected_plain_buf[64] = {
        0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U, //
        0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU, //
        0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU, //
        0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U, //
        0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U, //
        0xe5U, 0xfbU, 0xc1U, 0x19U, 0x1aU, 0x0aU, 0x52U, 0xefU, //
        0xf6U, 0x9fU, 0x24U, 0x45U, 0xdfU, 0x4fU, 0x9bU, 0x17U, //
        0xadU, 0x2bU, 0x41U, 0x7bU, 0xe6U, 0x6cU, 0x37U, 0x10U, //
    };
    uint8_t plain_buf[64];
    memset(plain_buf, 0U, sizeof(plain_buf));

    crypto_aes_Ret aes_ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_128,
        crypto_aes_Mode_Ecb,
        cipher_buf,
        sizeof(cipher_buf) / sizeof(cipher_buf[0]),
        key_buf,
        sizeof(key_buf) / sizeof(key_buf[0]),
        NULL,
        0U,
        plain_buf,
        sizeof(plain_buf) / sizeof(plain_buf[0])
    );
    if (aes_ret != crypto_aes_Ret_Ok) {
#if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        return __LINE__;
    }

    int32_t ret =
        memcmp(expected_plain_buf, plain_buf, sizeof(expected_plain_buf));
    if (ret != 0) {
#if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        printf("\nplain_buf:\n");
        for (uint32_t a = 0; a < 8U; a++) {
            printf(
                "%02x %02x %02x %02x %02x %02x %02x %02x\n",
                plain_buf[0 + a * 8],
                plain_buf[1 + a * 8],
                plain_buf[2 + a * 8],
                plain_buf[3 + a * 8],
                plain_buf[4 + a * 8],
                plain_buf[5 + a * 8],
                plain_buf[6 + a * 8],
                plain_buf[7 + a * 8]
            );
        }
#endif // #if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        return __LINE__;
    }

    return 0;
}

static int32_t crypto_aes_test_tc3(void) {
    // clang-format off
    uint8_t plain_buf[16] = {
        0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
        0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
    };
    // clang-format on
    uint8_t key_buf[192 / 8] = {
        0x8eU, 0x73U, 0xb0U, 0xf7U, 0xdaU, 0x0eU, 0x64U, 0x52U, //
        0xc8U, 0x10U, 0xf3U, 0x2bU, 0x80U, 0x90U, 0x79U, 0xe5U, //
        0x62U, 0xf8U, 0xeaU, 0xd2U, 0x52U, 0x2cU, 0x6bU, 0x7bU, //
    };
    uint8_t expected_cipher_buf[32] = {
        0xbdU, 0x33U, 0x4fU, 0x1dU, 0x6eU, 0x45U, 0xf2U, 0x5fU, //
        0xf7U, 0x12U, 0xa2U, 0x14U, 0x57U, 0x1fU, 0xa5U, 0xccU, //
        0xdaU, 0xa0U, 0xafU, 0x07U, 0x4bU, 0xd8U, 0x08U, 0x3cU, //
        0x8aU, 0x32U, 0xd4U, 0xfcU, 0x56U, 0x3cU, 0x55U, 0xccU, //
    };
    uint8_t cipher_buf[32];
    memset(cipher_buf, 0U, sizeof(cipher_buf));

    crypto_aes_Ret aes_ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_192,
        crypto_aes_Mode_Ecb,
        plain_buf,
        sizeof(plain_buf) / sizeof(plain_buf[0]),
        key_buf,
        sizeof(key_buf) / sizeof(key_buf[0]),
        NULL,
        0U,
        cipher_buf,
        sizeof(cipher_buf) / sizeof(cipher_buf[0])
    );
    if (aes_ret != crypto_aes_Ret_Ok) {
#if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        return __LINE__;
    }

    int32_t ret =
        memcmp(expected_cipher_buf, cipher_buf, sizeof(expected_cipher_buf));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static int32_t crypto_aes_test_tc4(void) {
    uint8_t cipher_buf[32] = {
        0xbdU, 0x33U, 0x4fU, 0x1dU, 0x6eU, 0x45U, 0xf2U, 0x5fU, //
        0xf7U, 0x12U, 0xa2U, 0x14U, 0x57U, 0x1fU, 0xa5U, 0xccU, //
        0xdaU, 0xa0U, 0xafU, 0x07U, 0x4bU, 0xd8U, 0x08U, 0x3cU, //
        0x8aU, 0x32U, 0xd4U, 0xfcU, 0x56U, 0x3cU, 0x55U, 0xccU, //
    };
    uint8_t key_buf[192 / 8] = {
        0x8eU, 0x73U, 0xb0U, 0xf7U, 0xdaU, 0x0eU, 0x64U, 0x52U,
        0xc8U, 0x10U, 0xf3U, 0x2bU, 0x80U, 0x90U, 0x79U, 0xe5U,
        0x62U, 0xf8U, 0xeaU, 0xd2U, 0x52U, 0x2cU, 0x6bU, 0x7bU,
    };
    // clang-format off
    uint8_t expected_plain_buf[16] = {
        0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
        0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
    };
    uint8_t plain_buf[16];
    memset(plain_buf, 0U, sizeof(plain_buf));
    // clang-format on

    crypto_aes_Ret aes_ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_192,
        crypto_aes_Mode_Ecb,
        cipher_buf,
        sizeof(cipher_buf) / sizeof(cipher_buf[0]),
        key_buf,
        sizeof(key_buf) / sizeof(key_buf[0]),
        NULL,
        0U,
        plain_buf,
        sizeof(plain_buf) / sizeof(plain_buf[0])
    );
    if (aes_ret != crypto_aes_Ret_Ok) {
#if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        return __LINE__;
    }

    int32_t ret =
        memcmp(expected_plain_buf, plain_buf, sizeof(expected_plain_buf));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static int32_t crypto_aes_test_tc5(void) {
    // clang-format off
    uint8_t plain_buf[16] = {
        0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
        0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
    };
    // clang-format on
    uint8_t key_buf[256 / 8] = {
        0x60U, 0x3dU, 0xebU, 0x10U, 0x15U, 0xcaU, 0x71U, 0xbeU,
        0x2bU, 0x73U, 0xaeU, 0xf0U, 0x85U, 0x7dU, 0x77U, 0x81U,
        0x1fU, 0x35U, 0x2cU, 0x07U, 0x3bU, 0x61U, 0x08U, 0xd7U,
        0x2dU, 0x98U, 0x10U, 0xa3U, 0x09U, 0x14U, 0xdfU, 0xf4U,
    };
    uint8_t expected_cipher_buf[32] = {
        0xf3U, 0xeeU, 0xd1U, 0xbdU, 0xb5U, 0xd2U, 0xa0U, 0x3cU,
        0x06U, 0x4bU, 0x5aU, 0x7eU, 0x3dU, 0xb1U, 0x81U, 0xf8U,
        0x4cU, 0x45U, 0xdfU, 0xb3U, 0xb3U, 0xb4U, 0x84U, 0xecU,
        0x35U, 0xb0U, 0x51U, 0x2dU, 0xc8U, 0xc1U, 0xc4U, 0xd6U,
    };
    uint8_t cipher_buf[32];
    memset(cipher_buf, 0U, sizeof(cipher_buf));

    crypto_aes_Ret aes_ret = crypto_aes_encrypt(
        crypto_aes_KeyLen_256,
        crypto_aes_Mode_Ecb,
        plain_buf,
        sizeof(plain_buf) / sizeof(plain_buf[0]),
        key_buf,
        sizeof(key_buf) / sizeof(key_buf[0]),
        NULL,
        0U,
        cipher_buf,
        sizeof(cipher_buf) / sizeof(cipher_buf[0])
    );
    if (aes_ret != crypto_aes_Ret_Ok) {
#if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        return __LINE__;
    }

    int32_t ret =
        memcmp(expected_cipher_buf, cipher_buf, sizeof(expected_cipher_buf));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static int32_t crypto_aes_test_tc6(void) {
    // clang-format off
    uint8_t cipher_buf[32] = {
        0xf3U, 0xeeU, 0xd1U, 0xbdU, 0xb5U, 0xd2U, 0xa0U, 0x3cU,
        0x06U, 0x4bU, 0x5aU, 0x7eU, 0x3dU, 0xb1U, 0x81U, 0xf8U,
        0x4cU, 0x45U, 0xdfU, 0xb3U, 0xb3U, 0xb4U, 0x84U, 0xecU,
        0x35U, 0xb0U, 0x51U, 0x2dU, 0xc8U, 0xc1U, 0xc4U, 0xd6U,
    };
    uint8_t key_buf[256 / 8] = {
        0x60U, 0x3dU, 0xebU, 0x10U, 0x15U, 0xcaU, 0x71U, 0xbeU,
        0x2bU, 0x73U, 0xaeU, 0xf0U, 0x85U, 0x7dU, 0x77U, 0x81U,
        0x1fU, 0x35U, 0x2cU, 0x07U, 0x3bU, 0x61U, 0x08U, 0xd7U,
        0x2dU, 0x98U, 0x10U, 0xa3U, 0x09U, 0x14U, 0xdfU, 0xf4U,
    };
    uint8_t expected_plain_buf[16] = {
        0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
        0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
    };
    uint8_t plain_buf[16];
    memset(plain_buf, 0U, sizeof(plain_buf));
    // clang-format on

    crypto_aes_Ret aes_ret = crypto_aes_decrypt(
        crypto_aes_KeyLen_256,
        crypto_aes_Mode_Ecb,
        cipher_buf,
        sizeof(cipher_buf) / sizeof(cipher_buf[0]),
        key_buf,
        sizeof(key_buf) / sizeof(key_buf[0]),
        NULL,
        0U,
        plain_buf,
        sizeof(plain_buf) / sizeof(plain_buf[0])
    );
    if (aes_ret != crypto_aes_Ret_Ok) {
#if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_TEST_PRINTF) && (CRYPTO_AES_TEST_PRINTF > 0U)
        return __LINE__;
    }

    int32_t ret =
        memcmp(expected_plain_buf, plain_buf, sizeof(expected_plain_buf));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static int32_t crypto_aes_test_tc7(void) {
    // clang-format off
    uint8_t plain_buf[64] = {
        0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
        0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
        0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU,
        0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U,
        0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U,
        0xe5U, 0xfbU, 0xc1U, 0x19U, 0x1aU, 0x0aU, 0x52U, 0xefU,
        0xf6U, 0x9fU, 0x24U, 0x45U, 0xdfU, 0x4fU, 0x9bU, 0x17U,
        0xadU, 0x2bU, 0x41U, 0x7bU, 0xe6U, 0x6cU, 0x37U, 0x10U,
    };
    uint8_t key_buf[128 / 8] = {
        0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
        0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU,
    };
    uint8_t expected_cipher_buf[80] = {
        0x3aU, 0xd7U, 0x7bU, 0xb4U, 0x0dU, 0x7aU, 0x36U, 0x60U,
        0xa8U, 0x9eU, 0xcaU, 0xf3U, 0x24U, 0x66U, 0xefU, 0x97U,
        0xf5U, 0xd3U, 0xd5U, 0x85U, 0x03U, 0xb9U, 0x69U, 0x9dU,
        0xe7U, 0x85U, 0x89U, 0x5aU, 0x96U, 0xfdU, 0xbaU, 0xafU,
        0x43U, 0xb1U, 0xcdU, 0x7fU, 0x59U, 0x8eU, 0xceU, 0x23U,
        0x88U, 0x1bU, 0x00U, 0xe3U, 0xedU, 0x03U, 0x06U, 0x88U,
        0x7bU, 0x0cU, 0x78U, 0x5eU, 0x27U, 0xe8U, 0xadU, 0x3fU,
        0x82U, 0x23U, 0x20U, 0x71U, 0x04U, 0x72U, 0x5dU, 0xd4U,
        0xa2U, 0x54U, 0xbeU, 0x88U, 0xe0U, 0x37U, 0xddU, 0xd9U,
        0xd7U, 0x9fU, 0xb6U, 0x41U, 0x1cU, 0x3fU, 0x9dU, 0xf8U,
    };
    uint8_t cipher_buf[80];
    memset(cipher_buf, 0U, sizeof(cipher_buf));
    // clang-format on

    crypto_aes_Handle aes_handle;

    (void)crypto_aes_Handle_init(
        &aes_handle,
        crypto_aes_KeyLen_128,
        crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        key_buf,
        sizeof(key_buf) / sizeof(key_buf[0]),
        NULL,
        0U,
        cipher_buf,
        sizeof(cipher_buf) / sizeof(cipher_buf[0])
    );

    (void)crypto_aes_Handle_update(&aes_handle, &plain_buf[0x00], 8U);
    (void)crypto_aes_Handle_update(&aes_handle, &plain_buf[0x08], 8U);
    (void)crypto_aes_Handle_update(&aes_handle, &plain_buf[0x10], 8U);
    (void)crypto_aes_Handle_update(&aes_handle, &plain_buf[0x18], 8U);
    (void)crypto_aes_Handle_update(&aes_handle, &plain_buf[0x20], 8U);
    (void)crypto_aes_Handle_update(&aes_handle, &plain_buf[0x28], 8U);
    (void)crypto_aes_Handle_update(&aes_handle, &plain_buf[0x30], 8U);
    (void)crypto_aes_Handle_update(&aes_handle, &plain_buf[0x38], 8U);

    (void)crypto_aes_Handle_finalize(&aes_handle);

    int32_t ret =
        memcmp(expected_cipher_buf, cipher_buf, sizeof(expected_cipher_buf));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static int32_t crypto_aes_test_main(void) {
    int32_t result;

    /// Test AES128 ECB encrypt synchronously
    result = crypto_aes_test_tc1();
    if (result != 0) {
        return result;
    }

    /// Test AES128 ECB decrypt synchronously
    result = crypto_aes_test_tc2();
    if (result != 0) {
        return result;
    }

    /// Test AES192 ECB encrypt synchronously
    result = crypto_aes_test_tc3();
    if (result != 0) {
        return result;
    }

    /// Test AES192 ECB decrypt synchronously
    result = crypto_aes_test_tc4();
    if (result != 0) {
        return result;
    }

    /// Test AES256 ECB encrypt synchronously
    result = crypto_aes_test_tc5();
    if (result != 0) {
        return result;
    }

    /// Test AES256 ECB decrypt synchronously
    result = crypto_aes_test_tc6();
    if (result != 0) {
        return result;
    }

    /// Test AES128 ECB encrypt asynchronously
    result = crypto_aes_test_tc7();
    if (result != 0) {
        return result;
    }

    return 0;
}

//==============================================================================
// PUBLIC INLINE FUNCTION DEFINITION
//==============================================================================

//==============================================================================
// GUARD END
//==============================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_AES_TEST_H

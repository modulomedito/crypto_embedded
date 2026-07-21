//==============================================================================
/// @file       crypto_aes.h
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      AES algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==============================================================================
//==============================================================================
// GUARD START
//==============================================================================
#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H
#ifdef __cplusplus
extern "C" {
#endif
//==============================================================================
// INCLUDE
//==============================================================================
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

//==============================================================================
// PUBLIC TYPEDEF
//==============================================================================

//==============================================================================
// PUBLIC MACRO
//==============================================================================
/// Block length in bytes, AES is 128-bit block only
#define CRYPTO_AES_BLOCK_U8_SIZE (16U)

//==============================================================================
// PUBLIC ENUM
//==============================================================================
typedef enum {
    crypto_aes_Ret_Ok = 0U,
    crypto_aes_Ret_InvalidArg,
    crypto_aes_Ret_BufferTooSmall,
    crypto_aes_Ret_CipherTextNotAligned,
} crypto_aes_Ret;

typedef enum {
    crypto_aes_KeyLen_128 = 0U,
    crypto_aes_KeyLen_192,
    crypto_aes_KeyLen_256,
} crypto_aes_KeyLen;

typedef enum {
    crypto_aes_Mode_Ecb = 0U,
    crypto_aes_Mode_Cbc,
    crypto_aes_Mode_Ctr,
} crypto_aes_Mode;

typedef enum {
    crypto_aes_Direction_Encrypt = 0U,
    crypto_aes_Direction_Decrypt,
} crypto_aes_Direction;

//==============================================================================
// PUBLIC STRUCT
//==============================================================================
typedef struct {
    /// Use the maxium key exp size for compatibility
    /// - AES128, key len = 16x8, key exp size = 176x8
    /// - AES192, key len = 24x8, key exp size = 208x8
    /// - AES256, key len = 32x8, key exp size = 240x8
    uint8_t round_key_buf[240];
    uint8_t iv_buf[CRYPTO_AES_BLOCK_U8_SIZE];
    uint8_t buf[CRYPTO_AES_BLOCK_U8_SIZE];
    crypto_aes_KeyLen keylen;
    crypto_aes_Mode mode;
    crypto_aes_Direction dir;
    const uint8_t* key_buf_ptr;
    const uint8_t* iv_buf_ptr;
    uint32_t key_u32_num;
    uint32_t round_num;
    uint8_t* result_buf_ptr;
    uint32_t result_buf_capacity;
    uint32_t result_len;
    uint32_t buf_len;
} crypto_aes_Handle;

//==============================================================================
// PUBLIC UNION
//==============================================================================

//==============================================================================
// PUBLIC VARIABLE DECLARATION
//==============================================================================

//==============================================================================
// PUBLIC FUNCTION DECLARATION
//==============================================================================
// Synchronous APIs
extern crypto_aes_Ret crypto_aes_encrypt(
    crypto_aes_KeyLen keylen,
    crypto_aes_Mode mode,
    const uint8_t* input_buf_ptr,
    uint32_t input_num,
    const uint8_t* key_buf_ptr,
    uint32_t key_buf_capacity,
    const uint8_t* iv_buf_ptr,
    uint32_t iv_buf_capacity,
    uint8_t* output_buf_ptr,
    uint32_t output_buf_capacity
);
extern crypto_aes_Ret crypto_aes_decrypt(
    crypto_aes_KeyLen keylen,
    crypto_aes_Mode mode,
    const uint8_t* input_buf_ptr,
    uint32_t input_num,
    const uint8_t* key_buf_ptr,
    uint32_t key_buf_capacity,
    const uint8_t* iv_buf_ptr,
    uint32_t iv_buf_capacity,
    uint8_t* output_buf_ptr,
    uint32_t output_buf_capacity
);

// Asynchronous APIs
extern crypto_aes_Ret crypto_aes_Handle_init(
    crypto_aes_Handle* self,
    crypto_aes_KeyLen keylen,
    crypto_aes_Mode mode,
    crypto_aes_Direction dir,
    const uint8_t* key_buf_ptr,
    uint32_t key_buf_capacity,
    const uint8_t* iv_buf_ptr,
    uint32_t iv_buf_capacity,
    uint8_t* output_buf_ptr,
    uint32_t output_buf_capacity
);
extern crypto_aes_Ret crypto_aes_Handle_update(
    crypto_aes_Handle* self,
    const uint8_t* input_buf_ptr,
    uint32_t input_num
);
extern crypto_aes_Ret crypto_aes_Handle_finalize(crypto_aes_Handle* self);

//==============================================================================
// PUBLIC INLINE FUNCTION DEFINITION
//==============================================================================

//==============================================================================
// GUARD END
//==============================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_AES_H

//==============================================================================
/// @file       crypto_aes.c
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      AES algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==============================================================================
//==============================================================================
// INCLUDE
//==============================================================================
#include "crypto_aes.h"
#include "crypto_padding.h"
#include "crypto_platform.h"
#include "crypto_util.h"

//==============================================================================
// IMPORTED SWITCH CHECK
//==============================================================================

//==============================================================================
// PRIVATE DEFINE
//==============================================================================
/// The number of columns comprising a state in AES, it is a constant in AES.
/// Value = 4
#define CRYPTO_AES_NB (4)

//==============================================================================
// PRIVATE TYPEDEF
//==============================================================================

//==============================================================================
// PRIVATE ENUM
//==============================================================================

//==============================================================================
// PRIVATE STRUCT
//==============================================================================
// In standard AES, the state is a 4x4 matrix of bytes.
// Data is stored column by column (a word is a column).
// Here we define a column (4 bytes) and the state (4 columns).
typedef struct {
    uint8_t byte[4]; // 4 bytes in a column
} crypto_aes_StateColumn;

typedef struct {
    crypto_aes_StateColumn col[4]; // 4 columns in a state
} crypto_aes_State;

//==============================================================================
// PRIVATE UNION
//==============================================================================

//==============================================================================
// PRIVATE FUNCTION DECLARATION
//==============================================================================
static void crypto_aes_Handle_ecb_encrypt(crypto_aes_Handle* self);
static void crypto_aes_Handle_ecb_decrypt(
    crypto_aes_Handle* self,
    uint8_t* buf_mut
);
static void crypto_aes_Handle_cbc_encrypt(crypto_aes_Handle* self);
static void crypto_aes_Handle_cbc_decrypt(
    crypto_aes_Handle* self,
    uint8_t* buf_mut
);
static void crypto_aes_Handle_ctr_xcrypt(crypto_aes_Handle* self);
static void crypto_aes_Handle_key_expansion(crypto_aes_Handle* self);
static void crypto_aes_Handle_cipher(
    crypto_aes_Handle* self,
    crypto_aes_State* state_mut
);
static void crypto_aes_Handle_inv_cipher(
    crypto_aes_Handle* self,
    crypto_aes_State* state_ptr
);
static void crypto_aes_Handle_add_round_key(
    crypto_aes_Handle* self,
    uint32_t round,
    crypto_aes_State* state_mut
);

static uint8_t crypto_aes_xtime(uint8_t x);
static uint8_t crypto_aes_multiply(uint8_t x, uint8_t y);
static void crypto_aes_xor_with_iv(uint8_t* buf_mut, const uint8_t* iv_ref);
static void crypto_aes_sub_bytes(crypto_aes_State* state_mut);
static void crypto_aes_shift_rows(crypto_aes_State* state_mut);
static void crypto_aes_mix_columns(crypto_aes_State* state_mut);
static void crypto_aes_inv_sub_bytes(crypto_aes_State* state_mut);
static void crypto_aes_inv_mix_columns(crypto_aes_State* state_mut);
static void crypto_aes_inv_shift_rows(crypto_aes_State* state_mut);

//==============================================================================
// PRIVATE VARIABLE DEFINITION
//==============================================================================
static const uint8_t crypto_aes_sbox_tbl[256] = {
    //  0      1      2      3      4      5      6      7
    0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U, // 0x00
    0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U, // 0x01
    0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U, // 0x02
    0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U, // 0x03
    0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU, // 0x04
    0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U, // 0x05
    0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU, // 0x06
    0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U, // 0x07
    0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U, // 0x08
    0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U, // 0x09
    0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU, // 0x0a
    0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU, // 0x0b
    0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U, // 0x0c
    0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U, // 0x0d
    0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U, // 0x0e
    0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U, // 0x0f
    0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U, // 0x10
    0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U, // 0x11
    0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U, // 0x12
    0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU, // 0x13
    0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU, // 0x14
    0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U, // 0x15
    0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U, // 0x16
    0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U, // 0x17
    0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U, // 0x18
    0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU, // 0x19
    0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU, // 0x1a
    0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU, // 0x1b
    0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U, // 0x1c
    0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU, // 0x1d
    0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U, // 0x1e
    0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U, // 0x1f
};

static const uint8_t crypto_aes_rsbox_tbl[256] = {
    //  0      1      2      3      4      5      6      7
    0x52U, 0x09U, 0x6aU, 0xd5U, 0x30U, 0x36U, 0xa5U, 0x38U, // 0x00
    0xbfU, 0x40U, 0xa3U, 0x9eU, 0x81U, 0xf3U, 0xd7U, 0xfbU, // 0x01
    0x7cU, 0xe3U, 0x39U, 0x82U, 0x9bU, 0x2fU, 0xffU, 0x87U, // 0x02
    0x34U, 0x8eU, 0x43U, 0x44U, 0xc4U, 0xdeU, 0xe9U, 0xcbU, // 0x03
    0x54U, 0x7bU, 0x94U, 0x32U, 0xa6U, 0xc2U, 0x23U, 0x3dU, // 0x04
    0xeeU, 0x4cU, 0x95U, 0x0bU, 0x42U, 0xfaU, 0xc3U, 0x4eU, // 0x05
    0x08U, 0x2eU, 0xa1U, 0x66U, 0x28U, 0xd9U, 0x24U, 0xb2U, // 0x06
    0x76U, 0x5bU, 0xa2U, 0x49U, 0x6dU, 0x8bU, 0xd1U, 0x25U, // 0x07
    0x72U, 0xf8U, 0xf6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U, // 0x08
    0xd4U, 0xa4U, 0x5cU, 0xccU, 0x5dU, 0x65U, 0xb6U, 0x92U, // 0x09
    0x6cU, 0x70U, 0x48U, 0x50U, 0xfdU, 0xedU, 0xb9U, 0xdaU, // 0x0a
    0x5eU, 0x15U, 0x46U, 0x57U, 0xa7U, 0x8dU, 0x9dU, 0x84U, // 0x0b
    0x90U, 0xd8U, 0xabU, 0x00U, 0x8cU, 0xbcU, 0xd3U, 0x0aU, // 0x0c
    0xf7U, 0xe4U, 0x58U, 0x05U, 0xb8U, 0xb3U, 0x45U, 0x06U, // 0x0d
    0xd0U, 0x2cU, 0x1eU, 0x8fU, 0xcaU, 0x3fU, 0x0fU, 0x02U, // 0x0e
    0xc1U, 0xafU, 0xbdU, 0x03U, 0x01U, 0x13U, 0x8aU, 0x6bU, // 0x0f
    0x3aU, 0x91U, 0x11U, 0x41U, 0x4fU, 0x67U, 0xdcU, 0xeaU, // 0x10
    0x97U, 0xf2U, 0xcfU, 0xceU, 0xf0U, 0xb4U, 0xe6U, 0x73U, // 0x11
    0x96U, 0xacU, 0x74U, 0x22U, 0xe7U, 0xadU, 0x35U, 0x85U, // 0x12
    0xe2U, 0xf9U, 0x37U, 0xe8U, 0x1cU, 0x75U, 0xdfU, 0x6eU, // 0x13
    0x47U, 0xf1U, 0x1aU, 0x71U, 0x1dU, 0x29U, 0xc5U, 0x89U, // 0x14
    0x6fU, 0xb7U, 0x62U, 0x0eU, 0xaaU, 0x18U, 0xbeU, 0x1bU, // 0x15
    0xfcU, 0x56U, 0x3eU, 0x4bU, 0xc6U, 0xd2U, 0x79U, 0x20U, // 0x16
    0x9aU, 0xdbU, 0xc0U, 0xfeU, 0x78U, 0xcdU, 0x5aU, 0xf4U, // 0x17
    0x1fU, 0xddU, 0xa8U, 0x33U, 0x88U, 0x07U, 0xc7U, 0x31U, // 0x18
    0xb1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xecU, 0x5fU, // 0x19
    0x60U, 0x51U, 0x7fU, 0xa9U, 0x19U, 0xb5U, 0x4aU, 0x0dU, // 0x1a
    0x2dU, 0xe5U, 0x7aU, 0x9fU, 0x93U, 0xc9U, 0x9cU, 0xefU, // 0x1b
    0xa0U, 0xe0U, 0x3bU, 0x4dU, 0xaeU, 0x2aU, 0xf5U, 0xb0U, // 0x1c
    0xc8U, 0xebU, 0xbbU, 0x3cU, 0x83U, 0x53U, 0x99U, 0x61U, // 0x1d
    0x17U, 0x2bU, 0x04U, 0x7eU, 0xbaU, 0x77U, 0xd6U, 0x26U, // 0x1e
    0xe1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0cU, 0x7dU, // 0x1f
};

static const uint8_t crypto_aes_rcon_tbl[11] = {
    0x8dU,
    0x01U,
    0x02U,
    0x04U,
    0x08U,
    0x10U,
    0x20U,
    0x40U,
    0x80U,
    0x1bU,
    0x36U,
};

//==============================================================================
// PUBLIC VARIABLE DEFINITION
//==============================================================================

//==============================================================================
// PUBLIC FUNCTION DEFINITION
//==============================================================================
/// @brief Synchronous AES encrypt, processes all data in one call
crypto_aes_Ret crypto_aes_encrypt(
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
) {
    crypto_aes_Handle handle;
    crypto_aes_Ret ret;

    // For ECB/CBC, PKCS#7 padding adds up to one full block
    // (worst case: block-aligned input).
    // Verify output buffer can hold the worst-case padded ciphertext.
    uint32_t min_out = input_num;
    if ((mode == crypto_aes_Mode_Ecb) || (mode == crypto_aes_Mode_Cbc)) {
        min_out = input_num + CRYPTO_AES_BLOCK_U8_SIZE;
    }
    if (output_buf_capacity < min_out) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_aes_Ret_BufferTooSmall;
    }

    ret = crypto_aes_Handle_init(
        &handle,
        keylen,
        mode,
        crypto_aes_Direction_Encrypt,
        key_buf_ptr,
        key_buf_capacity,
        iv_buf_ptr,
        iv_buf_capacity,
        output_buf_ptr,
        output_buf_capacity
    );
    if (ret != crypto_aes_Ret_Ok) {
        return ret;
    }

    ret = crypto_aes_Handle_update(&handle, input_buf_ptr, input_num);
    if (ret != crypto_aes_Ret_Ok) {
        return ret;
    }

    ret = crypto_aes_Handle_finalize(&handle);
    return ret;
}

/// @brief For synchronous decrypt, decrypt data at once
crypto_aes_Ret crypto_aes_decrypt(
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
) {
    crypto_aes_Handle handle;
    crypto_aes_Ret ret;

    ret = crypto_aes_Handle_init(
        &handle,
        keylen,
        mode,
        crypto_aes_Direction_Decrypt,
        key_buf_ptr,
        key_buf_capacity,
        iv_buf_ptr,
        iv_buf_capacity,
        output_buf_ptr,
        output_buf_capacity
    );
    if (ret != crypto_aes_Ret_Ok) {
        return ret;
    }

    (void)crypto_aes_Handle_update(&handle, input_buf_ptr, input_num);

    ret = crypto_aes_Handle_finalize(&handle);
    return ret;
}

/// For asynchronous encrypt/decrypt, init instance of class crypto_aes_Handle
crypto_aes_Ret crypto_aes_Handle_init(
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
) {
    bool is_valid = true;

    // Check keylen, key_buf_capacity
    switch (keylen) {
    case crypto_aes_KeyLen_128:
        if (key_buf_capacity < 128U / 8U) {
            is_valid = false;
        }
        break;
    case crypto_aes_KeyLen_192:
        if (key_buf_capacity < 192U / 8U) {
            is_valid = false;
        }
        break;
    case crypto_aes_KeyLen_256:
        if (key_buf_capacity < 256U / 8U) {
            is_valid = false;
        }
        break;
    default:
        is_valid = false;
        break;
    }
    if (is_valid == false) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_aes_Ret_InvalidArg;
    }

    // Check mode, iv_buf_ptr, iv_buf_capacity
    switch (mode) {
    case crypto_aes_Mode_Cbc:
    case crypto_aes_Mode_Ctr:
        if (iv_buf_ptr == NULL) {
            is_valid = false;
        }
        if (iv_buf_capacity < 16) {
            is_valid = false;
        }
        break;
    case crypto_aes_Mode_Ecb:
        break;
    default:
        is_valid = false;
        break;
    }
    if (is_valid == false) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_aes_Ret_InvalidArg;
    }

    // Check dir
    switch (dir) {
    case crypto_aes_Direction_Encrypt:
    case crypto_aes_Direction_Decrypt:
        break;
    default:
        is_valid = false;
        break;
    }
    if (is_valid == false) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_aes_Ret_InvalidArg;
    }

    // Check self, key_buf_ptr, output_buf_ptr
    if ((self == NULL) || //
        (key_buf_ptr == NULL) || //
        (output_buf_ptr == NULL)) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_aes_Ret_InvalidArg;
    }

    // Check output_buf_capacity
    // For ECB/CBC encrypt, PKCS#7 padding always produces at least one full
    // block (even for empty input), so output_buf_capacity must be >= 16.
    if (dir == crypto_aes_Direction_Encrypt) {
        if ((mode == crypto_aes_Mode_Ecb) || //
            (mode == crypto_aes_Mode_Cbc)) {
            if (output_buf_capacity < CRYPTO_AES_BLOCK_U8_SIZE) {
                CRYPTO_PLATFORM_ASSERT(false);
                return crypto_aes_Ret_BufferTooSmall;
            }
        }
    }

    self->key_buf_ptr = key_buf_ptr;
    self->mode = mode;
    self->dir = dir;
    self->keylen = keylen;
    self->buf_len = 0U;
    self->result_buf_ptr = output_buf_ptr;
    self->result_buf_capacity = output_buf_capacity;
    self->result_len = 0U;
    crypto_util_memset(self->buf, 0U, CRYPTO_AES_BLOCK_U8_SIZE);
    if ((mode == crypto_aes_Mode_Cbc) || (mode == crypto_aes_Mode_Ctr)) {
        self->iv_buf_ptr = iv_buf_ptr;
        memcpy(self->iv_buf, iv_buf_ptr, CRYPTO_AES_BLOCK_U8_SIZE);
    }

    switch (keylen) {
    case crypto_aes_KeyLen_128:
        self->key_u32_num = 4U;
        self->round_num = 10U;
        break;
    case crypto_aes_KeyLen_192:
        self->key_u32_num = 6U;
        self->round_num = 12U;
        break;
    case crypto_aes_KeyLen_256:
        self->key_u32_num = 8U;
        self->round_num = 14U;
        break;
    default:
        // keylen has already been checked above
        break;
    }

    crypto_aes_Handle_key_expansion(self);

    return crypto_aes_Ret_Ok;
}

/// @brief For asynchronous encrypt/decrypt, update input data
crypto_aes_Ret crypto_aes_Handle_update(
    crypto_aes_Handle* self,
    const uint8_t* input_buf_ptr,
    uint32_t input_num
) {
    // Check self, input_buf_ptr
    if ((self == NULL) || //
        (input_buf_ptr == NULL)) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_aes_Ret_InvalidArg;
    }

    // Check input_num
    if (input_num == 0U) {
        return crypto_aes_Ret_Ok;
    }

    uint32_t in_pos = 0U;

    while (in_pos < input_num) {
        // For ECB/CBC Decryption, we delay processing a full 16-byte block
        // until we know it's not the last block (i.e. more data is coming).
        if (self->dir == crypto_aes_Direction_Decrypt) {
            if ((self->mode == crypto_aes_Mode_Ecb) ||
                (self->mode == crypto_aes_Mode_Cbc)) {
                if (self->buf_len == CRYPTO_AES_BLOCK_U8_SIZE) {
                    memcpy(
                        self->result_buf_ptr,
                        self->buf,
                        CRYPTO_AES_BLOCK_U8_SIZE
                    );
                    if (self->mode == crypto_aes_Mode_Ecb) {
                        crypto_aes_Handle_ecb_decrypt(
                            self,
                            self->result_buf_ptr
                        );
                    } else {
                        crypto_aes_Handle_cbc_decrypt(
                            self,
                            self->result_buf_ptr
                        );
                    }
                    self->result_buf_ptr += CRYPTO_AES_BLOCK_U8_SIZE;
                    self->result_len += CRYPTO_AES_BLOCK_U8_SIZE;
                    self->buf_len = 0;
                }
            }
        }

        uint32_t space = CRYPTO_AES_BLOCK_U8_SIZE - self->buf_len;
        uint32_t copy_len =
            (input_num - in_pos) < space ? (input_num - in_pos) : space;
        crypto_util_memcpy(
            &self->buf[self->buf_len],
            &input_buf_ptr[in_pos],
            copy_len
        );
        self->buf_len += copy_len;
        in_pos += copy_len;

        // For Encryption and CTR mode, process as soon as we have 16 bytes
        if (self->buf_len == CRYPTO_AES_BLOCK_U8_SIZE) {
            if ((self->mode == crypto_aes_Mode_Ecb ||
                 self->mode == crypto_aes_Mode_Cbc) &&
                self->dir == crypto_aes_Direction_Decrypt) {
                // Skip processing here, will process in the next iteration or
                // finalize
                continue;
            }

            crypto_util_memcpy(
                self->result_buf_ptr,
                self->buf,
                CRYPTO_AES_BLOCK_U8_SIZE
            );
            if (self->mode == crypto_aes_Mode_Ecb) {
                crypto_aes_Handle_ecb_encrypt(self);
            } else if (self->mode == crypto_aes_Mode_Cbc) {
                crypto_aes_Handle_cbc_encrypt(self);
            } else if (self->mode == crypto_aes_Mode_Ctr) {
                crypto_aes_Handle_ctr_xcrypt(self);
            } else {
                // Mode has been guarded when init
            }
            self->result_buf_ptr += CRYPTO_AES_BLOCK_U8_SIZE;
            self->result_len += CRYPTO_AES_BLOCK_U8_SIZE;
            self->buf_len = 0;
        }
    }

    return crypto_aes_Ret_Ok;
}

/// For asynchronous encrypt/decrypt, finalize the encrypt/decrypt output
crypto_aes_Ret crypto_aes_Handle_finalize(crypto_aes_Handle* self) {
    if (self == NULL) {
        return crypto_aes_Ret_InvalidArg;
    }

    crypto_aes_Ret ret = crypto_aes_Ret_Ok;

    if ((self->mode == crypto_aes_Mode_Ecb) ||
        (self->mode == crypto_aes_Mode_Cbc)) {
        if (self->dir == crypto_aes_Direction_Encrypt) {
            // PKCS#7 Padding — always applied, even for block-aligned input
            // (which requires a full padding block).
            uint32_t padded_len = 0U;
            uint8_t padded_buf[CRYPTO_AES_BLOCK_U8_SIZE];

            (void)crypto_padding_pkcs7_pad(
                self->buf,
                self->buf_len,
                CRYPTO_AES_BLOCK_U8_SIZE,
                padded_buf,
                sizeof(padded_buf),
                &padded_len
            );

            if (self->result_buf_capacity >= (self->result_len + padded_len)) {
                crypto_util_memcpy(
                    self->result_buf_ptr,
                    padded_buf,
                    padded_len
                );
            } else {
                return crypto_aes_Ret_BufferTooSmall;
            }

            if (self->mode == crypto_aes_Mode_Ecb) {
                crypto_aes_Handle_ecb_encrypt(self);
            } else {
                crypto_aes_Handle_cbc_encrypt(self);
            }
            self->result_buf_ptr += padded_len;
            self->result_len += padded_len;
        } else {
            // PKCS#7 Unpadding
            if ((self->buf_len != 0U) &&
                (self->buf_len != CRYPTO_AES_BLOCK_U8_SIZE)) {
                ret = crypto_aes_Ret_CipherTextNotAligned;
                goto cleanup;
            }
            if (self->buf_len == CRYPTO_AES_BLOCK_U8_SIZE) {
                uint32_t unpadded_len = 0U;
                uint8_t temp[CRYPTO_AES_BLOCK_U8_SIZE];

                crypto_util_memcpy(temp, self->buf, CRYPTO_AES_BLOCK_U8_SIZE);
                if (self->mode == crypto_aes_Mode_Ecb) {
                    crypto_aes_Handle_ecb_decrypt(self, temp);
                } else {
                    crypto_aes_Handle_cbc_decrypt(self, temp);
                }

                crypto_padding_Ret pad_ret = crypto_padding_pkcs7_unpad(
                    temp,
                    CRYPTO_AES_BLOCK_U8_SIZE,
                    CRYPTO_AES_BLOCK_U8_SIZE,
                    self->result_buf_ptr,
                    self->result_buf_capacity - self->result_len,
                    &unpadded_len
                );

                if (pad_ret != crypto_padding_Ret_Ok) {
                    ret = crypto_aes_Ret_CipherTextNotAligned;
                    goto cleanup;
                }

                self->result_buf_ptr += unpadded_len;
                self->result_len += unpadded_len;
            }
        }
    } else if (self->mode == crypto_aes_Mode_Ctr) {
        if (self->buf_len > 0) {

            if (self->result_buf_capacity >=
                (self->result_len + self->buf_len)) {
                crypto_util_memcpy(
                    self->result_buf_ptr,
                    self->buf,
                    self->buf_len
                );
            } else {
                return crypto_aes_Ret_BufferTooSmall;
            }

            crypto_aes_Handle_ctr_xcrypt(self);
            self->result_buf_ptr += self->buf_len;
            self->result_len += self->buf_len;
        }
    } else {
        // Mode has been guarded when init
    }

cleanup:
    // Securely wipe sensitive key material and internal state from memory

    // FIXME: Fix it
    // crypto_util_memset(self, 0, sizeof(crypto_aes_Handle));
    return ret;
}

//==============================================================================
// PRIVATE FUNCTION DEFINITION
//==============================================================================
static void crypto_aes_Handle_ecb_encrypt(crypto_aes_Handle* self) {
    crypto_aes_State state;
    memcpy((void*)&state, (void*)self->result_buf_ptr, sizeof(state));
    crypto_aes_Handle_cipher(self, &state);
    memcpy((void*)self->result_buf_ptr, (void*)&state, sizeof(state));
}

static void crypto_aes_Handle_ecb_decrypt(
    crypto_aes_Handle* self,
    uint8_t* buf_mut
) {
    crypto_aes_State state;
    memcpy((void*)&state, (void*)buf_mut, sizeof(state));
    crypto_aes_Handle_inv_cipher(self, &state);
    memcpy((void*)buf_mut, (void*)&state, sizeof(state));
}

static void crypto_aes_Handle_cbc_encrypt(crypto_aes_Handle* self) {
    uint8_t* buf_mut = self->result_buf_ptr;
    uint8_t* iv_mut = self->iv_buf;
    crypto_aes_State state;

    crypto_aes_xor_with_iv(buf_mut, iv_mut);
    memcpy((void*)&state, (void*)buf_mut, sizeof(state));
    crypto_aes_Handle_cipher(self, &state);
    memcpy((void*)buf_mut, (void*)&state, sizeof(state));
    iv_mut = buf_mut;

    memcpy(self->iv_buf, iv_mut, CRYPTO_AES_BLOCK_U8_SIZE);
}

static void crypto_aes_Handle_cbc_decrypt(
    crypto_aes_Handle* self,
    uint8_t* buf_mut
) {
    uint32_t i;
    uint8_t store_next_iv_buf[CRYPTO_AES_BLOCK_U8_SIZE];
    for (i = 0; i < self->buf_len; i += CRYPTO_AES_BLOCK_U8_SIZE) {
        memcpy(store_next_iv_buf, buf_mut, CRYPTO_AES_BLOCK_U8_SIZE);
        crypto_aes_State state;
        memcpy((void*)&state, (void*)buf_mut, sizeof(state));
        crypto_aes_Handle_inv_cipher(self, &state);
        memcpy((void*)buf_mut, (void*)&state, sizeof(state));
        crypto_aes_xor_with_iv(buf_mut, self->iv_buf);
        memcpy(self->iv_buf, store_next_iv_buf, CRYPTO_AES_BLOCK_U8_SIZE);
        buf_mut += CRYPTO_AES_BLOCK_U8_SIZE;
    }
}

static void crypto_aes_Handle_ctr_xcrypt(crypto_aes_Handle* self) {
    uint32_t i = 0U;
    uint8_t keystream_buf[CRYPTO_AES_BLOCK_U8_SIZE];
    crypto_util_memset(keystream_buf, 0U, sizeof(keystream_buf));

    while (i < self->buf_len) {
        // Generate a new block of keystream
        crypto_aes_State state;
        memcpy(keystream_buf, self->iv_buf, CRYPTO_AES_BLOCK_U8_SIZE);
        memcpy((void*)&state, (void*)keystream_buf, sizeof(state));
        crypto_aes_Handle_cipher(self, &state);
        memcpy((void*)keystream_buf, (void*)&state, sizeof(state));

        // Increment the IV (Counter) for the next block
        for (uint32_t j = CRYPTO_AES_BLOCK_U8_SIZE; j > 0U; j--) {
            self->iv_buf[j - 1U]++;
            if (self->iv_buf[j - 1U] != 0U) {
                break;
            }
        }

        // XOR the keystream with the data
        uint32_t bytes_to_process = self->buf_len - i;
        if (bytes_to_process > CRYPTO_AES_BLOCK_U8_SIZE) {
            bytes_to_process = CRYPTO_AES_BLOCK_U8_SIZE;
        }

        for (uint32_t bi = 0U; bi < bytes_to_process; bi++) {
            self->result_buf_ptr[i] ^= keystream_buf[bi];
            i++;
        }
    }
}

static void crypto_aes_Handle_add_round_key(
    crypto_aes_Handle* self,
    uint32_t round,
    crypto_aes_State* state_mut
) {
    uint32_t i = 0U;
    uint32_t j = 0U;

    // Iterate over columns
    for (i = 0U; i < 4U; i++) {
        // Iterate over rows within the column
        for (j = 0U; j < 4U; j++) {
            state_mut->col[i].byte[j] ^=
                self->round_key_buf[(round * 16) + (i * 4) + j];
        }
    }
}

static void crypto_aes_Handle_cipher(
    crypto_aes_Handle* self,
    crypto_aes_State* state_mut
) {
    // Initial round: Add the first round key
    crypto_aes_Handle_add_round_key(self, 0, state_mut);

    // Main rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey
    for (uint8_t round = 1; round < self->round_num; round++) {
        crypto_aes_sub_bytes(state_mut);
        crypto_aes_shift_rows(state_mut);
        crypto_aes_mix_columns(state_mut);
        crypto_aes_Handle_add_round_key(self, round, state_mut);
    }

    // Final round: SubBytes, ShiftRows, AddRoundKey (No MixColumns)
    crypto_aes_sub_bytes(state_mut);
    crypto_aes_shift_rows(state_mut);
    crypto_aes_Handle_add_round_key(self, self->round_num, state_mut);
}

static void crypto_aes_Handle_inv_cipher(
    crypto_aes_Handle* self,
    crypto_aes_State* state_ptr
) {
    // Initial round: Add the last round key
    crypto_aes_Handle_add_round_key(self, self->round_num, state_ptr);

    // Main rounds: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
    for (uint32_t round = (self->round_num - 1); round > 0U; round--) {
        crypto_aes_inv_shift_rows(state_ptr);
        crypto_aes_inv_sub_bytes(state_ptr);
        crypto_aes_Handle_add_round_key(self, round, state_ptr);
        crypto_aes_inv_mix_columns(state_ptr);
    }

    // Final round: InvShiftRows, InvSubBytes, AddRoundKey (No InvMixColumns)
    crypto_aes_inv_shift_rows(state_ptr);
    crypto_aes_inv_sub_bytes(state_ptr);
    crypto_aes_Handle_add_round_key(self, 0, state_ptr);
}

static void crypto_aes_Handle_key_expansion(crypto_aes_Handle* self) {
    uint32_t i, j, k;
    uint8_t temp_word[4];
    uint8_t* round_key_mut = self->round_key_buf;
    const uint8_t* key_ref = self->key_buf_ptr;
    uint32_t key_u32_num = self->key_u32_num;
    uint32_t round_num = self->round_num;

    // The first round key is the key itself.
    for (i = 0; i < key_u32_num; i++) {
        round_key_mut[(i * 4)] = key_ref[(i * 4)];
        round_key_mut[(i * 4) + 1] = key_ref[(i * 4) + 1];
        round_key_mut[(i * 4) + 2] = key_ref[(i * 4) + 2];
        round_key_mut[(i * 4) + 3] = key_ref[(i * 4) + 3];
    }

    // All other round keys are derived from the previous round keys.
    for (i = key_u32_num; i < CRYPTO_AES_NB * (round_num + 1); i++) {
        k = (i - 1) * 4;
        temp_word[0] = round_key_mut[k];
        temp_word[1] = round_key_mut[k + 1];
        temp_word[2] = round_key_mut[k + 2];
        temp_word[3] = round_key_mut[k + 3];

        if (i % key_u32_num == 0) {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
            const uint8_t temp_byte = temp_word[0];
            temp_word[0] = temp_word[1];
            temp_word[1] = temp_word[2];
            temp_word[2] = temp_word[3];
            temp_word[3] = temp_byte;

            // SubBytes: replace each byte using the S-box
            temp_word[0] = crypto_aes_sbox_tbl[temp_word[0]];
            temp_word[1] = crypto_aes_sbox_tbl[temp_word[1]];
            temp_word[2] = crypto_aes_sbox_tbl[temp_word[2]];
            temp_word[3] = crypto_aes_sbox_tbl[temp_word[3]];

            // XOR with round constant (Rcon)
            temp_word[0] = temp_word[0] ^ crypto_aes_rcon_tbl[i / key_u32_num];
        }

        // AES256, 256/32 = 8 words per key
        if (key_u32_num == 8) {
            if (i % key_u32_num == 4) {
                // Extra SubBytes step for AES-256
                temp_word[0] = crypto_aes_sbox_tbl[temp_word[0]];
                temp_word[1] = crypto_aes_sbox_tbl[temp_word[1]];
                temp_word[2] = crypto_aes_sbox_tbl[temp_word[2]];
                temp_word[3] = crypto_aes_sbox_tbl[temp_word[3]];
            }
        }

        j = i * 4;
        k = (i - key_u32_num) * 4;
        // XOR with the word `key_u32_num` positions earlier
        round_key_mut[j] = round_key_mut[k] ^ temp_word[0];
        round_key_mut[j + 1] = round_key_mut[k + 1] ^ temp_word[1];
        round_key_mut[j + 2] = round_key_mut[k + 2] ^ temp_word[2];
        round_key_mut[j + 3] = round_key_mut[k + 3] ^ temp_word[3];
    }
}

static void crypto_aes_inv_sub_bytes(crypto_aes_State* state_mut) {
    uint8_t i, j;
    for (i = 0; i < 4; i++) { // iterate over columns
        for (j = 0; j < 4; j++) { // iterate over rows
            state_mut->col[i].byte[j] =
                crypto_aes_rsbox_tbl[state_mut->col[i].byte[j]];
        }
    }
}

static void crypto_aes_xor_with_iv(uint8_t* buf_mut, const uint8_t* iv_ref) {
    uint8_t i;
    // The block in AES is always 128bit no matter the key size
    for (i = 0; i < CRYPTO_AES_BLOCK_U8_SIZE; i++) {
        buf_mut[i] ^= iv_ref[i];
    }
}

static void crypto_aes_sub_bytes(crypto_aes_State* state_mut) {
    uint8_t i, j;
    for (i = 0; i < 4; i++) { // iterate over columns
        for (j = 0; j < 4; j++) { // iterate over rows
            state_mut->col[i].byte[j] =
                crypto_aes_sbox_tbl[state_mut->col[i].byte[j]];
        }
    }
}

static void crypto_aes_shift_rows(crypto_aes_State* state_mut) {
    uint8_t temp;

    // Rotate first row 1 columns to left
    temp = state_mut->col[0].byte[1];
    state_mut->col[0].byte[1] = state_mut->col[1].byte[1];
    state_mut->col[1].byte[1] = state_mut->col[2].byte[1];
    state_mut->col[2].byte[1] = state_mut->col[3].byte[1];
    state_mut->col[3].byte[1] = temp;

    // Rotate second row 2 columns to left
    temp = state_mut->col[0].byte[2];
    state_mut->col[0].byte[2] = state_mut->col[2].byte[2];
    state_mut->col[2].byte[2] = temp;

    temp = state_mut->col[1].byte[2];
    state_mut->col[1].byte[2] = state_mut->col[3].byte[2];
    state_mut->col[3].byte[2] = temp;

    // Rotate third row 3 columns to left
    temp = state_mut->col[0].byte[3];
    state_mut->col[0].byte[3] = state_mut->col[3].byte[3];
    state_mut->col[3].byte[3] = state_mut->col[2].byte[3];
    state_mut->col[2].byte[3] = state_mut->col[1].byte[3];
    state_mut->col[1].byte[3] = temp;
}

static uint8_t crypto_aes_xtime(uint8_t x) {
    return ((x << 1U) ^ (((x >> 7U) & 1U) * 0x1bU));
}

static void crypto_aes_mix_columns(crypto_aes_State* state_mut) {
    uint8_t i;
    uint8_t temp_col_xor; // XOR sum of all bytes in a column
    uint8_t temp_xor_adj; // XOR sum of adjacent bytes
    uint8_t original_col_0;

    for (i = 0; i < 4; i++) { // iterate over columns
        original_col_0 = state_mut->col[i].byte[0];

        // Calculate the XOR sum of all 4 bytes in the current column
        temp_col_xor = state_mut->col[i].byte[0] ^ state_mut->col[i].byte[1] ^
                       state_mut->col[i].byte[2] ^ state_mut->col[i].byte[3];

        // Mix row 0
        temp_xor_adj = state_mut->col[i].byte[0] ^ state_mut->col[i].byte[1];
        temp_xor_adj = crypto_aes_xtime(temp_xor_adj);
        state_mut->col[i].byte[0] ^= temp_xor_adj ^ temp_col_xor;

        // Mix row 1
        temp_xor_adj = state_mut->col[i].byte[1] ^ state_mut->col[i].byte[2];
        temp_xor_adj = crypto_aes_xtime(temp_xor_adj);
        state_mut->col[i].byte[1] ^= temp_xor_adj ^ temp_col_xor;

        // Mix row 2
        temp_xor_adj = state_mut->col[i].byte[2] ^ state_mut->col[i].byte[3];
        temp_xor_adj = crypto_aes_xtime(temp_xor_adj);
        state_mut->col[i].byte[2] ^= temp_xor_adj ^ temp_col_xor;

        // Mix row 3
        temp_xor_adj = state_mut->col[i].byte[3] ^ original_col_0;
        temp_xor_adj = crypto_aes_xtime(temp_xor_adj);
        state_mut->col[i].byte[3] ^= temp_xor_adj ^ temp_col_xor;
    }
}

static uint8_t crypto_aes_multiply(uint8_t x, uint8_t y) {
    uint8_t xtime_x;
    uint8_t result = ((y & 1U) * x);

    xtime_x = crypto_aes_xtime(x);
    result ^= (((y >> 1U) & 1U) * xtime_x);

    xtime_x = crypto_aes_xtime(x);
    xtime_x = crypto_aes_xtime(xtime_x);
    result ^= (((y >> 2U) & 1U) * xtime_x);

    xtime_x = crypto_aes_xtime(x);
    xtime_x = crypto_aes_xtime(xtime_x);
    xtime_x = crypto_aes_xtime(xtime_x);
    result ^= (((y >> 3U) & 1U) * xtime_x);

    xtime_x = crypto_aes_xtime(x);
    xtime_x = crypto_aes_xtime(xtime_x);
    xtime_x = crypto_aes_xtime(xtime_x);
    xtime_x = crypto_aes_xtime(xtime_x);
    result ^= (((y >> 4U) & 1U) * xtime_x);

    return result;
}

static void crypto_aes_inv_mix_columns(crypto_aes_State* state_mut) {
    int32_t i;
    uint8_t a, b, c, d;

    for (i = 0; i < 4; i++) { // iterate over columns
        a = state_mut->col[i].byte[0];
        b = state_mut->col[i].byte[1];
        c = state_mut->col[i].byte[2];
        d = state_mut->col[i].byte[3];

        state_mut->col[i].byte[0] =
            crypto_aes_multiply(a, 0x0e) ^ crypto_aes_multiply(b, 0x0b) ^
            crypto_aes_multiply(c, 0x0d) ^ crypto_aes_multiply(d, 0x09);
        state_mut->col[i].byte[1] =
            crypto_aes_multiply(a, 0x09) ^ crypto_aes_multiply(b, 0x0e) ^
            crypto_aes_multiply(c, 0x0b) ^ crypto_aes_multiply(d, 0x0d);
        state_mut->col[i].byte[2] =
            crypto_aes_multiply(a, 0x0d) ^ crypto_aes_multiply(b, 0x09) ^
            crypto_aes_multiply(c, 0x0e) ^ crypto_aes_multiply(d, 0x0b);
        state_mut->col[i].byte[3] =
            crypto_aes_multiply(a, 0x0b) ^ crypto_aes_multiply(b, 0x0d) ^
            crypto_aes_multiply(c, 0x09) ^ crypto_aes_multiply(d, 0x0e);
    }
}

static void crypto_aes_inv_shift_rows(crypto_aes_State* state_mut) {
    uint8_t temp;

    // Rotate first row 1 columns to right
    temp = state_mut->col[3].byte[1];
    state_mut->col[3].byte[1] = state_mut->col[2].byte[1];
    state_mut->col[2].byte[1] = state_mut->col[1].byte[1];
    state_mut->col[1].byte[1] = state_mut->col[0].byte[1];
    state_mut->col[0].byte[1] = temp;

    // Rotate second row 2 columns to right
    temp = state_mut->col[0].byte[2];
    state_mut->col[0].byte[2] = state_mut->col[2].byte[2];
    state_mut->col[2].byte[2] = temp;

    temp = state_mut->col[1].byte[2];
    state_mut->col[1].byte[2] = state_mut->col[3].byte[2];
    state_mut->col[3].byte[2] = temp;

    // Rotate third row 3 columns to right
    temp = state_mut->col[0].byte[3];
    state_mut->col[0].byte[3] = state_mut->col[1].byte[3];
    state_mut->col[1].byte[3] = state_mut->col[2].byte[3];
    state_mut->col[2].byte[3] = state_mut->col[3].byte[3];
    state_mut->col[3].byte[3] = temp;
}

//==============================================================================
// TEST
//==============================================================================
#define CRYPTO_AES_DEBUG (1U)

#if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
#include <stdio.h>
#endif // #if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)

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
    crypto_util_memset(cipher_buf, 0U, sizeof(cipher_buf));

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
#if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        return __LINE__;
    }

    int32_t ret = crypto_util_memcmp(
        expected_cipher_buf,
        cipher_buf,
        sizeof(expected_cipher_buf)
    );
    if (ret != 0) {
#if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
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
#endif // #if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
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
    crypto_util_memset(plain_buf, 0U, sizeof(plain_buf));

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
#if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        return __LINE__;
    }

    int32_t ret = crypto_util_memcmp(
        expected_plain_buf,
        plain_buf,
        sizeof(expected_plain_buf)
    );
    if (ret != 0) {
#if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
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
#endif // #if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
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
    crypto_util_memset(cipher_buf, 0U, sizeof(cipher_buf));

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
#if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        return __LINE__;
    }

    int32_t ret = crypto_util_memcmp(
        expected_cipher_buf,
        cipher_buf,
        sizeof(expected_cipher_buf)
    );
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
    crypto_util_memset(plain_buf, 0U, sizeof(plain_buf));
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
#if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        return __LINE__;
    }

    int32_t ret = crypto_util_memcmp(
        expected_plain_buf,
        plain_buf,
        sizeof(expected_plain_buf)
    );
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
    crypto_util_memset(cipher_buf, 0U, sizeof(cipher_buf));

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
#if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        return __LINE__;
    }

    int32_t ret = crypto_util_memcmp(
        expected_cipher_buf,
        cipher_buf,
        sizeof(expected_cipher_buf)
    );
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
    crypto_util_memset(plain_buf, 0U, sizeof(plain_buf));
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
#if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        printf("\naes_ret = %d\n", aes_ret);
#endif // #if defined(CRYPTO_AES_DEBUG) && (CRYPTO_AES_DEBUG > 0U)
        return __LINE__;
    }

    int32_t ret = crypto_util_memcmp(
        expected_plain_buf,
        plain_buf,
        sizeof(expected_plain_buf)
    );
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static int32_t crypto_aes_test_tc7(void) {
    // clang-format off
    uint8_t plain_buf[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    uint8_t key_buf[128 / 8] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    uint8_t expected_cipher_buf[80] = {
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
    uint8_t cipher_buf[80];
    crypto_util_memset(cipher_buf, 0U, sizeof(cipher_buf));
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

    int32_t ret = crypto_util_memcmp(
        expected_cipher_buf,
        cipher_buf,
        sizeof(expected_cipher_buf)
    );
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

int32_t crypto_aes_test(void) {
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

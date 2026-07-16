//==============================================================================
/// @file       crypto_padding.c
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      Padding algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==============================================================================
//==============================================================================
// INCLUDE
//==============================================================================
#include "crypto_padding.h"
#include "crypto_platform.h"
#include "crypto_util.h"

//==============================================================================
// IMPORTED SWITCH CHECK
//==============================================================================

//==============================================================================
// PRIVATE DEFINE
//==============================================================================

//==============================================================================
// PRIVATE TYPEDEF
//==============================================================================

//==============================================================================
// PRIVATE ENUM
//==============================================================================

//==============================================================================
// PRIVATE STRUCT
//==============================================================================

//==============================================================================
// PRIVATE UNION
//==============================================================================

//==============================================================================
// PRIVATE FUNCTION DECLARATION
//==============================================================================

//==============================================================================
// PRIVATE VARIABLE DEFINITION
//==============================================================================

//==============================================================================
// PUBLIC VARIABLE DEFINITION
//==============================================================================

//==============================================================================
// PUBLIC FUNCTION DEFINITION
//==============================================================================
/// @brief Apply PKCS#7 padding to input data
crypto_padding_Ret crypto_padding_pkcs7_pad(
    const uint8_t* input_buf_ptr,
    uint32_t input_num,
    uint8_t block_size,
    uint8_t* output_buf_ptr,
    uint32_t output_capacity,
    uint32_t* output_num_ptr
) {
    uint8_t pad_val = 0U;
    uint32_t padded_len = 0U;

    if ((input_buf_ptr == NULL) || //
        (output_buf_ptr == NULL) || //
        (output_num_ptr == NULL)) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_padding_Ret_InvalidArg;
    }

    if ((block_size == 0U) || (block_size > 255U)) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_padding_Ret_InvalidArg;
    }

    pad_val = block_size - (uint8_t)(input_num % (uint32_t)block_size);
    padded_len = input_num + (uint32_t)pad_val;

    if (padded_len > output_capacity) {
        return crypto_padding_Ret_BufferTooSmall;
    }

    // Copy input data
    if (input_num > 0U) {
        crypto_util_memcpy(output_buf_ptr, input_buf_ptr, input_num);
    }

    // Append padding bytes
    crypto_util_memset(output_buf_ptr + input_num, pad_val, (uint32_t)pad_val);

    *output_num_ptr = padded_len;
    return crypto_padding_Ret_Ok;
}

/// @brief Remove PKCS#7 padding from data and validate
crypto_padding_Ret crypto_padding_pkcs7_unpad(
    const uint8_t* input_buf_ptr,
    uint32_t input_num,
    uint8_t block_size,
    uint8_t* output_buf_ptr,
    uint32_t output_capacity,
    uint32_t* output_num_ptr
) {
    uint8_t pad_val = 0U;
    uint32_t i = 0U;
    const uint8_t* pad_start_ptr = NULL;

    if ((input_buf_ptr == NULL) || //
        (output_buf_ptr == NULL) || //
        (output_num_ptr == NULL)) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_padding_Ret_InvalidArg;
    }

    if ((block_size == 0U) || (block_size > 255U)) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_padding_Ret_InvalidArg;
    }

    if ((input_num == 0U) || ((input_num % (uint32_t)block_size) != 0U)) {
        CRYPTO_PLATFORM_ASSERT(false);
        return crypto_padding_Ret_BadPadding;
    }

    pad_val = input_buf_ptr[input_num - 1U];

    // pad_val must be in range [1, block_size]
    if ((pad_val == 0U) || (pad_val > block_size)) {
        return crypto_padding_Ret_BadPadding;
    }

    // Verify all padding bytes equal pad_val
    pad_start_ptr = &input_buf_ptr[input_num - (uint32_t)pad_val];
    for (i = 0U; i < pad_val; i++) {
        if (pad_start_ptr[i] != pad_val) {
            return crypto_padding_Ret_BadPadding;
        }
    }

    *output_num_ptr = input_num - (uint32_t)pad_val;

    if (*output_num_ptr > output_capacity) {
        return crypto_padding_Ret_BufferTooSmall;
    }

    if (*output_num_ptr > 0U) {
        crypto_util_memcpy(output_buf_ptr, input_buf_ptr, *output_num_ptr);
    }

    return crypto_padding_Ret_Ok;
}

//==============================================================================
// PRIVATE FUNCTION DEFINITION
//==============================================================================

//==============================================================================
// TEST
//==============================================================================

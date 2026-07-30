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
#include <string.h>

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
/// @details PKCS#7 always appends at least 1 byte of padding. If the input is
///          already block-aligned, a full block of padding is appended.
///          pad_val = block_size - (input_len % block_size), repeated pad_val
///          times.
/// @param[in]  input_ref       Input data buffer
/// @param[in]  input_len       Input data length in bytes
/// @param[in]  block_size      Block size in bytes (typically 16 for AES)
/// @param[out] output_mut      Output buffer for padded data
/// @param[in]  output_capacity Output buffer capacity in bytes
/// @param[out] output_len_mut  Actual padded output length
/// @return crypto_padding_Ret_Ok on success
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
        crypto_platform_assert(false);
        return crypto_padding_Ret_InvalidArg;
    }

    if ((block_size == 0U) || (block_size > 255U)) {
        crypto_platform_assert(false);
        return crypto_padding_Ret_InvalidArg;
    }

    pad_val = block_size - (uint8_t)(input_num % (uint32_t)block_size);
    padded_len = input_num + (uint32_t)pad_val;

    if (padded_len > output_capacity) {
        return crypto_padding_Ret_BufferTooSmall;
    }

    // Copy input data
    if (input_num > 0U) {
        memcpy(output_buf_ptr, input_buf_ptr, input_num);
    }

    // Append padding bytes
    crypto_util_memset(&output_buf_ptr[input_num], pad_val, (uint32_t)pad_val);

    *output_num_ptr = padded_len;
    return crypto_padding_Ret_Ok;
}

/// @brief Remove PKCS#7 padding from data and validate
/// @details Reads the last byte as the pad value, verifies all padding bytes
///          match, and writes the unpadded output.
/// @param[in]  input_ref       Padded input buffer
/// @param[in]  input_len       Padded input length (must be > 0, multiple of
/// block_size)
/// @param[in]  block_size      Block size in bytes (typically 16 for AES)
/// @param[out] output_mut      Output buffer for unpadded data
/// @param[in]  output_capacity Output buffer capacity in bytes
/// @param[out] output_len_mut  Actual unpadded output length
/// @return crypto_padding_Ret_Ok on success, BadPadding if validation fails
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
        crypto_platform_assert(false);
        return crypto_padding_Ret_InvalidArg;
    }

    if ((block_size == 0U) || (block_size > 255U)) {
        crypto_platform_assert(false);
        return crypto_padding_Ret_InvalidArg;
    }

    if ((input_num == 0U) || ((input_num % (uint32_t)block_size) != 0U)) {
        crypto_platform_assert(false);
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
        memcpy(output_buf_ptr, input_buf_ptr, *output_num_ptr);
    }

    return crypto_padding_Ret_Ok;
}

//==============================================================================
// PRIVATE FUNCTION DEFINITION
//==============================================================================

//==============================================================================
// TEST
//==============================================================================

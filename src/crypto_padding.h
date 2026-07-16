//=============================================================================
/// @file       crypto_padding.h
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      Padding algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==============================================================================
//==============================================================================
// GUARD START
//==============================================================================
#ifndef CRYPTO_PADDING_H
#define CRYPTO_PADDING_H
#ifdef __cplusplus
extern "C" {
#endif
//==============================================================================
// INCLUDE
//==============================================================================
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

//==============================================================================
// PUBLIC TYPEDEF
//==============================================================================

//==============================================================================
// PUBLIC MACRO
//==============================================================================

//==============================================================================
// PUBLIC ENUM
//==============================================================================
typedef enum {
    crypto_padding_Ret_Ok = 0U,
    crypto_padding_Ret_InvalidArg,
    crypto_padding_Ret_BufferTooSmall,
    crypto_padding_Ret_BadPadding,
} crypto_padding_Ret;

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
);

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
);

//==============================================================================
// GUARD END
//==============================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_PADDING_H

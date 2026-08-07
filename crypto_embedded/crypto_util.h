//==============================================================================
/// @file       crypto_util.h
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      Crypto utility
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==============================================================================
//==============================================================================
// GUARD START
//==============================================================================
#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H
#ifdef __cplusplus
extern "C" {
#endif
//==============================================================================
// INCLUDE
//==============================================================================
#include <stdbool.h>
#include <stdint.h>
#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
#include <assert.h>
#endif

//==============================================================================
// PUBLIC TYPEDEF
//==============================================================================

//==============================================================================
// PUBLIC MACRO
//==============================================================================
#define CRYPTO_UTIL_STATIC_ASSERT(name, cond)                                  \
    typedef char name##_failed_at_line_##__LINE__[(cond) ? 1 : -1]

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

//==============================================================================
// PUBLIC INLINE FUNCTION DEFINITION
//==============================================================================
static inline void crypto_util_memset(
    uint8_t *dst_ptr,
    uint8_t val,
    uint32_t len
) {
    for (uint32_t i = 0U; i < len; i++) {
        dst_ptr[i] = val;
    }
}

static inline void crypto_util_assert(bool cond) {
#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32) // Host
    assert(cond);
#elif defined(__HIGHTEC__) // HighTec (GCC-based, TriCore/Aurix)
#define crypto_util_assert(cond)
    if ((cond) == false) {
        __builtin_trap();
    }
#elif defined(__TASKING__) // TASKING
    if ((cond) == false) {
        __debug();
    }
#elif defined(__TI_COMPILER_VERSION__) // TI C2000
    if ((cond) == false) {
        asm(" ESTOP0");
    }
#elif defined(__GNUC__) // Generic GCC (ARM, RISC-V, etc.)
    if ((cond) == false) {
        __builtin_trap();
    }
#else // Unknown platform: infinite loop
    if ((cond) == false) {
        for (;;) {
        }
    }
#endif
}

static inline void crypto_util_panic(void) {
#ifndef CRYPTO_NO_PANIC /* allow test harness to suppress panic */
#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32) // Host
    assert(0);
#elif defined(__HIGHTEC__) // HighTec (GCC-based, TriCore/Aurix)
#define crypto_util_assert(cond)
    __builtin_trap();
#elif defined(__TASKING__) // TASKING
    __debug();
#elif defined(__TI_COMPILER_VERSION__) // TI C2000
    asm(" ESTOP0");
#elif defined(__GNUC__) // Generic GCC (ARM, RISC-V, etc.)
    __builtin_trap();
#else // Unknown platform: infinite loop
    for (;;) {
    }
#endif
#endif /* CRYPTO_NO_PANIC */
}

//==============================================================================
// GUARD END
//==============================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_UTIL_H

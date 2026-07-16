//==============================================================================
/// @file       crypto_platform.h
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      Platform specific configuration
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==============================================================================
//==============================================================================
// GUARD START
//==============================================================================
#ifndef CRYPTO_PLATFORM_H
#define CRYPTO_PLATFORM_H
#ifdef __cplusplus
extern "C" {
#endif
//==============================================================================
// INCLUDE
//==============================================================================

//==============================================================================
// PUBLIC TYPEDEF
//==============================================================================

//==============================================================================
// PUBLIC MACRO
//==============================================================================
/// @brief Cross-platform assertion macro
/// @details User may override by defining CRYPTO_PLATFORM_ASSERT before
/// including this header. On hosted platforms, delegates to standard C assert()
/// and respects NDEBUG. On embedded platforms, emits a debug trap or enters an
/// infinite loop to halt execution for debugging.
#if !defined(CRYPTO_PLATFORM_ASSERT)
// Hosted platforms: Linux, macOS, Windows use standard C assert()
#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
#include <assert.h>
#define CRYPTO_PLATFORM_ASSERT(cond) assert(cond)
// HighTec (GCC-based, TriCore/Aurix)
#elif defined(__HIGHTEC__)
#define CRYPTO_PLATFORM_ASSERT(cond)                                           \
    do {                                                                       \
        if ((cond) == false) {                                                 \
            __builtin_trap();                                                  \
        }                                                                      \
    } while (0)
// TASKING
#elif defined(__TASKING__)
#define CRYPTO_PLATFORM_ASSERT(cond)                                           \
    do {                                                                       \
        if ((cond) == false) {                                                 \
            __debug();                                                         \
        }                                                                      \
    } while (0)
// TI C2000
#elif defined(__TI_COMPILER_VERSION__)
#define CRYPTO_PLATFORM_ASSERT(cond)                                           \
    do {                                                                       \
        if ((cond) == false) {                                                 \
            asm(" ESTOP0");                                                    \
        }                                                                      \
    } while (0)
// Generic GCC (ARM, RISC-V, etc.)
#elif defined(__GNUC__)
#define CRYPTO_PLATFORM_ASSERT(cond)                                           \
    do {                                                                       \
        if ((cond) == false) {                                                 \
            __builtin_trap();                                                  \
        }                                                                      \
    } while (0)
// Unknown platform: infinite loop
#else
#define CRYPTO_PLATFORM_ASSERT(cond)                                           \
    do {                                                                       \
        if ((cond) == false) {                                                 \
            for (;;) {                                                         \
            }                                                                  \
        }                                                                      \
    } while (0)
#endif
#endif // #if !defined(CRYPTO_PLATFORM_ASSERT)

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
// GUARD END
//==============================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_PLATFORM_H

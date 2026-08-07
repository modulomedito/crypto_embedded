/*============================================================================*/
/**
 * @file       test_main.c
 * @brief      Unity test runner
 * @copyright  Copyright (C) 2026. MIT License.
 */
/*============================================================================*/
#include "unity.h"

/* module test runners */
void run_aes_tests(void);
void run_padding_tests(void);
void run_bignum_tests(void);

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();

    run_aes_tests();
    run_padding_tests();
    run_bignum_tests();

    return UNITY_END();
}

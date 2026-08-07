/*============================================================================*/
/**
 * @file       crypto_bignum_test.c
 * @brief      Big number module tests (stub — zero executable lines)
 * @copyright  Copyright (C) 2026. MIT License.
 */
/*============================================================================*/
#include "unity.h"
#include "crypto_bignum.h"

void test_bignum_header_included(void)
{
    /* crypto_bignum.c has zero executable statements.
     * Just verify the header is included and doesn't crash. */
    TEST_ASSERT_TRUE(1);
}

void run_bignum_tests(void)
{
    RUN_TEST(test_bignum_header_included);
}

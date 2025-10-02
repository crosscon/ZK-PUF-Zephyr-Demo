#include "globals.h"
#include <stdint.h>
#include <stddef.h>
#include <mbedtls/bignum.h>
#include <string.h>

/* Parses a numeric string into a fixed-length big-endian byte buffer.
 * - If `str` starts with "0x" or "0X" it is parsed as hex (base 16).
 * - Otherwise it is parsed as decimal (base 10).
 * - The resulting value is written as big-endian into `out` of length out_len.
 * - If the value needs more than out_len bytes -> returns -EOVERFLOW.
 * - Returns 0 on success or negative errno on error.
 */
int parse_numeric_string_to_fixed(const char *str, uint8_t *out, size_t out_len)
{
    int ret;
    mbedtls_mpi mpi;
    const char *p = str;
    int base = 10;

    if (!str || !out || out_len == 0) {
        return -EINVAL;
    }

    if ((str[0] == '0') && (str[1] == 'x' || str[1] == 'X')) {
        base = 16;
        p = str + 2; /* skip 0x prefix */
        if (*p == '\0') {
            return -EINVAL; /* only "0x" provided */
        }
    }

    mbedtls_mpi_init(&mpi);

    /* read string into mpi (handles arbitrary length decimal/hex) */
    ret = mbedtls_mpi_read_string(&mpi, base, p);
    if (ret != 0) {
        mbedtls_mpi_free(&mpi);
        return -EINVAL;
    }

    /* check required bytes */
    size_t bits = mbedtls_mpi_bitlen(&mpi); /* 0 if value == 0 */
    size_t needed_bytes = (bits + 7) / 8;
    if (needed_bytes == 0) {
        needed_bytes = 1; /* represent zero as one zero byte, but we'll still write full out_len */
    }

    if (needed_bytes > out_len) {
        mbedtls_mpi_free(&mpi);
        return -EOVERFLOW;
    }

    /* zero entire output buffer and write big-endian representation into it */
    memset(out, 0, out_len);
    ret = mbedtls_mpi_write_binary(&mpi, out, out_len); /* writes exactly out_len bytes, MSB first */
    if (ret != 0) {
        mbedtls_mpi_free(&mpi);
        return -EIO;
    }

    mbedtls_mpi_free(&mpi);
    return 0;
}

void hex_to_decimal(const struct shell *shell, uint8_t *array, size_t len, const char *label)
{
    int ret;
    mbedtls_mpi mpi;
    mbedtls_mpi_init(&mpi);

    // Convert raw bytes into an MPI
    ret = mbedtls_mpi_read_binary(&mpi, array, len);
    if (ret != 0) {
        shell_error(shell, "Failed to read binary into MPI: -0x%04X", -ret);
        mbedtls_mpi_free(&mpi);
        return;
    }

    // Determine how much space is needed
    size_t required_len = 0;
    ret = mbedtls_mpi_write_string(&mpi, 10, NULL, 0, &required_len);
    if (ret != MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL) {
        shell_error(shell, "Failed to calculate string length: -0x%04X", -ret);
        mbedtls_mpi_free(&mpi);
        return;
    }

    // Allocate the buffer
    char *decimal_str = malloc(required_len);
    if (!decimal_str) {
        shell_error(shell, "Failed to allocate memory for decimal string");
        mbedtls_mpi_free(&mpi);
        return;
    }

    // Write the string for real
    ret = mbedtls_mpi_write_string(&mpi, 10, decimal_str, required_len, &required_len);
    if (ret != 0) {
        shell_error(shell, "Failed to convert MPI to string: -0x%04X", -ret);
        free(decimal_str);
        mbedtls_mpi_free(&mpi);
        return;
    }

    shell_print(shell, "%s%s", label, decimal_str);

    free(decimal_str);
    mbedtls_mpi_free(&mpi);
}

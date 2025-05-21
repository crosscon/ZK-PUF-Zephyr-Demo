#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>

/* Flash configuration macros, specific to
 * platform/use-case. These were based
 * on the LPC55S69 board */

#ifndef FLASH_WRITE_SIZE
#define FLASH_WRITE_SIZE  0x200 /* 512 bytes as per DTS */
#endif
#ifndef PARTITION_OFFSET
#define PARTITION_OFFSET  0     /* Offset within the partition */
#endif
#ifndef STORAGE_PARTITION
#define STORAGE_PARTITION storage_partition
#endif

/* Define flash layout offsets within the partition */
#define FLASH_OFFSET_ACTIVATION_CODE (PARTITION_OFFSET + 0)
#define FLASH_SIZE_ACTIVATION_CODE   ALIGN_UP(PUF_ACTIVATION_CODE_SIZE, FLASH_WRITE_SIZE)

#define FLASH_OFFSET_INTRINSIC_KEY_1_KC (FLASH_OFFSET_ACTIVATION_CODE + FLASH_SIZE_ACTIVATION_CODE)
#define FLASH_SIZE_INTRINSIC_KEY_1_KC   ALIGN_UP(PUF_KEY_CODE_SIZE, FLASH_WRITE_SIZE)

/* Later additional variables can be tracked as needed, for example:
 * #define FLASH_OFFSET_ADDITIONAL_VAR (FLASH_OFFSET_ACTIVATION_CODE + FLASH_SIZE_ACTIVATION_CODE)
 * #define FLASH_SIZE_ADDITIONAL_VAR   0x400
 */

/* Macro to align size up to the next multiple of 'align' */
#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))

/**
 * @brief Initializes the flash area and returns the flash device pointer.
 *
 * @param partition_id   Identifier for the flash partition.
 * @param flash_area_out Pointer to the flash_area pointer to be filled.
 * @param flash_dev_out  Pointer to the flash device pointer to be filled.
 *
 * @return 0 on success, -1 on error.
 */
int flash_initialize(uint32_t partition_id, const struct flash_area **flash_area_out, const struct device **flash_dev_out);

/**
 * @brief Writes data to flash with page-size alignment.
 *
 * @param flash_dev       Pointer to the flash device.
 * @param flash_area      Pointer to the flash area structure.
 * @param data_offset     Data starting point offset within the partition.
 * @param data            Pointer to the data to be written.
 * @param data_size       Size of the data.
 *
 * @return 0 on success, -1 on error.
 */
int flash_write_padded(const struct device *flash_dev, const struct flash_area *flash_area, off_t data_offset,
                       const uint8_t *data, size_t data_size);

/**
 * @brief Reads data from flash into a provided buffer.
 *
 * @param flash_dev       Pointer to the flash device.
 * @param flash_area      Pointer to the flash area structure.
 * @param data_offset     Data starting point offset within the partition.
 * @param buffer          Destination buffer for read data.
 * @param data_size       Size of the data to read.
 *
 * @return 0 on success, -1 on error.
 */
int flash_read_data(const struct device *flash_dev, const struct flash_area *flash_area, off_t data_offset,
                    uint8_t *buffer, size_t data_size);

#include <stdint.h>

/* API Error Codes */
#define TEE_SUCCESS                       0x00000000
#define TEE_ERROR_CORRUPT_OBJECT          0xF0100001
#define TEE_ERROR_CORRUPT_OBJECT_2        0xF0100002
#define TEE_ERROR_STORAGE_NOT_AVAILABLE   0xF0100003
#define TEE_ERROR_STORAGE_NOT_AVAILABLE_2 0xF0100004
#define TEE_ERROR_UNSUPPORTED_VERSION     0xF0100005
#define TEE_ERROR_CIPHERTEXT_INVALID      0xF0100006
#define TEE_ERROR_GENERIC                 0xFFFF0000
#define TEE_ERROR_ACCESS_DENIED           0xFFFF0001
#define TEE_ERROR_CANCEL                  0xFFFF0002
#define TEE_ERROR_ACCESS_CONFLICT         0xFFFF0003
#define TEE_ERROR_EXCESS_DATA             0xFFFF0004
#define TEE_ERROR_BAD_FORMAT              0xFFFF0005
#define TEE_ERROR_BAD_PARAMETERS          0xFFFF0006
#define TEE_ERROR_BAD_STATE               0xFFFF0007
#define TEE_ERROR_ITEM_NOT_FOUND          0xFFFF0008
#define TEE_ERROR_NOT_IMPLEMENTED         0xFFFF0009
#define TEE_ERROR_NOT_SUPPORTED           0xFFFF000A
#define TEE_ERROR_NO_DATA                 0xFFFF000B
#define TEE_ERROR_OUT_OF_MEMORY           0xFFFF000C
#define TEE_ERROR_BUSY                    0xFFFF000D
#define TEE_ERROR_COMMUNICATION           0xFFFF000E
#define TEE_ERROR_SECURITY                0xFFFF000F
#define TEE_ERROR_SHORT_BUFFER            0xFFFF0010
#define TEE_ERROR_EXTERNAL_CANCEL         0xFFFF0011
#define TEE_ERROR_TIMEOUT                 0xFFFF3001
#define TEE_ERROR_OVERFLOW                0xFFFF300F
#define TEE_ERROR_TARGET_DEAD             0xFFFF3024
#define TEE_ERROR_STORAGE_NO_SPACE        0xFFFF3041
#define TEE_ERROR_MAC_INVALID             0xFFFF3071
#define TEE_ERROR_SIGNATURE_INVALID       0xFFFF3072
#define TEE_ERROR_TIME_NOT_SET            0xFFFF5000
#define TEE_ERROR_TIME_NEEDS_RESET        0xFFFF5001

/* Values used within `arg.ret_origin` to indicate where
 * an error or return code originated from */
#define TEE_ORIGIN_API                    0x00000001
#define TEE_ORIGIN_COMMS                  0x00000002
#define TEE_ORIGIN_TEE                    0x00000003
#define TEE_ORIGIN_TRUSTED_APP            0x00000004

/* Login identifiers */
#define TEE_IOCTL_LOGIN_PUBLIC            0x00000000
#define TEE_IOCTL_LOGIN_USER              0x00000001
#define TEE_IOCTL_LOGIN_GROUP             0x00000002
// 0x00000003 is unused
#define TEE_IOCTL_LOGIN_APPLICATION       0x00000004
#define TEE_IOCTL_LOGIN_USER_APPLICATION  0x00000005
#define TEE_IOCTL_LOGIN_GROUP_APPLICATION 0x00000006

#define TEE_UUID_LEN 16

typedef uint32_t TEE_Result;

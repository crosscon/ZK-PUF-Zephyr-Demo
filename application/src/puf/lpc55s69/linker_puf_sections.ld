/* Hardcode activation_code at 0x00070000 */
.activation_code 0x00070000 : ALIGN(4)
{
    KEEP(*(.activation_code))
}

/* Place key_code right after it at 0x00070500 */
.key_code 0x00070500 : ALIGN(4)
{
    KEEP(*(.key_code))
}

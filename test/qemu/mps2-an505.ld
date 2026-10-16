/* QEMU mps2-an505 (Cortex-M33, boots Secure): SSRAM1 Secure alias at 0x10000000, SSRAM2/3 Secure alias at 0x38000000 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x10000000, LENGTH = 4M
    RAM   (rwx) : ORIGIN = 0x38000000, LENGTH = 4M
}
INCLUDE sections.ld

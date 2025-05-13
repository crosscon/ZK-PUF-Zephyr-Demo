# PoC of integrating PUF logic for lpc55s69 within Zephyr

## Building
```sh
west build -d build -p always -b lpcxpresso55s69/lpc55s69/cpu0/ns application/
```

## Flashing

```sh
LinkServer flash LPC55S69:LPCXpresso55S69 load build/zephyr/zephyr.elf
```

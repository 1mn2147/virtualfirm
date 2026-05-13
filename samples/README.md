# Samples

Create the demo binary with:

```bash
firmware-mvp init-sample --out samples/demo_firmware.bin
```

Fixture variants:

```bash
firmware-mvp init-sample --kind raw --out samples/demo_firmware.bin
firmware-mvp init-sample --kind elf --out samples/demo_firmware.elf
firmware-mvp init-sample --kind high-entropy --out samples/high_entropy.bin
firmware-mvp init-sample --kind mmio-heavy --out samples/mmio_heavy.bin
```

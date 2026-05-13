# STM32F1 Memory Map Notes

This lightweight reference is included for the MVP RAG flow.

| Range | Peripheral |
| --- | --- |
| 0x40000000-0x400003FF | TIM2 |
| 0x40000400-0x400007FF | TIM3 |
| 0x40000800-0x40000BFF | TIM4 |
| 0x40003800-0x40003BFF | SPI2/I2S2 |
| 0x40004400-0x400047FF | USART2 |
| 0x40004800-0x40004BFF | USART3 |
| 0x40005400-0x400057FF | I2C1 |
| 0x40005800-0x40005BFF | I2C2 |
| 0x40010800-0x40010BFF | GPIOA |
| 0x40010C00-0x40010FFF | GPIOB |
| 0x40011000-0x400113FF | USART1 |
| 0x40013000-0x400133FF | SPI1 |
| 0x40013800-0x40013BFF | USART1 alternate control area |
| 0x40021000-0x400213FF | RCC |

Common observations:

- Writes to RCC registers usually enable peripheral clocks before GPIO, UART, SPI, I2C, or timer initialization.
- UART initialization often touches GPIO configuration registers, USART baud-rate, control, and status registers.
- Dummy reads from status registers are often enough to unblock simple boot emulation.

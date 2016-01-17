#ifndef INC_ADC
#define INC_ADC

#define NUM_ADC_CHANNELS    16

struct adc_addr {
    uint32_t base;
    uint32_t irq;
    uint32_t rcc;
    const char * name;
    uint8_t channel_array[NUM_ADC_CHANNELS];
    uint8_t num_channels;

    uint32_t dma_base;
    uint32_t dma_rcc;
    uint32_t dma_channel;
    uint32_t dma_stream;
    uint32_t dma_irq;
};

void adc_init(struct fnode *dev, const struct adc_addr adc_addrs[], int num_adc);

#endif


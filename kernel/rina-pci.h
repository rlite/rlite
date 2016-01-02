#ifndef __RINA_PCI__
#define __RINA_PCI__

typedef uint8_t pdu_type_t;

enum {
    PDU_TYPE_MGMT = 0x12,
};

struct rina_pci {
    pdu_type_t type;
} __attribute__((packed));

#endif  /* __RINA_PCI__ */

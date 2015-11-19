#ifndef HW_VHOST_NVME_H
#define HW_VHOST_NVME_H

#include <linux/vhost.h>
#include "hw/virtio/vhost.h"

#define TYPE_VHOST_NVME "vhost-nvme"
#define VHOST_NVME(obj) \
        OBJECT_CHECK(VHostNVME, (obj), TYPE_VHOST_NVME)

typedef struct NvmeBar {
    uint64_t    cap;
    uint32_t    vs;
    uint32_t    intms;
    uint32_t    intmc;
    uint32_t    cc;
    uint32_t    rsvd1;
    uint32_t    csts;
    uint32_t    nssrc;
    uint32_t    aqa;
    uint64_t    asq;
    uint64_t    acq;
} NvmeBar;

struct vhost_nvme_user_eventfd;

typedef struct VHostNVME {
    PCIDevice    parent_obj;
    MemoryRegion iomem;

    char *wwpn;
    int num_queues;

    struct vhost_dev dev;
    struct vhost_nvme_user_eventfd *eventfd;
} VHostNVME;

struct vhost_nvme_user_eventfd {
    struct vhost_nvme_eventfd eventfd;
    int _irq_enabled;
    int _vector;
    EventNotifier notifier;
    VHostNVME *ctrl;
};

#endif

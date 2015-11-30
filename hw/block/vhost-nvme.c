#include <hw/block/block.h>
#include <hw/hw.h>
#include <hw/pci/msix.h>
#include <hw/pci/pci.h>
#include "sysemu/sysemu.h"
#include "qapi/visitor.h"
#include "sysemu/block-backend.h"
#include <sys/ioctl.h>
#include "vhost-nvme.h"

static uint64_t vhost_nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    VHostNVME *n = (VHostNVME *)opaque;
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    uint64_t val = 0;

    if (addr < sizeof(NvmeBar)) {
        struct vhost_nvme_bar bar;
        int ret;

        bar.type = VHOST_NVME_BAR_READ;
        bar.offset = addr;
        bar.size = size;
        ret = vhost_ops->vhost_nvme_rw_bar(&n->dev, &bar);
        assert(ret == 0);
        if (!ret)
            val = bar.val;
    }
    return val;
}

static void vhost_nvme_write_bar(VHostNVME *n, hwaddr addr, uint64_t data,
    unsigned size)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct vhost_nvme_bar bar;
    int ret;

    bar.type = VHOST_NVME_BAR_WRITE;
    bar.offset = addr;
    bar.val = data;
    bar.size = size;
    ret = vhost_ops->vhost_nvme_rw_bar(&n->dev, &bar);
    assert(ret == 0);
}

static void vhost_nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
    VHostNVME *n = (VHostNVME *)opaque;

    vhost_nvme_write_bar(n, addr, data, size);
}

static const MemoryRegionOps vhost_nvme_mmio_ops = {
    .read = vhost_nvme_mmio_read,
    .write = vhost_nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static void vhost_nvme_notifier_read(EventNotifier *e)
{
    struct vhost_nvme_user_eventfd *eventfd =
        container_of(e, struct vhost_nvme_user_eventfd, notifier);
    VHostNVME *n = eventfd->ctrl;

    if (!event_notifier_test_and_clear(e))
        return;

#if 0 /* TODO: support per cq notify */
    if (eventfd->_irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            msix_notify(&(n->parent_obj), eventfd->_vector);
        } else {
            pci_irq_pulse(&n->parent_obj);
        }
    }
#else
     pci_irq_pulse(&n->parent_obj);
#endif
}

static int vhost_nvme_enable_notifier(VHostNVME *n)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct vhost_nvme_user_eventfd *eventfd;
    int fd;
    int ret;
    int i;

    n->eventfd = g_malloc0(sizeof(struct vhost_nvme_user_eventfd)
                            * n->num_queues);
    for (i = 0; i < n->num_queues; i++) {
        eventfd = &n->eventfd[i];

        ret = event_notifier_init(&eventfd->notifier, 0);
        if (ret)
		return ret;
        event_notifier_set_handler(&eventfd->notifier, vhost_nvme_notifier_read);

        fd = event_notifier_get_fd(&eventfd->notifier);
        eventfd->eventfd.fd = fd;
        eventfd->eventfd.num = i;
        eventfd->eventfd.irq_enabled = &eventfd->_irq_enabled;
        eventfd->eventfd.vector = &eventfd->_vector;
        eventfd->ctrl = n;

        ret = vhost_ops->vhost_nvme_set_eventfd(&n->dev, &eventfd->eventfd);
        if (ret < 0)
            return ret -errno;
    }

    return 0;
}

static int vhost_nvme_set_endpoint(VHostNVME *n)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct vhost_nvme_target backend;
    int ret;

    pstrcpy(backend.vhost_wwpn, sizeof(backend.vhost_wwpn), n->wwpn);
    ret = vhost_ops->vhost_nvme_set_endpoint(&n->dev, &backend);
    if (ret < 0) {
        return -errno;
    }
    return 0;
}

static int vhost_nvme_set_memtable(VHostNVME *n)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    int ret;

    ret = vhost_ops->vhost_set_mem_table(&n->dev, n->dev.mem);
    if (ret < 0) {
        return -errno;
    }
    return 0;
}

#define PCI_VENDOR_ID_GOOGLE 0x1AE0

static int vhost_nvme_init(PCIDevice *pci_dev)
{
    VHostNVME *n = VHOST_NVME(pci_dev);
    uint8_t *pci_conf;
    int vhostfd;
    uint32_t reg_size;
    int num_queues;
    int ret;

    if (!n->wwpn)
        return -1;

    pci_conf = pci_dev->config;
    pci_conf[PCI_INTERRUPT_PIN] = 1;
    pci_config_set_prog_interface(pci_dev->config, 0x2);
    pci_config_set_vendor_id(pci_dev->config, PCI_VENDOR_ID_GOOGLE);
    pci_config_set_device_id(pci_dev->config, 0x5845);
    pci_config_set_class(pci_dev->config, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(&n->parent_obj, 0x80);

    num_queues = 4; /* TODO: get from kernel */
    n->num_queues = num_queues;
    reg_size = pow2ceil(0x1004 + 2 * (num_queues + 1) * 4);

    memory_region_init_io(&n->iomem, OBJECT(n), &vhost_nvme_mmio_ops, n,
                          "vhost_nvme", reg_size);
    pci_register_bar(&n->parent_obj, 0,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
        &n->iomem);
    msix_init_exclusive_bar(&n->parent_obj, num_queues, 4);

    msix_vector_use(&n->parent_obj, 0);

    vhostfd = open("/dev/vhost-nvme", O_RDWR);
    if (vhostfd < 0)
        return -errno;

    /* We don't use virtqueue for now */
    n->dev.nvqs = 0;

    ret = vhost_dev_init(&n->dev, (void *)(uintptr_t)vhostfd,
                         VHOST_BACKEND_TYPE_KERNEL);
    if (ret)
        goto close_vhostfd;

    ret = vhost_nvme_set_memtable(n);
    if (ret)
        goto close_vhostfd;

    ret = vhost_nvme_set_endpoint(n);
    if (ret)
        goto close_vhostfd;

    ret = vhost_nvme_enable_notifier(n);
    if (ret)
        goto close_vhostfd;

    return 0;

close_vhostfd:
    close(vhostfd);
    return ret;
}

static void vhost_nvme_exit(PCIDevice *pci_dev)
{
    VHostNVME *n = VHOST_NVME(pci_dev);

    msix_uninit_exclusive_bar(pci_dev);

    vhost_dev_cleanup(&n->dev);
}

static Property vhost_nvme_props[] = {
    DEFINE_PROP_STRING("wwpn", VHostNVME, wwpn),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription vhost_nvme_vmstate = {
    .name = "nvme",
    .unmigratable = 1,
};

static void vhost_nvme_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->init = vhost_nvme_init;
    pc->exit = vhost_nvme_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->device_id = 0x5845;
    pc->revision = 1;
    pc->is_express = 1;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Non-Volatile Memory Express";
    dc->props = vhost_nvme_props;
    dc->vmsd = &vhost_nvme_vmstate;
}

static void vhost_nvme_instance_init(Object *obj)
{
}

static const TypeInfo vhost_nvme_info = {
    .name          = TYPE_VHOST_NVME,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(VHostNVME),
    .class_init    = vhost_nvme_class_init,
    .instance_init = vhost_nvme_instance_init,
};

static void vhost_nvme_register_types(void)
{
    type_register_static(&vhost_nvme_info);
}

type_init(vhost_nvme_register_types)

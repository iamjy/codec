/******************************************************************************
 * This confidential and proprietary C/C++ code may be used only as
 * authorised by a licensing agreement from Mn_nH, Inc.
 *   (C) COPYRIGHT 2013-2015 Mn_nH, Inc. Limited
 *       ALL RIGHTS RESERVED
 * The entire notice above must be reproduced on all authorised
 * copies and copies may only be made to the extent permitted
 * by a licensing agreement from Mn_nH, Inc. Limited.
 *
 ******************************************************************************/
#ifndef DEBUG
#define DEBUG

#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/clk.h>
#include <linux/slab.h>
#include <asm/dma.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/ctype.h>
#include <generated/autoconf.h>

#include "ion.h"
#include "mv_ion_drv.h"
#include "mnhevc.h"


/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
#ifndef DEBUG
#define DEBUG
#endif

// #define DYNAMIC_RISC_BASE


/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
#define MV_VPU_DRV_NAME		"mn-lilith"

#define DSP_TRANS_TIMEOUT	100
#define REVELATION_TIMEOUT	100

#define ORC_ADDR_MASK			(0x1 << 20) - 1
#define ORC_ADDR_ALIGN(x, mask) (x + SZ_1M & ~(mask))


/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
extern void __iomem *syscon_base;


/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static struct mn_media_info media_info;


/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static int
mv_mnhevc_probe(struct platform_device *pdev);
static int
mv_mnhevc_release(struct platform_device *pdev);
static int
mv_mnhevc_load_fw(struct platform_device *pdev);


/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static irqreturn_t
hevc_isr(int irq, void *dev_id)
{
    struct mn_media_info *mnhevc = GET_MEDIA();
	void __iomem *orc_base = mnhevc->reg_orc;

    if (readl(orc_base + OPR2ARM_CMD) == OPR2ARM_BOOT) { 
		wake_up_interruptible(&mnhevc->vpu_trans); 
    }
    else if (readl(orc_base + OPR2ARM_CMD) == OPR2ARM_ACK) { 
		wake_up_interruptible(&mnhevc->vpu_ack);
    }
    else if (readl(orc_base + OPR2ARM_CMD) == OPR2ARM_FRM_DONE) { 
		wake_up_interruptible(&mnhevc->vpu_done);
    }
    else if (readl(orc_base + OPR2ARM_CMD) == OPR2ARM_MESSAGE ) {
		wake_up_interruptible(&mnhevc->vpu_msg);
    }
    else {
		wake_up_interruptible(&mnhevc->vpu_err);
    }

	writel(0x0, orc_base + OPR2ARM_INTR);

    return IRQ_HANDLED;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
int32_t
load_firmware_to_mnhevc(struct mn_media_info *mnhevc, const int8_t *dna,
													  size_t size)
{
    uint32_t i;
    uint32_t *code_data = (uint32_t *)dna;
	void __iomem *orc_base  = mnhevc->reg_orc;
	void __iomem *code_base = mnhevc->code_base_virt;
	phys_addr_t code_base_phys = mnhevc->code_base_phys;
	struct device *dev = &mnhevc->pdev->dev;

	/* OpenRISK Reset */
#if 0 /* Will be used at later date */
    test_and_set_bit(OPR_RSTOUT_BIT,
					 (volatile unsigned long *)
					 ((unsigned long)syscon_base + RST_OUT0));
#endif
	writel(0x0, orc_base + OPR_ENABLE);

	/* Align code base address by 1MiB */
#ifdef DYNAMIC_RISC_BASE
	code_base = ORC_ADDR_ALIGN((unsigned long)code_base, ORC_ADDR_MASK);
	code_base_phys = ORC_ADDR_ALIGN(code_base_phys, ORC_ADDR_MASK);
#endif
	dev_info(dev, "FW_LOADING virt %#x phys %#x", code_base, code_base_phys);

	for (i = 0; i < size / 4; i++)
		writel(code_data[i],  code_base + (i << 2));

	/* Set base address of code area */
#ifdef DYNAMIC_RISC_BASE
    writel(0, orc_base + OPR_CODE_START);
    writel((code_base_phys >> 20) | (0x7 << 12) | (0x1 << 31),
			orc_base + OPR_CODE_REMAP);
#else
    writel(code_base_phys >> 12, orc_base + OPR_CODE_START);
#endif

	/* Set QMEM base */
    writel(QMEM_I_MASK, orc_base + OPR_QMEM_IMASK);
    writel(QMEM_I_ADDR, orc_base + OPR_QMEM_IADDR);
    writel(QMEM_D_MASK, orc_base + OPR_QMEM_DMASK);
    writel(QMEM_D_ADDR, orc_base + OPR_QMEM_DADDR);

    return 0;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static void
mv_check_fw_version(struct platform_device *pdev, uint32_t version)
{
    int major, minor, beta = 0;

    if (version & 0xF0000000)
		beta = (version >> 24) & 0xF;
    major = (version >> 16) & 0xFF;
    minor = (version) & 0xFFFF;
    if (beta)
		dev_info(&pdev->dev, "FW v%d.%db%d loaded\r\n", major, minor, beta);
	else
		dev_info(&pdev->dev, "FW v%d.%d loaded\r\n", major, minor);
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static void
mv_unload_codec_fw(struct mn_media_info *mnhevc)
{
	void __iomem *orc_base = mnhevc->reg_orc;
    struct platform_devi *pdev = mnhevc->pdev;
	struct device *dev = &mnhevc->pdev->dev;

	if (mnhevc->fw)
    	release_firmware(mnhevc->fw);

#ifdef DYNAMIC_RISC_BASE
	free_pages_exact(mnhevc->code_base_virt, mnhevc->code_size);
#else
	iounmap((void __iomem *)mnhevc->code_base_virt);
	release_mem_region(mnhevc->code_base_phys, mnhevc->code_size);
#endif

	dev_info(dev, "Unload FW virt %#x phys %#x size %d",
				   mnhevc->code_base_virt,
				   mnhevc->code_base_phys,
				   mnhevc->code_size);

    writel(ORC_REMAP_DISABLE, orc_base + OPR_CODE_REMAP);

    return;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
int32_t
mv_load_codec_fw(struct device *dev, struct mn_media_info *mnhevc)
{
    int ret = VPU_SUCCESS;
	void *virt;
	phys_addr_t phys;
	size_t size;
    struct platform_device *pdev = mnhevc->pdev;
    const struct firmware *fw = mnhevc->fw;
	struct resource *res = NULL;

	size = PAGE_ALIGN(ORC_CODE_SIZE);
#ifdef DYNAMIC_RISC_BASE
	virt = alloc_pages_exact(size, GFP_KERNEL);
	phys = virt_to_phys(virt);
#else
	phys = ORC_CODE_BASE;
	res = request_mem_region(phys, size, dev_name(dev));
	if (!res) {
		dev_err(dev,  "Failed to get openrisc memory base!");
		return -EIO;
	}

	virt = ioremap_nocache(phys, size);
	if (!virt) {
		dev_err(dev, "Failed to ioremap orc code base!");
		return -EFAULT;
	}
#endif

	ret = request_firmware(&fw, "mnhevc_main-icdc_li.bin", dev);
    if (ret != 0) {
		dev_err(dev, "Failed to request firmware! %d\n", ret);
		goto err;
    }

	dev_info(dev, "FW_CODE_BASE virt %#x phys %#x size %d", virt, phys, size);

	mnhevc->code_size = size;
	mnhevc->code_base_phys = (uint32_t)phys;
	mnhevc->code_base_virt = (uint32_t)virt;
	load_firmware_to_mnhevc(mnhevc, fw->data, fw->size);

	if (fw) {
    	release_firmware(fw);
		mnhevc->fw = NULL;
	}

	return ret;

err:
    mv_unload_codec_fw(mnhevc);
    return VPU_FAIL;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static int 
mv_mnhevc_open(struct inode *inode, struct file *filp)
{
    int ret = VPU_SUCCESS;
    struct mn_media_info *mnhevc = (struct mn_media_info *)GET_MEDIA();
	struct device *dev = &mnhevc->pdev->dev;
	void __iomem *orc_base = mnhevc->reg_orc;
	void __iomem *usb_base = mnhevc->reg_usb3;

    /* check opened already */
    mutex_lock_interruptible(&mnhevc->singleton);
    if (mnhevc->grant >= 0)
		goto opened;
    
	mnhevc->grant = 0;
    mutex_unlock(&mnhevc->singleton);

	/* Firmware Loading */
	if (mv_mnhevc_load_fw(mnhevc->pdev) < 0)
		return VPU_FAIL;

	/* OpenRISC Reset Release */
#if 0 /* Will be used at later date */
    test_and_clear_bit(OPR_RSTOUT_BIT,
					   (volatile unsigned long *)
					   ((unsigned long)syscon_base + RST_OUT0));
	writel(0xE, syscon_base + RST_OUT0);
#endif

	writel(0x1, usb_base);
	writel(0x1, orc_base + OPR_ENABLE);

    ret = wait_event_interruptible_timeout(mnhevc->vpu_trans,
										   readl(orc_base + OPR2ARM_UPDATE),
										   DSP_TRANS_TIMEOUT);
    if (ret < 0) {
		dev_err(dev, "DSP boot timeout (%08x)\n", ret);
		goto err;
    }

    writel(0, orc_base + OPR2ARM_UPDATE);

    filp->private_data = (void *)mnhevc;

    return 0;

opened:
    mutex_unlock(&mnhevc->singleton);
    return -EBUSY;

err:
    mutex_unlock(&mnhevc->singleton);
    return -1;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static int 
mv_mnhevc_close(struct inode *inode, struct file *filp)
{
    struct mn_media_info *mnhevc = (struct mn_media_info *)filp->private_data;
	void __iomem *orc_base = mnhevc->reg_orc;
	void __iomem *usb_base = mnhevc->reg_usb3;

    /* OpenRISC Reset */
#if 0 /* Will be used at later date */
    test_and_set_bit(OPR_RSTOUT_BIT,
					 (volatile unsigned long *)
					 ((unsigned long)syscon_base + RST_OUT0));
#endif
	writel(0x0, usb_base);
	writel(0x0, orc_base + OPR_ENABLE);

	/* HEVC Resource Release */
	mv_unload_codec_fw(mnhevc);

    mnhevc->grant = -1;

    return 0;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static ssize_t 
mv_mnhevc_read(struct file *filp,  char __user *buf, size_t count, loff_t* f_pos)
{
    return 0;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static ssize_t 
mv_mnhevc_write(struct file *fiip, const char *buf, size_t count, loff_t *f_pos)
{
    return 0;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static long
mv_mnhevc_register_buffer(struct mn_media_info *mn, struct mn_buffer *head,
						  int idx, int fd)
{
	int ret = VPU_SUCCESS;
	int i;
	struct device *dev = &mn->pdev->dev;
	struct mn_buffer *buf = NULL;

	buf = kzalloc(sizeof(struct mn_buffer), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	
	ret = mv_ion_client_register(NULL, fd);
	if (ret < 0)
		return ret;

	buf->virt = (void *)mv_ion_get_vaddr_from_client(NULL, fd);
	if (!buf->virt)
		dev_err(dev, "Failed to get vaddr from %d client!", fd);

	buf->phys = mv_ion_get_paddr_from_client(NULL, fd);
	if (!buf->phys)
		dev_err(dev, "Failed to get paddr from %d client!", fd);

	buf->size = mv_ion_get_size_from_client(NULL, fd);
	if (buf->size <= 0)
		dev_err(&dev, "Failed to get size form %d client!", fd);

	buf->fd  = fd;
	buf->idx = idx;

	mutex_lock(&mn->list_lock);
	list_add(&buf->list, &head->head);
	mutex_unlock(&mn->list_lock);

	return ret;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static int
mv_mnhevc_deregister_buffer(struct mn_media_info *mn, struct mn_buffer *buf,
													  int fd)
{
	int ret = VPU_SUCCESS;
	int i;
	struct device *dev = &mn->pdev->dev;
	struct mn_buffer *b = NULL;
	
	mutex_lock(&mn->list_lock);
	if (!list_empty(&buf->head)) {
		list_for_each_entry(b, &buf->head, list) {
			if (b->fd == fd) {
				list_del(&b->list);
				kfree(b);
				break;
			}
		}
	}
	mutex_unlock(&mn->list_lock);

	if (b->fd != fd)
		return -EAGAIN;

	ret = mv_ion_client_unregister(NULL, fd);
	if (ret < 0) {
		dev_err(dev, "Failed to unregister %d client!", fd);
		return ret;
	}

	return ret;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
int 
mv_mnhevc_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret = 0;
	unsigned long start  = vma->vm_start;
	unsigned long len    = PAGE_ALIGN(vma->vm_end - vma->vm_start);
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long pfn    = __phys_to_pfn(offset);
	unsigned long prot   = vma->vm_page_prot;
    struct mn_media_info *mnhevc = (struct mn_media_info*)file->private_data;
	struct device *dev = &mnhevc->pdev->dev;

	if (offset == mnhevc->res_mnhevc.start ||
		offset == mnhevc->res_orc.start ||
		offset == mnhevc->res_usb3.start) {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,6,0))
		vma->vm_flags |= (VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
#else
		vma->vm_flags |= (VM_IO | VM_RESERVED);
#endif
		prot = pgprot_noncached(prot);

		if (remap_pfn_range(vma, start, pfn, len, prot)) {
			dev_err("Failed to remap 0x%x to user sapce\n", offset);
			return -EAGAIN;
		}
	}
	else {
		dev_err("Failed to remap 0x%x to user sapce\n", offset);
		return -EINVAL;
	}
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
long 
mv_mnhevc_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	void __user *argp = (void __user *)arg;
    unsigned long offset;
    struct mn_codec_access_info mn_codec_access;
    struct mn_media_info *mnhevc = (struct mn_media_info*)filp->private_data;
	struct device *dev = &mnhevc->pdev->dev;
	unsigned long address, p_addr;
	unsigned long v_addr;

	if (copy_from_user(&mn_codec_access, (const void __user *)argp,
										  sizeof(mn_codec_access))) {
		ret = -EFAULT;
	}

   	switch (mn_codec_access.control) {
	case CODEC_REGISTER_CONF_BUFFER: {
		int fd; // Shared FD from user space
		struct mn_buffer *cbuf = NULL;

		fd = mn_codec_access.reg_data;
		dev_info(dev, "REGISTER_CONF_BUFFER FD %d\n", fd);
		ret = mv_mnhevc_register_buffer(mnhevc, mnhevc->cbuf,
												mnhevc->cbuf_cnt, fd);
		if (ret < 0) {
			dev_err(dev, "Failed to regiser ion clinet! %d\n",fd);
			return ret;
		}

		mnhevc->cbuf_cnt++;

		/* ----------------------------------------------------------------- */
		/* Temporaraily Test Code */
		mutex_lock(&mnhevc->list_lock);
		if (!list_empty(&mnhevc->cbuf->head)) {
			list_for_each_entry(cbuf, &mnhevc->cbuf->head, list) {
				if (cbuf->fd == fd) {
					mnhevc->mnhevc_conf_virt = cbuf->virt;
					mnhevc->mnhevc_conf_phys = cbuf->phys;
					dev_info(dev, "mnhevc_conf_virt 0x%x\n",
								   mnhevc->mnhevc_conf_virt);
					dev_info(dev, "mnhevc_conf_phys 0x%x\n",
								   mnhevc->mnhevc_conf_phys);
					mutex_unlock(&mnhevc->list_lock);
					break;
				}
			}
		}
		/* ----------------------------------------------------------------- */
		
		break;
	}
	case CODEC_REGISTER_INPUT_BUFFER: {
		int fd; // Shared FD from user space
		struct mn_buffer *ibuf = NULL;

		fd = mn_codec_access.reg_data;
		dev_info(dev, "REGISTER_INPUT_BUFFER FD %d\n", fd);
		ret = mv_mnhevc_register_buffer(mnhevc, mnhevc->ibuf,
												mnhevc->ibuf_cnt, fd);
		if (ret < 0) {
			dev_err(dev, "Failed to regiser ion clinet! %d\n",fd);
			return ret;
		}

		mnhevc->ibuf_cnt++;

		/* ----------------------------------------------------------------- */
		/* Temporaraily Test Code */
		mutex_lock(&mnhevc->list_lock);
		if (!list_empty(&mnhevc->ibuf->head)) {
			list_for_each_entry(ibuf, &mnhevc->ibuf->head, list) {
				if (ibuf->fd == fd) {
					mnhevc->mnhevc_ich_virt = ibuf->virt;
					mnhevc->mnhevc_ich_phys = ibuf->phys;
					dev_info(dev, "mnhevc_ich_virt 0x%x\n",
								   mnhevc->mnhevc_ich_virt);
					dev_info(dev, "mnhevc_ich_phys 0x%x\n",
								   mnhevc->mnhevc_ich_phys);
					mutex_unlock(&mnhevc->list_lock);
					break;
				}
			}
		}
		/* ----------------------------------------------------------------- */

		break;
	}
	case CODEC_REGISTER_OUTPUT_BUFFER: {
		int fd; // Shared FD from user space
		struct mn_buffer *obuf = NULL;

		fd = mn_codec_access.reg_data;
		dev_info(dev, "REGISTER_OUTPUT_BUFFER FD %d\n", fd);
		ret = mv_mnhevc_register_buffer(mnhevc, mnhevc->obuf,
												mnhevc->obuf_cnt, fd);
		if (ret < 0) {
			dev_err(dev, "Failed to regiser ion clinet! %d\n",fd);
			return ret;
		}

		mnhevc->obuf_cnt++;

		/* ----------------------------------------------------------------- */
		/* Temporaraily Test Code */
		mutex_lock(&mnhevc->list_lock);
		if (!list_empty(&mnhevc->obuf->head)) {
			list_for_each_entry(obuf, &mnhevc->obuf->head, list) {
				if (obuf->fd == fd) {
					mnhevc->mnhevc_och_virt = obuf->virt;
					mnhevc->mnhevc_och_phys = obuf->phys;
					dev_info(dev, "mnhevc_och_virt 0x%x\n",
								   mnhevc->mnhevc_och_virt);
					dev_info(dev, "mnhevc_och_phys 0x%x\n",
								   mnhevc->mnhevc_och_phys);
					mutex_unlock(&mnhevc->list_lock);
					break;
				}
			}
		}
		/* ----------------------------------------------------------------- */

		break;
	}
	case CODEC_UNREGISTER_CONF_BUFFER: {
		int fd; // Shared FD from user space

		fd = mn_codec_access.reg_data;
		dev_info(dev, "UNREGISTER_CONF_BUFFER FD %d\n", fd);
		ret = mv_mnhevc_deregister_buffer(mnhevc, mnhevc->cbuf, fd);
		if (ret < 0) {
			dev_err(dev, "Failed to deregiser conf buffer! %d\n",fd);
			return ret;
		}

		break;
	}
	case CODEC_UNREGISTER_INPUT_BUFFER: {
		int fd; // Shared FD from user space

		fd = mn_codec_access.reg_data;
		dev_info(dev, "UNREGISTER_INPUT_BUFFER FD %d\n", fd);
		ret = mv_mnhevc_deregister_buffer(mnhevc, mnhevc->ibuf, fd);
		if (ret < 0) {
			dev_err(dev, "Failed to deregiser input buffer! %d\n",fd);
			return ret;
		}

		break;
	}
	case CODEC_UNREGISTER_OUTPUT_BUFFER: {
		int fd; // Shared FD from user space

		fd = mn_codec_access.reg_data;
		dev_info(dev, "UNREGISTER_OUTPUT_BUFFER FD %d\n", fd);
		ret = mv_mnhevc_deregister_buffer(mnhevc, mnhevc->obuf, fd);
		if (ret < 0) {
			dev_err(dev, "Failed to deregiser output buffer! %d\n",fd);
			return ret;
		}

		break;
	}
	case CODEC_REG_RD :
	{
		unsigned long msk = 0xFFFF0000;
		unsigned long p_base = 0x0;
    	p_addr = mn_codec_access.address;
		if (mnhevc->res_usb3.start == (p_addr & msk)) {
    		v_addr = mnhevc->reg_usb3;
			p_base = mnhevc->res_usb3.start;
		}
		else if (mnhevc->res_orc.start == (p_addr & msk)) {
    		v_addr = mnhevc->reg_orc;
			p_base = mnhevc->res_orc.start;
		}
		else {
    		v_addr = mnhevc->reg_mnhevc;
			p_base = mnhevc->res_mnhevc.start;
		}

    	address = (u32)((int)v_addr + (p_addr - p_base));
    	mn_codec_access.reg_data = readl(address);
    	dev_dbg(dev, "REG_RD p %#x v %#x src %#x\n", p_addr, v_addr, address);
    	dev_dbg(dev, "REG_RD %d %#x(%#x)\n", mn_codec_access.reg_data, address,
										 	 p_base);

		if (copy_to_user((const void __user *)argp, &mn_codec_access,
						  sizeof(mn_codec_access))) 
			ret = -EFAULT;

    	break;
	}
	case CODEC_REG_WR :
	{
		unsigned long msk = 0xFFFF0000;
		unsigned long p_base = 0x0;
	    p_addr = mn_codec_access.address;
		if (mnhevc->res_usb3.start == (p_addr & msk)) {
    		v_addr = mnhevc->reg_usb3;
			p_base = mnhevc->res_usb3.start;
		}
		else if (mnhevc->res_orc.start == (p_addr & msk)) {
    		v_addr = mnhevc->reg_orc;
			p_base = mnhevc->res_orc.start;
		}
		else {
    		v_addr = mnhevc->reg_mnhevc;
			p_base = mnhevc->res_mnhevc.start;
		}

	    address = (u32)((int)v_addr + (p_addr - p_base));
    	writel(mn_codec_access.reg_data, address);
    	dev_dbg(dev, "REG_WR %d %#x(%#x)\n", mn_codec_access.reg_data, address,
										 	 p_base);

		break;
	}
	case CODEC_MEM_RD :
    	p_addr = mn_codec_access.address;
    	v_addr = mnhevc->mnhevc_och_virt;
    	address = (u32)((int)v_addr + (p_addr - mnhevc->mnhevc_och_phys));
    	dev_dbg(dev, "MEM_RD p %#x v %#x src %#x\n", p_addr, v_addr, address);
    	dev_dbg(dev, "MEM_RD to %p from %#x length %d(%#x)\n",
				  	  (void *)mn_codec_access.mem_data, address,
				  			  mn_codec_access.length,
							  mn_codec_access.length);
	
		if (copy_to_user(mn_codec_access.mem_data, address,
						 mn_codec_access.length))
			ret = -EFAULT;

    	break;
	case CODEC_MEM_WR :
    	p_addr = mn_codec_access.address;
    	v_addr = mnhevc->mnhevc_ich_virt;
    	address = (u32)((int)v_addr + (p_addr - mnhevc->mnhevc_ich_phys));
    	dev_dbg(dev, "MEM_WR p %#x v %#x dest %#x\n", p_addr, v_addr, address);
    	dev_dbg(dev, "MEM_WR to %#x from %p length %d(%#x)\n",
					  address, (void *)mn_codec_access.mem_data,
				  					   mn_codec_access.length,
									   mn_codec_access.length);

		if (copy_from_user(address, mn_codec_access.mem_data,
									mn_codec_access.length))
			ret = -EFAULT;

		break;
	case CODEC_SEND_MESSAGE : {
		/* static int cnt = 0;
		   if (cnt == 0)
			printk(KERN_ERR "%d\n", cnt); */

		writel(mn_codec_access.command,
			   mnhevc->reg_orc + ARM2OPR_CMD);
		dev_dbg(dev, "SND_MSG %d(%#x) %#x",
					  mn_codec_access.command, mn_codec_access.command,
					  mnhevc->reg_orc + ARM2OPR_CMD);

		writel(mn_codec_access.address,
			   mnhevc->reg_orc + ARM2OPR_ADDR);
		dev_dbg(dev, "SND_MSG %#x(%d) %#x",
					  mn_codec_access.address, mn_codec_access.address,
					  mnhevc->reg_orc + ARM2OPR_ADDR);

		writel(mn_codec_access.reg_data,
			   mnhevc->reg_orc + ARM2OPR_DATA);
		dev_dbg(dev, "SND_MSG %d(%#x) %#x", 
					   mn_codec_access.reg_data, mn_codec_access.reg_data,
					   mnhevc->reg_mnhevc + ARM2OPR_DATA);

    	writel(1, mnhevc->reg_orc + ARM2OPR_UPDATE);
		dev_dbg(dev, "SND_MSG %d %#x", 1, mnhevc->reg_orc + ARM2OPR_UPDATE);
    	
		writel(1, mnhevc->reg_orc + ARM2OPR_INTR);
		dev_dbg(dev, "SND_MSG %d %#x", 1, mnhevc->reg_orc + ARM2OPR_INTR);

    	ret = wait_event_interruptible_timeout(mnhevc->vpu_ack,
							readl(mnhevc->reg_orc + OPR2ARM_UPDATE),
							REVELATION_TIMEOUT);
    	if (ret < 1) {
			dev_err(dev, "timeout (%08x)\n", ret);
			ret = -EFAULT;
    	}

		/* if (cnt == 4)
			printk(KERN_ERR "%d\n", cnt); */

    	writel(0, mnhevc->reg_orc + OPR2ARM_UPDATE);
		dev_dbg(dev, "SND_MSG %d %#x", 0, mnhevc->reg_orc + OPR2ARM_UPDATE);

		if (mn_codec_access.command == 2) {
			printk(KERN_ERR "+\n");
			// cnt = 0;
		}
		/* else
			cnt++; */

		break;
	}
	case CODEC_WAIT_DONE :
    	ret = wait_event_interruptible_timeout(mnhevc->vpu_done,
							readl(mnhevc->reg_orc + OPR2ARM_UPDATE),
							REVELATION_TIMEOUT);
    	if (ret < 1) {
			dev_err(dev, "timeout (%08x)\n", ret);
			ret = -EFAULT;
    	}
		printk(KERN_ERR "-\n");
		dev_dbg(dev, "done!\n");
    	
		writel(0, mnhevc->reg_orc + OPR2ARM_UPDATE);
		dev_dbg(dev, "WAIT_DONE %d %#x", 0, mnhevc->reg_orc + OPR2ARM_UPDATE);

    	mn_codec_access.command  = readl(mnhevc->reg_orc + OPR2ARM_CMD);
    	mn_codec_access.address  = readl(mnhevc->reg_orc + OPR2ARM_ADDR);
    	mn_codec_access.reg_data = readl(mnhevc->reg_orc + OPR2ARM_DATA);

		dev_dbg(dev, "WAIT_DONE cmd %d(%#x)(read from %#x)\n",
					  mn_codec_access.command, mn_codec_access.command,
					  mnhevc->reg_orc + OPR2ARM_CMD);
		dev_dbg(dev, "WAIT_DONE addr %#x(%d)(read from %#x)\n",
					  mn_codec_access.address, mn_codec_access.address,
					  mnhevc->reg_orc + OPR2ARM_ADDR);
		dev_dbg(dev, "WAIT_DONE data %d(%#x)(read from %#x)\n",
					  mn_codec_access.reg_data, mn_codec_access,
					  mnhevc->reg_orc + OPR2ARM_DATA);

		break;
	case CODEC_GET_ORC_BASE_PHYS :
		mn_codec_access.reg_data = mnhevc->res_orc.start;
		dev_info(dev, "GET_ORC_BAS_PHYS %#x\n", mnhevc->res_orc.start);
		if (copy_to_user((const void __user *)argp, &mn_codec_access,
						  sizeof(mn_codec_access)))
			return -EINVAL;

		break;
	case CODEC_GET_CODEC_BASE_PHYS:
		mn_codec_access.reg_data = mnhevc->res_mnhevc.start;
		dev_info(dev, "GET_CODEC_BAS_PHYS %#x\n", mnhevc->res_mnhevc.start);
		if (copy_to_user((const void __user *)argp, &mn_codec_access,
						  sizeof(mn_codec_access)))
			return -EINVAL;

		break;
	case CODEC_GET_USB3_BASE_PHYS:
		mn_codec_access.reg_data = mnhevc->res_usb3.start;
		dev_info(dev, "GET_USB3_BASE_PHYS %#x\n", mnhevc->res_usb3.start);
		if (copy_to_user((const void __user *)argp, &mn_codec_access,
						  sizeof(mn_codec_access)))
			return -EINVAL;

		break;
	case CODEC_GET_IO_BUF_PHYS : {
		int shared_fd = mn_codec_access.reg_data;
		bool found = false;
		struct mn_buffer *buf = NULL;

		mutex_lock(&mnhevc->list_lock);
		if (!list_empty(&mnhevc->cbuf->head)) {
			list_for_each_entry(buf, &mnhevc->cbuf->head, list) {
				if (buf->fd == shared_fd) {
					found = true;
					break;
				}
			}
		}
		mutex_unlock(&mnhevc->list_lock);

		if (found) {
			mn_codec_access.reg_data = buf->phys;
			dev_info(dev, "GET_C_BUF_PHYS %#x\n", buf->phys);
			if (copy_to_user((const void __user *)argp, &mn_codec_access,
						  	  sizeof(mn_codec_access))) 
				ret = -EFAULT;

			break;
		}

		mutex_lock(&mnhevc->list_lock);
		if (!list_empty(&mnhevc->ibuf->head)) {
			list_for_each_entry(buf, &mnhevc->ibuf->head, list) {
				if (buf->fd == shared_fd) {
					found = true;
					break;
				}
			}
		}
		mutex_unlock(&mnhevc->list_lock);

		if (found) {
			mn_codec_access.reg_data = buf->phys;
			dev_info(dev, "GET_I_BUF_PHYS %#x\n", buf->phys);
			if (copy_to_user((const void __user *)argp, &mn_codec_access,
						  	  sizeof(mn_codec_access))) 
				ret = -EFAULT;

			break;
		}

		mutex_lock(&mnhevc->list_lock);
		if (!list_empty(&mnhevc->obuf->head)) {
			list_for_each_entry(buf, &mnhevc->obuf->head, list) {
				if (buf->fd == shared_fd) {
					found = true;
					break;
				}
			}
		}
		mutex_unlock(&mnhevc->list_lock);

		if (found) {
			mn_codec_access.reg_data = buf->phys;
			dev_info(dev, "GET_O_BUF_PHYS %#x\n", buf->phys);
			if (copy_to_user((const void __user *)argp, &mn_codec_access,
						  	  sizeof(mn_codec_access))) 
				ret = -EFAULT;
					
			break;
		}
		else {
			dev_err(dev, "Could not find phys requested\n");
			return -EAGAIN;
		}

		break;
	}
	case CODEC_TRANS_TO_USB :
		p_addr = mn_codec_access.address;
		v_addr = mnhevc->mnhevc_ich_virt;
		address = (u32)((int)v_addr + (p_addr - mnhevc->mnhevc_ich_phys)); 
    	dev_info(dev, "TRANS_TO_USB p %#x v %#x dest %#x\n",
					    p_addr, v_addr, address);
    	dev_info(dev, "TRANS_TO_USB %#x from %p length %d(%#x)\n",
					   address, (void *)mn_codec_access.mem_data,
				  						mn_codec_access.length,
										mn_codec_access.length);

		if (copy_from_user(address, mn_codec_access.mem_data,
						   			mn_codec_access.length))
			ret = -EFAULT;

		break;
	defaut:
		dev_err(dev, "Unknown IOCTL interface!\n"); 
		break;
	}
	

    return ret;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static int
mv_mnhevc_init_resource(struct platform_device *pdev)
{
	int ret = VPU_SUCCESS;
	size_t size = 0;
	void __iomem *orc_base = NULL;
	void __iomem *codec_base = NULL;
	void __iomem *usb3_base = NULL;
    struct mn_media_info *mnhevc = GET_MEDIA();
	struct device_node *nd_vpu = mnhevc->nd_vpu;
	struct device *dev = &pdev->dev;
	struct resource codec_res;
	struct resource orc_res;
	struct resource usb3_res;

	ret = of_address_to_resource(nd_vpu, 0, &codec_res);
	if (WARN(ret, "Failed to get hevc resource!"))
		return ret;

	ret = of_address_to_resource(nd_vpu, 1, &orc_res);
	if (WARN(ret, "Failed to get openrisc resource!"))
		return ret;

	ret = of_address_to_resource(nd_vpu, 3, &usb3_res);
	if (WARN(ret, "Failed to get usb3 resource!"))
		return ret;

	codec_base = of_iomap(nd_vpu, 0);
	if (WARN(!codec_base, "Failed to get hevc reg base!"))
		return -EFAULT;

	orc_base = of_iomap(nd_vpu, 1);
	if (WARN(!orc_base, "Failed to get openrisc reg base!"))
		return -EFAULT;

	usb3_base = of_iomap(nd_vpu, 3);
	if (WARN(!orc_base, "Failed to get usb3 reg base!"))
		return -EFAULT;

	memcpy((void *)&mnhevc->res_orc, 
		   (const void *)&orc_res, sizeof(struct resource));
	memcpy((void *)&mnhevc->res_mnhevc,
		   (const void *)&codec_res, sizeof(struct resource));
	memcpy((void *)&mnhevc->res_usb3,
		   (const void *)&usb3_res, sizeof(struct resource));

	mnhevc->reg_mnhevc	   = codec_base;
	mnhevc->reg_orc		   = orc_base;
	mnhevc->reg_usb3	   = usb3_base;
    mnhevc->codec_irq	   = IRQ_HEVC_INTR;
    mnhevc->orc_irq		   = IRQ_OPR0;
    mnhevc->grant		   = -1;
    mnhevc->pdev		   = pdev;

	dev_info(dev, "HEVC reg base vir 0x%x\n", mnhevc->reg_mnhevc);
	dev_info(dev, "HEVC reg base phy 0x%x\n", codec_res.start);
	dev_info(dev, "OpenRISC reg base vir 0x%x\n", mnhevc->reg_orc);
	dev_info(dev, "OpenRISC reg base phy 0x%x\n", orc_res.start);
	dev_info(dev, "USB3 reg base phy 0x%x\n", usb3_res.start);
	dev_info(dev, "USB3 reg base phy 0x%x\n", usb3_res.start);

	return ret;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static int
mv_mnhevc_load_fw(struct platform_device *pdev)
{
	int ret = VPU_SUCCESS;
    struct mn_media_info *mnhevc = GET_MEDIA();

    ret = mv_load_codec_fw(&pdev->dev, mnhevc);
    if (ret < 0) {
		dev_err(&pdev->dev, "Failed to load codec firmware!\n");
		return ret;
    }

	mv_check_fw_version(pdev, mnhevc->code_vers);

	return ret;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static int
mv_mnhevc_init_irq(struct platform_device *pdev)
{
	int ret = VPU_SUCCESS;
    struct mn_media_info *mnhevc = GET_MEDIA();

    ret = request_irq(mnhevc->orc_irq, hevc_isr, IRQF_DISABLED, "mnhevc", NULL);
    if (ret < 0)  {
		dev_err(&pdev->dev, "Failed to request irq %d\n", mnhevc->orc_irq);
		return ret;
    }

	return ret;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static int 
of_platform_vpu_setup(struct platform_device *ofdev)
{
	int ret = VPU_SUCCESS;

	if (mv_mnhevc_init_resource(ofdev) < 0)
		return VPU_FAIL;

	if (mv_mnhevc_init_irq(ofdev) < 0)
		return VPU_FAIL;

	return ret;
}

static const struct file_operations
mv_mnhevc_fops = {
    .open	         = mv_mnhevc_open,
    .release         = mv_mnhevc_close,
    .read 	         = mv_mnhevc_read,
    .write 	         = mv_mnhevc_write,
    .unlocked_ioctl	 = mv_mnhevc_ioctl,
	.mmap            = mv_mnhevc_mmap,

    .owner	         = THIS_MODULE,
};

static struct of_device_id
of_platform_vpu_table[] = {
	{ .compatible = "Mn_nH,MnHEVC Encoder IP", .data = (void *)0, },
	{},
};
	
static struct platform_driver
mv_mnhevc_driver = {
    .probe   = mv_mnhevc_probe,
    .remove  = mv_mnhevc_release,
    .suspend = NULL,
    .resume  = NULL,
    .driver  = {
		.name = MV_VPU_DRV_NAME,
		.owner = THIS_MODULE,
		.of_match_table = of_platform_vpu_table,
    },
};

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static int __init
mv_mnhevc_probe(struct platform_device *pdev)
{
    int ret;
	char *path = NULL;
	struct mn_media_info *mnhevc = GET_MEDIA();
	struct device_node *nd_intc = NULL;
	const struct of_device_id *match = NULL;

	match = of_match_device(&of_platform_vpu_table, &pdev->dev);
	if (WARN(!match, "There is no device matching in of_platform_vpu_table!"))
		return -EINVAL;

	ret = of_property_read_string(of_aliases, "video-encoder", &path);
	if (WARN(ret, "Failed to get video-encoder path!"))
		return -EINVAL;

	mnhevc->nd_vpu = of_find_node_by_path(path);
	if (WARN(!mnhevc->nd_vpu, "Failed to find video-encoder node!"))
		return -EINVAL;

	ret = of_property_read_string(of_aliases, "mv,interrupt-controller", &path);
	if (WARN(ret, "Failed to read intc path!"))
		return -EINVAL;

	nd_intc = of_find_node_by_path(path);
	if (WARN(!nd_intc, "Failed to find intc node!"))
		return -EINVAL;

	mnhevc->irq_dm = irq_find_host(nd_intc);
	if (WARN(!mnhevc->irq_dm, "Failed to get irq domain!"))
		return -EINVAL;

	ret = of_platform_vpu_setup(pdev);
	if (ret < 0)
		goto err;

	mnhevc->cbuf = kzalloc(sizeof(struct mn_buffer), GFP_KERNEL);
	if (WARN(!mnhevc->cbuf, "There is no enough memory for kzalloc!"))
		return -ENOMEM;
	
	mnhevc->ibuf = kzalloc(sizeof(struct mn_buffer), GFP_KERNEL);
	if (WARN(!mnhevc->ibuf, "There is no enough memory for kzalloc!"))
		return -ENOMEM;
	
	mnhevc->obuf = kzalloc(sizeof(struct mn_buffer), GFP_KERNEL);
	if (WARN(!mnhevc->obuf, "There is no enough memory for kzalloc!"))
		return -ENOMEM;

	mnhevc->misc.minor  = MISC_DYNAMIC_MINOR;
	mnhevc->misc.name   = MnHEVC_DEV_NAME;
	mnhevc->misc.fops   = &mv_mnhevc_fops;
	mnhevc->misc.parent = &pdev->dev;
	ret = misc_register(&mnhevc->misc);
	if (WARN(ret, "Failed to register mn-lilith misc device!\n"))
		return ret;

	init_waitqueue_head(&mnhevc->vpu_ack);
    init_waitqueue_head(&mnhevc->vpu_msg);
    init_waitqueue_head(&mnhevc->vpu_done);
    init_waitqueue_head(&mnhevc->vpu_trans);
    init_waitqueue_head(&mnhevc->vpu_err);

	mutex_init(&mnhevc->singleton);
	mutex_init(&mnhevc->list_lock);

	INIT_LIST_HEAD(&mnhevc->cbuf->head);
	INIT_LIST_HEAD(&mnhevc->ibuf->head);
	INIT_LIST_HEAD(&mnhevc->obuf->head);

	platform_set_drvdata(pdev, mnhevc);

    return 0;

err:
    return ret;
}

/* --------------------------------------------------------------------------
 *
 * -------------------------------------------------------------------------- */
static int
mv_mnhevc_release(struct platform_device *pdev)
{
    struct mn_media_info *mnhevc = GET_MEDIA();

    if (mnhevc->reg_mnhevc)
		iounmap((void *)mnhevc->reg_mnhevc);
    
	if (mnhevc->reg_orc)
		iounmap((void *)mnhevc->reg_orc);

    if (mnhevc->codec_irq != (uint32_t)-1)
		free_irq(mnhevc->codec_irq, NULL);

	if (mnhevc->orc_irq != (uint32_t)-1)
		free_irq(mnhevc->orc_irq, NULL);

    mv_unload_codec_fw(mnhevc);
    misc_deregister(&mnhevc->misc);

    return 0;
}

module_platform_driver(mv_mnhevc_driver);

MODULE_DESCRIPTION("Mn_nH MnHEVC Video Processor");
MODULE_AUTHOR("MIN, AUG, JinyoungB Park");
MODULE_LICENSE("Dual BSD/GPL");

#endif

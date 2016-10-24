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

#ifndef _MNHEVC_H
#define _MNHEVC_H

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/font.h>
#include <linux/version.h>
#include <linux/mutex.h>
#include <linux/videodev2.h>
#include <linux/kthread.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
#include <linux/freezer.h>
#endif
//#include <media/videobuf-vmalloc.h>
//#include <media/v4l2-device.h>
//#include <media/v4l2-ioctl.h>
//#include <media/v4l2-ctrls.h>
//#include <media/v4l2-common.h>

#include <linux/firmware.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/semaphore.h>

#include "mnhevc_defines.h"

#define VPU_SUCCESS  0
#define VPU_FAIL    -1

/* --------------------------------------------------------------------------
 * 
 * -------------------------------------------------------------------------- */
struct mn_buffer {
	unsigned int idx;
	unsigned int fd;			// Shread FD from user space

	void *virt;
	phys_addr_t phys;

	size_t size;
	
	struct list_head head;
	struct list_head list;
};

struct mn_media_info {
	uint32_t major;
	uint32_t cdev_nr;
	int32_t  grant;				// used for multi open

	struct mutex singleton;

	wait_queue_head_t vpu_err;
	wait_queue_head_t vpu_msg;
	wait_queue_head_t vpu_ack;
	wait_queue_head_t vpu_done;
	wait_queue_head_t vpu_trans;

    unsigned long reg_syc;			// system controller base
    unsigned long reg_orc;			// openrisc controller base
    unsigned long reg_orc_code;		// openrisc code base
    unsigned long reg_orc_malloc;	// openrisc malloc base
    unsigned long reg_mnhevc;		// mnhevc controller base
    unsigned long reg_usb3;			// mnhevc controller base

	unsigned long mnhevc_ich_virt;	// mnhevc input channel memory base
	unsigned long mnhevc_ich_phys;	// mnhevc input channel memory base
	unsigned long mnhevc_och_virt;	// mnhevc output channel memory base
	unsigned long mnhevc_och_phys;	// mnhevc output channel memory base
	unsigned long mnhevc_conf_virt;	// mnhevc configuration buffer memory base
	unsigned long mnhevc_conf_phys;	// mnhevc configuration buffer memory base
	
	struct resource res_orc;
	struct resource res_mnhevc;
	struct resource res_usb3;

    uint32_t codec_irq;
    uint32_t orc_irq;

    unsigned long code_base_phys;
	unsigned long code_base_virt;
    uint32_t code_vers;
	size_t   code_size;
	
	uint32_t cbuf_cnt;			// Configuration Buffer Counter
	uint32_t ibuf_cnt;			// Input Buffer Counter
	uint32_t obuf_cnt;			// Output Buffer Counter

	struct platform_device *pdev;
	struct miscdevice misc;
	
	struct device_node *nd_vpu;
	struct irq_domain *irq_dm;
	struct firmware *fw;

	struct mutex list_lock;
	struct mn_buffer *cbuf;		// Input Buffer
	struct mn_buffer *ibuf;		// Input Buffer
	struct mn_buffer *obuf;		// Output Buffer
};



/*-----------------------------------------------------------------------------
 * 
 *-----------------------------------------------------------------------------*/
#define MnHEVC_DEV_NAME       "mnhevc0"
#define MnHEVC_MAJOR          241

#define GET_MEDIA()         (&media_info)


#endif

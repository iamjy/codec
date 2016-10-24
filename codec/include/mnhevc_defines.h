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
#ifndef _MNHEVC_DEFINES_H
#define _MNHEVC_DEFINES_H


/*-----------------------------------------------------------------------------
 * System Controller
 *----------------------------------------------------------------------------*/
#define RST_OUT0		0x0B0
#define RST_OUT1		0x0B4 

#define OPR_RSTOUT_BIT	0


/*-----------------------------------------------------------------------------
 * OpenRISC
 *-----------------------------------------------------------------------------*/
#define OPR_ENABLE			0x000

#define OPR_QMEM_IMASK		0x100
#define OPR_QMEM_IADDR		0x104
#define OPR_QMEM_DMASK		0x108
#define OPR_QMEM_DADDR		0x10C
#define OPR_CODE_START		0x110
#define OPR_CODE_REMAP		0x114

#define ARM2OPR_UPDATE		0x080 
#define ARM2OPR_CMD			0x084
#define ARM2OPR_ADDR		0x088
#define ARM2OPR_DATA		0x08C

#define OPR2ARM_UPDATE		0x090
#define OPR2ARM_CMD			0x094
#define OPR2ARM_ADDR		0x098
#define OPR2ARM_DATA		0x09C

#define ARM2OPR_INTR		0x0A0
#define OPR2ARM_INTR		0x0B0

#define QMEM_I_ADDR			(0x90000000)
#define QMEM_I_MASK			(0xFFFFF000)
#define QMEM_D_ADDR			(0x90000000)
#define QMEM_D_MASK			(0xFFFFF000)

#define OPR2ARM_BOOT             	0
#define OPR2ARM_ACK					1
#define OPR2ARM_FRM_DONE         	2
#define OPR2ARM_MESSAGE          	3
#define OPR2ARM_ERR_WriteUVLC    	4
#define OPR2ARM_ERR_UVLC         	5
#define OPR2ARM_ERR_CoRefIdx     	6
#define OPR2ARM_ERR_HierBitAlloc 	7
#define OPR2ARM_ERR_HDR          	8
#define OPR2ARM_ERR              	9

#define ORC_REMAP_ENABLE	(1 << 31)
#define ORC_REMAP_DISABLE	(~(ORC_REMAP_ENABLE) & ORC_REMAP_ENABLE)
#define ORC_CODE_SIZE		SZ_1M
// #define ORC_CODE_BASE    0x10100000
#define ORC_CODE_BASE       0x20000000


/*-----------------------------------------------------------------------------
 * Video Encoder Codec
 *-----------------------------------------------------------------------------*/
// #define MnHEVC_STR_COMPLETE	0x160
// #define MnHEVC_STR_UPDATE	0x164
#define MnHEVC_STR_UPDATE	0xFF0
#define MnHEVC_STR_BASE		0x168
#define MnHEVC_STR_END		0x16C
#define MnHEVC_STR_START	0x170
#define MnHEVC_STR_RADDR	0x174
#define MnHEVC_STR_WADDR	0x178


/*-----------------------------------------------------------------------------
 * USB 3.0 Register
 *----------------------------------------------------------------------------*/
#define USB_CLK_INV			0x000
#define INTR_PC2ARM			0x004

#define ARM2PC_UPDATE		0x100
#define ARM2PC_CMD			0x104
#define ARM2PC_ADDR			0x108
#define ARM2PC_SIZE			0x10C

#define PC2ARM_UPDATE		0x200 
#define PC2ARM_CMD			0x204
#define PC2ARM_ADDR			0x208
#define PC2ARM_SIZE			0x20C


/*-----------------------------------------------------------------------------
 * IOCTL
 *-----------------------------------------------------------------------------*/
#define CODEC_REG_RD    				0x00
#define CODEC_REG_WR    				0x01
#define CODEC_MEM_RD    				0x02
#define CODEC_MEM_WR    				0x03
#define CODEC_SEND_MESSAGE				0x04	// arm2opr
#define CODEC_WAIT_DONE					0x05	// opr2arm
#define CODEC_REGISTER_CONF_BUFFER		0x06
#define CODEC_REGISTER_INPUT_BUFFER		0x07
#define CODEC_REGISTER_OUTPUT_BUFFER	0x08
#define CODEC_UNREGISTER_CONF_BUFFER	0x09
#define CODEC_UNREGISTER_INPUT_BUFFER	0x0A
#define CODEC_UNREGISTER_OUTPUT_BUFFER	0x0B
#define CODEC_GET_ORC_BASE_PHYS			0x0C
#define CODEC_GET_CODEC_BASE_PHYS		0x0D
#define CODEC_GET_USB3_BASE_PHYS		0x0E
#define CODEC_GET_IO_BUF_PHYS			0x0F
#define CODEC_TRANS_TO_USB 				0x10

struct mn_codec_access_info {
    unsigned int control;
	unsigned int command;
    unsigned int address;
    unsigned int length;
    unsigned int reg_data;
    unsigned char *mem_data;
};

#define MnHEVC_IOCTL_MAGIC	'a'
#define CODEC_IOSET_ACCESS	_IOW(MnHEVC_IOCTL_MAGIC, 0x01, \
								 struct mn_codec_access_info)

#endif

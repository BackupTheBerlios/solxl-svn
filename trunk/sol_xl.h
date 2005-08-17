/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at ./OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/* Copyright 2005 Jeremy Teo.
 * All rights reserved.  Use is subject to license terms.
 */
#ifndef SOL_XL_H
#define SOL_XL_H
#endif

#define XL_IDNUM 0 /* zero seems to work    */
#define XL_DRIVER_NAME "sol_xl"
#define XL_HIWAT ETHERMAX
#define XL_LOWAT 1
#define XL_PCI_OPREGS 1
static char xl_gld_ident[] = "3com 905b driver v0.1";
static int xl_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd);
static int xl_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd);

static ether_addr_t xl_broadcast_addr = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};


/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t xl_reg_accattr = {
    DDI_DEVICE_ATTR_V0,
    DDI_STRUCTURE_LE_ACC,
    DDI_STRICTORDER_ACC
};
/* DMA access descriptors for uplist
 *
 */
static ddi_device_acc_attr_t xl_dma_accattr = {
    DDI_DEVICE_ATTR_V0,
    DDI_STRUCTURE_LE_ACC,
    DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t dma_attr = {
    DMA_ATTR_V0,                /* dma_attr version */
    0x00000000ull,              /* dma_attr_addr_lo  */
    0xFFFFFFFFull,              /* dma_attr_addr_hi. The card only supports
                                 * 32bit addresses
                                 */
    0xFFFFFFFFull,              /* dma_attr_count_max   */
    16,                         /* dma_attr_align. 16 byte aligned  */
    0,                          
    0x00000001,                 /* dma_attr_minxfer */
    0xFFFFFFFFull,              /* dma_attr_maxxfer */
    0xFFFFFFFFull,              /* dma_attr_seg     */
    1,                          /* dma_attr_sgllen  */
    1,                          /* dma_attr_granular*/
    0                           /* dma_attr_flags   */
};
/* Describes 1 dma area: eg. 1 dma handle and 1 dma buffer
 * bound together. For use with uplist and downlists
 *
 */

typedef struct dma_area {
    ddi_dma_handle_t handle;
    ddi_acc_handle_t acchandle;
    ddi_dma_cookie_t cookie;
    uint_t           num_cookie;
    void             *addr;
    size_t           alloc_length;
} dma_area_t;
/* Packet reception requires constructing an UpList
 *
 * An UpList is made up of a linked list of UPDs
 * Each UPD is made up of a short header,
 * followed by 1 to 63 UpFrags.
 * Each UpFrag contains an address to a fragment,
 * and the length of said fragment.
 */
/* Describes 1 UpFrag */
typedef struct upfrag {
    uint32_t up_fragaddr;   /* 32 bit address of fragment */
    uint32_t up_fraglength; /* length of the fragment */
} upfrag_t;

/* Describes 1 UPD */
typedef struct upd {
    uint32_t up_nextptr;   /* Points to next upd making up this linked list
                            * which is our UpList.
                            * If this is the last upd, up_nextptr is 0
                            */
    uint32_t up_pktstatus; /* Packet status. NIC fills this in after filling in 
                            *  our upd with data received.
                            */
    upfrag_t up_frags[1];  /* The UpFrags that make up this UPD. For 
                            * learning purposes, only 1 for now. 
                            * We can have up to 63.
                            */
} upd_t;

/* Packet transmission requires constructing a DownList
 *
 * A DownList is made up of a linked list of DPDs
 * Each DPD is made up of a short header, 
 * followed by 1 to 63 DownFrags
 * Each UpFrag contains an address to a fragment,
 * and length of said fragment.
 */

/* Describes one DownFrag */
typedef struct downfrag {
    uint32_t down_fragaddr;   /* 32bit address of fragment */
    uint32_t down_fraglength; /* length of the fragment. Set bit 32 
                               * to indicate last downfrag
                               * for this DPD
                               */
} downfrag_t;

typedef struct dpd {
    uint32_t   down_nextptr;     /* Points to next dpd making up this 
                                  * linked list which is our DownList. 
                                  * If this is the last upd,
                                  * down_nextptr is 0.
                                  */
    /*uint32_t   schedule_time;*/    /* Don't use. set to 0.*/
    uint32_t   frame_startheader;/* packet control info.
                                  * Used to enable/disable various 
                                  * checksumming features,
                                  * as well as when to generate
                                  * TX related interrupts
                                  */
    uint32_t down_fragaddr;
    uint32_t down_fraglength;
                                  
    
} dpd_t;
typedef struct xl_t {
    dev_info_t          *devinfo;      /* device instance */
    gld_mac_info_t      *macinfo;      /* GLD instance data*/
    
    ddi_acc_handle_t    cfg_handle;    /* DDI I/O handle   */
    ddi_acc_handle_t    io_handle;     /* DDI I/O handle   */
    caddr_t             io_regs;       /* for use with ddi_io_get/put */
    uint16_t            device_id;
    uint16_t            vendor_id;
    uint8_t             mac_addr[6];   /* card mac address */
    ddi_iblock_cookie_t iblk;          /* hardware interrupt cookie */
    ddi_softintr_t      reschedule_idp;/* soft interrupt id for xl_reschedule*/
    
    uint32_t            up_liststart;  /* 32bit DMA-able 
                                        * address to starting UPD of UpList
                                        *
                                        */
    dma_area_t          uplist_da;     /* dma_area for uplist 
                                        *  (packet receive)
                                        */
    dma_area_t          upfrag_da;     /* dma_area for one and 
                                        * only upfrag
                                        * (packet receive)
                                        */
    
   
    uint32_t            down_liststart;/* 32bit DMA-able 
                                        * address to starting DPD of DownList
                                        */
    dma_area_t          downlist_da;   /* dma_area for downlist 
                                        *  (packet transmit)
                                        */
    dma_area_t          downfrag_da;   /* dma_area for one and 
                                        * only downfrag
                                        * (packet transmit)
                                        */
    unsigned int        tx_waiting;   /* how many packets from GLD
                                       * are waiting to be sent
                                       */
    uint64_t            intr_fired;   /* how many times xl_gld_intr
                                       * has been called
                                       */
    uint16_t            status_flags; /* Indicates how much of the setup 
                                       * work has been done. Used for
                                       * graceful recovery
                                       */
    
} xl_instance;
/* Bit settings for use with status_flags */
#define XL_FLAG_GLD_ALLOC       0x0001      /* macinfo allocated, as well 
                                               as xl_instance*/
#define XL_FLAG_PCICFG_ALLOC    0x0002      /* pci cfg handle allocated */
#define XL_FLAG_IO_ALLOC        0x0004      /* pci register mapping allocated */
#define XL_FLAG_HINTR_ALLOC     0x0008      /* hardware interrupt allocated */
#define XL_FLAG_SINTR_ALLOC     0x0010      /* software interrupt allocated */
#define XL_FLAG_GLDREG_ALLOC    0x0020      /* gld macinfo registered */
#define XL_FLAG_UPLIST_ALLOC    0x0040      /* uplist allocated */
#define XL_FLAG_UPFRAG_ALLOC    0x0080      /* upfrag allocated */
#define XL_FLAG_DOWNLIST_ALLOC  0x0100      /* downlist allocated */
#define XL_FLAG_DOWNFRAG_ALLOC  0x0200      /* downfrag allocated */
/*3c905B registers (their offsets)
 *
 */
/* Outside Windows */
#define XL_REG_TXSTATUS     0x1B /*TxStatus. 8 bit, r/w*/
#define XL_REG_DOWNLISTPTR  0x24 /* DownListPtr. 32bit*/
#define XL_REG_UPLISTPTR    0x38 /* UpListPtr. 32bit */
 
/* Window 0 */
#define XL_REG_CMD    0x0E /*16 bit command register.Write Only*/
#define XL_REG_STATUS 0x0E /*16 bit intStatus register. Read Only*/
#define XL_REG_EE     0x0A /*16 bit EEPROM cmd register. R/W. */
#define XL_REG_EEDATA 0x0C /*16 bit EEPROM data register. R/W.*/

/* Window 2 */
#define XL_REG_STNADDR     0x00 /* 48bit MAC address register*/ 
#define XL_REG_STNADDRMID  0x02 /* R/W. */ 
#define XL_REG_STNADDRHIGH 0x04   
/* For example, to program 00:20:AF:12:34:56 into the card
 *
 * We would write
 * 
 * - 0x2000 into XL_REG_STNADDR
 * - 0x12AF into XL_REG_STNADDRMID
 * - 0x5634 into XL_REG_STNADDRHIGH
 */

/* Window 6 */
#define XL_REG_FRAMESTXOK 0x06 /* 8 bit register indicating how many
                                * frames transmitted ok
                                */
#define XL_REG_BYTESRXOK  0x0A /* 16 bit register indicating how many
                                * bytes were RX ok.
                                */
#define XL_REG_BYTESTXOK  0x0C /* 16 bit register indicating how many
                                * bytes were TX ok.
                                */
/*3c905B commands
 *
 */
 
#define XL_CMD_WINSEL    0x0800 /* for selecting register windows
                                 * there are total of 8 windows,
                                 * 0 to 7. hence 0x0800 to 0x0807
                                 */
#define XL_CMD_GRESET    0x0000 /* must wait after issuing */
#define XL_CMD_TXRESET   0x5800 /* must wait after issuing */
#define XL_CMD_RXRESET   0x2800 /* must wait after issuing */
#define XL_CMD_RXFILTER  0x8000 /* must OR appropriately
                                 * See XL_SET_RX_PROM etc
                                 */
#define XL_SET_RX_NORM   0x0001 /* OR with XL_CMD_RXFILTER
                                 * to accept packets for this
                                 * mac address only
                                 */
#define XL_SET_RX_MCAST  0x0002 /* all multicast + bcast */
#define XL_SET_RX_BCAST  0x0004 /* bcast */
#define XL_SET_RX_PROM   0x0008 /* promiscuous */
#define XL_SET_RX_MHASH  0x0010 /* mhash filter for 3c90xb only*/
#define XL_CMD_RXENABLE  0x2000 /* enable RX */
#define XL_CMD_RXDISABLE 0x1800 /* disable RX */

#define XL_CMD_TXENABLE  0x4800 /* enable TX  */
#define XL_CMD_TXDISABLE 0x5000 /* disable TX */
#define XL_CMD_INTRACK   0x6800 /* Ack interrupts. Must
                                 * OR with whichever interrupts
                                 * we wish to acknowledge
                                 */
#define XL_CMD_INTRENABLE      0x7000 /* must OR 
                                       * with whichever interrupts
                                       * to enable
                                       */
#define XL_SET_INTR_INTRLATCH  0x0001 /* Always enable this*/
#define XL_SET_INTR_HOSTERROR  0x0002 /* Host Error */
#define XL_SET_INTR_TXCOMP     0x0004 /* TX completed */
#define XL_SET_INTR_RXCOMP     0x0010 /* Don't use*/
#define XL_SET_INTR_RXEARLY    0x0020 /* Don't use */
#define XL_SET_INTR_INTRREQ    0x0040 /* Don't use */
#define XL_SET_INTR_UPDATESTAT 0x0080 /* stats updated */
#define XL_SET_INTR_LINKEVT    0x0100 /* Don't use. */
#define XL_SET_INTR_DPCOMP     0x0200 /* Packet upload to the NIC complete*/
#define XL_SET_INTR_UPCOMP     0x0400 /* Packet download from the NIC complete*/                                 

#define XL_SET_NORND           0x00000001 /*No rnding up of odd length packets*/
#define XL_SET_RNDDEFEAT       0x10000000 /*No rnding up of odd length packets*/
#define XL_SET_DNINDICATE      0x80000000 /* fire an interrupt when
                                           * packet finishes downloading
                                           * to NIC
                                           */
#define XL_SET_TXINDICATE      0x00008000 /* Fire an interrupt when packet
                                           * finishes transmission
                                           */
#define XL_SET_CRCDIS          0x00002000 /* Disable CRC checksumming*/                                     
#define XL_CMD_INDENABLE       0x7800     /* must OR 
                                           * with whichever interrupts
                                           * to enable
                                           */
#define XL_CMD_ENSTATS         0xA800     /* Enable statistics recording */
#define XL_CMD_DISSTATS        0xB000     /* Disable statistics recording */
/* Normal set of interrupts we want enabled */
#define XL_CMD_INTRNORM XL_CMD_INTRENABLE  | XL_SET_INTR_HOSTERROR | XL_SET_INTR_TXCOMP | XL_SET_INTR_DPCOMP | XL_SET_INTR_UPCOMP
#define XL_CMD_INDNORM  XL_CMD_INDENABLE  | XL_SET_INTR_HOSTERROR | XL_SET_INTR_TXCOMP | XL_SET_INTR_DPCOMP | XL_SET_INTR_UPCOMP
#define XL_CMD_INTRDISABLE (XL_CMD_INTRENABLE)

/* EEPROM Commands */
#define XL_EE_READADDR 0x0080 /* must wait 162 microseconds
                               * after issuing
                               */
/*various 3c905B bit offsets 
 *
 */                           

/* Bit offsets for status register */
#define XL_STATUS_INPROGRESS 0x1000 /* indicates command in
                                     * progress. must wait
                                     * until this bit is cleared
                                     */
/* Bit offsets for EEPROM */
#define XL_EE_MACADDR 0x000A /* start of mac address */
#define XL_EE_BUSY    0x8000 /* EEPROM busy bit. 1 == busy */

/* Bit masks for DPD FrameStartHeader */
#define XL_FSH_DNCOMPLETE  0x00010000 /* If set, download of DPD is complete */

/* Bit masks for UPD PacketStatus */
#define XL_PKT_LENGTH     0x00001FFF /* Bits 0 to 12 store length of uploaded 
                                        packet */
#define XL_PKT_UPCOMPLETE 0x00008000 /* Bit 15 indicates upload of this packet
                                      * (from NIC to CPU) is complete
                                      */

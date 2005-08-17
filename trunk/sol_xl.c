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

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/note.h>
#include <sys/modctl.h>
#include <sys/stropts.h>

#include <sys/kstat.h>
#include <sys/ethernet.h>
#include <sys/errno.h>
#include <sys/dlpi.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/cyclic.h>
#include <sys/conf.h>
#include <sys/callb.h>
#include <netinet/ip6.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <netinet/udp.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/gld.h>
#include <sys/kmem.h>

#include "sol_xl.h"
static struct module_info xl_module_info = {
    XL_IDNUM,
    XL_DRIVER_NAME,
    0,
    ETHERMTU,
    XL_HIWAT,
    XL_LOWAT
};

static struct qinit xl_r_qinit = {  /* read queues */
    NULL,
    gld_rsrv,
    gld_open,
    gld_close,
    NULL,
    &xl_module_info,
    NULL
};

static struct qinit xl_w_qinit = {  /* write queues */
    gld_wput,
    gld_wsrv,
    NULL,
    NULL,
    NULL,
    &xl_module_info,
    NULL
};

static struct streamtab xl_streamtab = {
    &xl_r_qinit,
    &xl_w_qinit,
    NULL,
    NULL
};

static struct cb_ops xl_cb_ops = {
    nulldev,        /* cb_open */
    nulldev,        /* cb_close */
    nodev,          /* cb_strategy */
    nodev,          /* cb_print */
    nodev,          /* cb_dump */
    nodev,          /* cb_read */
    nodev,          /* cb_write */
    nodev,          /* cb_ioctl */
    nodev,          /* cb_devmap */
    nodev,          /* cb_mmap */
    nodev,          /* cb_segmap */
    nochpoll,       /* cb_chpoll */
    ddi_prop_op,        /* cb_prop_op */
    &xl_streamtab,  /* cb_stream */
    D_MP,           /* cb_flag */
    CB_REV,         /* cb_rev */
    nodev,          /* cb_aread */
    nodev           /* cb_awrite */
};

static struct dev_ops xl_dev_ops = {
    DEVO_REV,       /* devo_rev */
    0,              /* devo_refcnt */
    gld_getinfo,    /* devo_getinfo */
    nulldev,        /* devo_identify */
    nulldev,        /* devo_probe */
    xl_attach,      /* devo_attach */
    xl_detach,      /* devo_detach */
    nodev,          /* devo_reset */
    &xl_cb_ops,     /* devo_cb_ops */
    (struct bus_ops *)NULL, /* devo_bus_ops */
    NULL            /* devo_power */
};

static struct modldrv xl_modldrv = {
    &mod_driverops,     /* Type of module.  This one is a driver */
    xl_gld_ident,       /* short description */
    &xl_dev_ops         /* driver specific ops */
};

static struct modlinkage modlinkage = {
    MODREV_1,
    (void *)&xl_modldrv,
    NULL
};
/* Helper functions for writing to/reading from registers
 *
 *
 */
#define PIO_ADDR(xl_i, offset)  ((void *)((caddr_t)(xl_i)->io_regs+(offset)))

/*=============32 bit register put/get========================*/
void xl_reg_put32(xl_instance *inst, uintptr_t offset, uint32_t value)
{
    ddi_put32(inst->io_handle, PIO_ADDR(inst,offset), value);
}
uint32_t xl_reg_get32(xl_instance *inst, uintptr_t offset)
{
    return ddi_get32(inst->io_handle, PIO_ADDR(inst,offset));
}
/*============================================================*/
/*=============16 bit register put/get========================*/
void xl_reg_put16(xl_instance *inst, uintptr_t offset, uint16_t value)
{
    ddi_put16(inst->io_handle, PIO_ADDR(inst,offset), value);
}

uint16_t xl_reg_get16(xl_instance *inst, uintptr_t offset)
{
    return ddi_get16(inst->io_handle, PIO_ADDR(inst,offset));
}
/*===========================================================*/
/*=============8 bit register put/get========================*/
void xl_reg_put8(xl_instance *inst, uintptr_t offset, uint8_t value)
{
    ddi_put8(inst->io_handle, PIO_ADDR(inst,offset), value);
}

uint8_t xl_reg_get8(xl_instance *inst, uintptr_t offset)
{
    return ddi_get8(inst->io_handle, PIO_ADDR(inst,offset));
}
/*==========================================================*/

/* Specific functions for manipulating the 3c905B
 *
 */

void xl_wait(xl_instance *inst)
{
    /* For certain commands issued to the 3c905B, we must wait
     * for the commands to finish. Hence the reason for this
     * function. We wait 1 milliseconds, check a cmdInProgress
     * bit in XL_REG_STATUS and return if the bit is cleared.
     * else we keep waiting, up to a 100 milliseconds. If by then
     * it hasn't finished, then the chip is seriously borked.
     */
    int i;
    uint16_t result;
    
    for(i = 0; i < 100; i++)
    {
        delay(drv_usectohz(1000) ); /* 1 milli-second
                                   * == 1 micro-second
                                   */
        result = xl_reg_get16(inst, XL_REG_STATUS);
        
        if( (result & XL_STATUS_INPROGRESS) == 0 )
        {
            /* Chip has finished. We can return */
            return;
        }
    }
    
    cmn_err(CE_WARN, "sol_xl--xl_wait chip never finishes command");
    return;
}
void xl_win_sel(xl_instance *inst, int window)
{
    uint16_t target_window;
    /* The 3c905B has windows 0 to 7, for a total of 8 windows.
     * Doing a simple logical OR of the specified window with
     * XL_WIN_BASE will give us the value to place into the XL_CMD
     * register
     */

    target_window = XL_CMD_WINSEL | window;
    xl_reg_put16(inst, XL_REG_CMD, target_window);
    /* No need to wait after this command according to mfgr docs.*/
    return;
}

void xl_greset(xl_instance *inst)
{
    uint16_t r_cmd = XL_CMD_GRESET;
    xl_wait(inst);
    /* We must make sure no other command is pending
     * before we issue our reset cmd. hence the first xl_wait;
     */
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);
    /* Must wait after this command according to mfgr docs.*/
    xl_wait(inst);
    return;
}

void xl_ee_wait(xl_instance *inst)
{
    /* Some EEPROM commands take very long to complete.
     * So we wait as instructed by the mfgr docs.
     */
     
    int i;
    uint16_t result;
    
    for(i = 0; i < 100; i++)
    {
        delay(drv_usectohz(162) );
        result = xl_reg_get16(inst, XL_REG_EE);
        
        if( (result & XL_EE_BUSY)==0 )
        {
            return;
        }
    }
    
    cmn_err(CE_WARN, "sol_xl--xl_ee_wait chip never finishes command");
    return;
}
#define EEPROM_5BIT_OFFSET(A) ((((A) << 2) & 0x7F00) | ((A) & 0x003F))
void xl_getmacaddr(xl_instance *inst)
{
    /* This function extracts the mac address of the card.
     * total of 6 bytes, stored in the EEPROM of the card.
     * We access the EEPROM by
     * - Selecting window 0
     * - Sending an EEPROM read command with the offset of the
     *   MAC address within the EEPROM
     * - Waiting for 162 microseconds
     * - Reading the data back.
     */
     
    uint16_t r_cmd;
    uint16_t result;
    uint16_t *ptr;
    int i;
    
    xl_win_sel(inst, 0);
    
    for(i = 0; i < 3; i++)
    {
        r_cmd = (XL_EE_READADDR | EEPROM_5BIT_OFFSET(XL_EE_MACADDR + i));
        
        xl_reg_put16(inst, XL_REG_EE, r_cmd);
        xl_ee_wait(inst);
        result = xl_reg_get16(inst, XL_REG_EEDATA);
        
        result = ntohs(result);
        ptr = (uint16_t *)(inst->mac_addr + (i*2));
        *ptr = result;
    }

    return;
}

void xl_setmacaddr(xl_instance *inst)
{
    /* This function programs the mac address in *inst
     * into the StationAddress register of the card.
     * This is used for packet reception.
     * We need to
     * - Select window 2
     * - Write 3 words into StationAddress
     */
    uint16_t curr_word;
    uint16_t *ptr;
    int i;
    
    xl_win_sel(inst, 2);
    
    for(i = 0; i < 3; i++)
    {
        ptr = (uint16_t *)(inst->mac_addr + (i*2));
        curr_word = *ptr;
        xl_reg_put16(inst, (XL_REG_STNADDR + (i*2)),curr_word);
    }

    /* For debugging purposes */
    for(i = 0; i < 3; i++)
    {
        curr_word = xl_reg_get16(inst, (XL_REG_STNADDR + (i*2)) );
        curr_word = ntohs(curr_word);
        cmn_err(CE_NOTE, "xl_setmacaddr -- curr_word is %4x", curr_word);
    }
    /* End debug */
}

void xl_txreset(xl_instance *inst)
{
    uint16_t r_cmd = XL_CMD_TXRESET;
    
    xl_wait(inst);
    /* We must make sure no other command is pending
     * before we issue our reset cmd. hence the first xl_wait;
     */
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);
    /* Must wait after this command according to mfgr docs.*/
    xl_wait(inst);
    return;
}

void xl_rxreset(xl_instance *inst)
{
    uint16_t r_cmd = XL_CMD_RXRESET;
    
    xl_wait(inst);
    /* We must make sure no other command is pending
     * before we issue our reset cmd. hence the first xl_wait;
     */
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);
    /* Must wait after this command according to mfgr docs.*/
    xl_wait(inst);
    return;
}

void xl_total_reset(xl_instance *inst)
{
    xl_greset(inst);
    xl_txreset(inst);
    xl_rxreset(inst);
    return;
}
int xl_alloc_dma_area(xl_instance *inst, dma_area_t *da, size_t da_size)
{
    int err;
    caddr_t va;
    /* To use dma we must do the following
     *
     * - acquire a DMA handle
     * - get a buffer using ddi_dma_mem_alloc
     * - bind the 2 together
     */

     /* Acquire an handle */
    err = ddi_dma_alloc_handle(inst->devinfo, &dma_attr,
            DDI_DMA_DONTWAIT, NULL,&da->handle);
    if(err != DDI_SUCCESS)
    {
        cmn_err(CE_WARN, "sol_xl--xl_alloc_dma_area: dma_alloc_handle failed");
        return DDI_FAILURE;
    }

    /* Acquire the buffer */
    err = ddi_dma_mem_alloc(da->handle,da_size,
            &xl_dma_accattr,DDI_DMA_RDWR|DDI_DMA_CONSISTENT|DDI_DMA_STREAMING,
            DDI_DMA_DONTWAIT, NULL, &va,&da->alloc_length,
            &da->acchandle);

    if(err != DDI_SUCCESS)
    {
        cmn_err(CE_WARN, "sol_xl--xl_alloc_dma_area: dma_mem_alloc failed");
        ddi_dma_free_handle(&da->handle);
        return DDI_FAILURE;
    }
    
    da->addr = va;

    /* Bind the two together */
    err = ddi_dma_addr_bind_handle(da->handle, NULL,
            da->addr, da->alloc_length, DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
            DDI_DMA_DONTWAIT, NULL,
            &da->cookie, &da->num_cookie);

    if (err != DDI_DMA_MAPPED || da->num_cookie != 1)
    {
        cmn_err(CE_WARN, "sol_xl--xl_alloc_dma_area: dma_addr_bind_handle failed");
        ddi_dma_mem_free(&da->acchandle);
        (void) ddi_dma_unbind_handle(da->handle);
        ddi_dma_free_handle(&da->handle);
        return DDI_FAILURE;
    }
     
    /* What follows are a bunch of debug statements */
    cmn_err(CE_NOTE, "xl_alloc_dma_area:alloc_length is %d", da->alloc_length);
    cmn_err(CE_NOTE, "xl_alloc_dma_area:num_cookies is %d",
            da->num_cookie);
    cmn_err(CE_NOTE, "xl_alloc_dma_area:da->cookie.dmac_address is %08x",
            (da->cookie).dmac_address );
    cmn_err(CE_NOTE, "xl_alloc_dma_area:da->cookie.dmac_laddress is %16x",
            (da->cookie).dmac_laddress );
    /* End of debug statements */
     
     return DDI_SUCCESS;
}

void xl_free_dma_area(dma_area_t *da)
{
    if(da->handle != NULL)
    {
        if(da->num_cookie )
        {
            (void) ddi_dma_unbind_handle(da->handle);
            da->num_cookie = 0;
        }
            ddi_dma_free_handle(&da->handle);
            da->handle = NULL;
    }

    if ( da->acchandle != NULL)
    {
        ddi_dma_mem_free(&da->acchandle);
        da->acchandle = NULL;
    }
}
int xl_alloc_uplist(xl_instance *inst)
{
    /* Allocates DMA-able memory and constructs an UpList
     * for getting packets from the NIC.
     */

    int err;
    upd_t *the_upd;
    /* To use dma we must do the following
     *
     * - acquire a DMA handle
     * - get a buffer using ddi_dma_mem_alloc
     * - bind the 2 together
     */
     
    err = xl_alloc_dma_area(inst, &inst->uplist_da, sizeof(upd_t));
    inst->up_liststart = ((inst->uplist_da).cookie).dmac_address;
    cmn_err(CE_NOTE, "xl_alloc_uplist:inst->up_liststart is %16x",
            inst->up_liststart);
            
    if(err == DDI_SUCCESS)
    {
        the_upd = (inst->uplist_da).addr; /* Use the virtual address.
                                           * Using dmac_address IS
                                           * NOT correct.
                                           */
        the_upd->up_nextptr = NULL;
        the_upd->up_pktstatus = 0;
    }
     
    return err;
}

void xl_free_uplist(xl_instance *inst)
{
    dma_area_t *da;
    da = &inst->uplist_da;
    xl_free_dma_area(da);
    inst->up_liststart=NULL;
}

int xl_alloc_upfrag(xl_instance *inst)
{
    /* Allocates DMA buffer for upfrags */

    int err;
    dma_area_t *da;
    upd_t *the_upd;
    
    err= xl_alloc_dma_area(inst, &inst->upfrag_da, ETHERMAX );
    da = &inst->upfrag_da;
    the_upd = (inst->uplist_da).addr; /* Use the virtual address.
                                       * Using dmac_address IS
                                       * NOT correct.
                                       */
    the_upd->up_frags[0].up_fragaddr = (da->cookie).dmac_address;
    the_upd->up_frags[0].up_fraglength = 0x80000000 | (da->cookie).dmac_size;
    cmn_err(CE_NOTE, "xl_alloc_upfrag: up_fraglength is %8x",
            the_upd->up_frags[0].up_fraglength);

    err = ddi_dma_sync((inst->upfrag_da).handle, 0 ,
            (inst->upfrag_da).alloc_length,DDI_DMA_SYNC_FORDEV);
    
    if(err != DDI_SUCCESS)
    {
       cmn_err(CE_WARN, "xl_alloc_upfrag-- cannot dma_sync upfrag");
    }

    err = ddi_dma_sync((inst->uplist_da).handle, 0 ,
            (inst->uplist_da).alloc_length,DDI_DMA_SYNC_FORDEV);
            
    if(err != DDI_SUCCESS)
    {
        cmn_err(CE_WARN, "xl_alloc_upfrag-- cannot dma_sync uplist");
    }
    
    return err;
}

void xl_free_upfrag(xl_instance *inst)
{
    dma_area_t *da;
    da = &inst->upfrag_da;
    xl_free_dma_area(da);
}

int xl_alloc_downlist(xl_instance *inst)
{
    /* Allocates DMA-able memory and constructs an DownList
     * for passing packets to the NIC
     */
    int err;
    dpd_t *the_dpd;
    
    err = xl_alloc_dma_area(inst, &inst->downlist_da, sizeof(dpd_t));
    inst->down_liststart = ((inst->downlist_da).cookie).dmac_address;
    cmn_err(CE_NOTE, "xl_alloc_downlist:inst->down_liststart is %16x",
            inst->down_liststart);

    if(err == DDI_SUCCESS)
    {
        the_dpd = (inst->downlist_da).addr; /* Use the virtual address.
                                             * Using dmac_address IS
                                             * NOT correct if we want
                                             * to access it using CPU.
                                             */
        the_dpd->down_nextptr = 0;
        /*the_dpd->schedule_time = 0;*/
        the_dpd->frame_startheader =  XL_SET_NORND | XL_SET_RNDDEFEAT | XL_SET_DNINDICATE |XL_SET_TXINDICATE;
    }
    
    return err;

}

void xl_free_downlist(xl_instance *inst)
{
    dma_area_t *da;
    da = &inst->downlist_da;
    xl_free_dma_area(da);
    inst->down_liststart=NULL;
}

int xl_alloc_downfrag(xl_instance *inst)
{
    /* Allocates DMA buffer for downfrags */
    int err;
    dma_area_t *da;
    dpd_t *the_dpd;
    
    err= xl_alloc_dma_area(inst, &inst->downfrag_da, ETHERMAX );
    da = &inst->downfrag_da;
    the_dpd = (inst->downlist_da).addr; /* Use the virtual address.
                                         * Using dmac_address IS
                                         * NOT correct if we want
                                         * to access it using CPU.
                                         */
    the_dpd->down_fragaddr   = (da->cookie).dmac_address;
    the_dpd->down_fraglength = 0x80000000 | (da->cookie).dmac_size;

    cmn_err(CE_NOTE, "xl_alloc_downfrag: down_fraglength is %8x",
    the_dpd->down_fraglength);

    return err;
}

void xl_free_downfrag(xl_instance *inst)
{
    dma_area_t *da;
    da = &inst->downfrag_da;
    xl_free_dma_area(da);
}

void xl_prepare_recv(xl_instance *inst)
{
    /* Used to instruct the card prepare for receiving packets.
     * We do everything short of enabling receive and interrupts,
     * which will be done by xl_gld_start
     * The following needs to be done to achieve this
     *
     * - set the appropriate filter values
     *   eg. Promiscuous, match our address only etc etc.
     * - bzero our upfrag just to be safe.
     * - dma sync so that any changes we've made can be seen by the NIC
     * - program in our uplist address into the UpListPtr register
     *
     */
    int err;
    uint16_t r_cmd;
    upd_t *the_upd;
    
    the_upd = (inst->uplist_da).addr;
    the_upd->up_pktstatus = 0;
    the_upd->up_nextptr   = 0;
    
    bzero((inst->upfrag_da).addr, (inst->upfrag_da).alloc_length);
    
    /* Sync the uplist and upfrag before giving the DMA address
     * to the NIC.
     */
    err = ddi_dma_sync((inst->uplist_da).handle, 0 ,
            0,DDI_DMA_SYNC_FORDEV);
     
    if(err != DDI_SUCCESS)
    {
        cmn_err(CE_WARN, "xl_prepare_recv-- cannot dma_sync uplist");
    }

    err = ddi_dma_sync((inst->upfrag_da).handle, 0 ,
            0,DDI_DMA_SYNC_FORDEV);
     
    if(err != DDI_SUCCESS)
    {
        cmn_err(CE_WARN, "xl_prepare_recv-- cannot dma_sync upfrag");
    }

    /* Set the appropriate filter values.
     * This means
     *
     * - select window 0
     * - program the correct filter value using
     *   the SetRxFilter command
     *
     * For now hardcode to receive packets for this mac
     * address, multicast and broadcast packets
     */
     
    xl_win_sel(inst, 0);
    /*r_cmd = XL_CMD_RXFILTER | XL_SET_RX_NORM | XL_SET_RX_PROM;*/
    r_cmd = XL_CMD_RXFILTER | XL_SET_RX_NORM | XL_SET_RX_MCAST;
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);

    /* Load our uplist address into UpListPtr register.
     * Must be 8 byte aligned,
     * (we chose 16 byte so it should be alright)
     * 32 bit address only.
     */
    xl_reg_put32(inst,XL_REG_UPLISTPTR, inst->up_liststart);

}

void xl_enable_recv(xl_instance *inst)
{
    /* Used to enable reception of packets.
     * Does not enable interrupts.
     *
     */
    uint16_t r_cmd;
    r_cmd = XL_CMD_RXENABLE;
    xl_win_sel(inst, 0);
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);

}

void xl_disable_recv(xl_instance *inst)
{
    /* Used to disable reception of packets.
     * Does not disable interrupts.
     *
     */
    uint16_t r_cmd;
    r_cmd = XL_CMD_RXDISABLE;
    xl_win_sel(inst, 0);
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);
    
}

void xl_prepare_send(xl_instance *inst)
{
    /* Used to instruct the card prepare for sending packets.
     * We do everything short of enabling transmission and interrupts,
     * which will be done by xl_start
     * The following needs to be done to achieve this
     * - dma sync our downlist and downfrag
     * - program in our downlist address into the DownListPtr register
     */
    int err;
    dpd_t *the_dpd;
    uint32_t dnlistptr;
    
    the_dpd = (inst->downlist_da).addr;

    the_dpd->down_nextptr      = 0;
    the_dpd->frame_startheader = XL_SET_NORND | XL_SET_DNINDICATE;

    /* Sync the downlist and downfrag before giving the DMA address
     * to the NIC.
     */
    err = ddi_dma_sync((inst->downlist_da).handle, 0 ,
            0,DDI_DMA_SYNC_FORDEV);
            
    if(err != DDI_SUCCESS)
    {
        cmn_err(CE_WARN, "xl_prepare_send-- cannot dma_sync downlist");
    }

    err = ddi_dma_sync((inst->downfrag_da).handle, 0 ,
            0,DDI_DMA_SYNC_FORDEV);
     
    if(err != DDI_SUCCESS)
    {
        cmn_err(CE_WARN, "xl_prepare_send-- cannot dma_sync downfrag");
    }
     
    /* Load our downlist address into DownListPtr register.
     * Must be 8 byte aligned,
     * (we chose 16 byte so it should be alright)
     * 32 bit address only.
     */
     
    xl_reg_put32(inst,XL_REG_DOWNLISTPTR, inst->down_liststart);
    
}

void xl_enable_send(xl_instance *inst)
{
    /* Used to enable transmission of packets.
     * Does not enable interrupts.
     */
    uint16_t r_cmd;
    r_cmd = XL_CMD_TXENABLE;
    xl_win_sel(inst, 0);
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);
    
}

void xl_disable_send(xl_instance *inst)
{
    /* Used to disable transmission of packets.
     * Does not disable interrupts.
     *
     */
    uint16_t r_cmd;
    r_cmd = XL_CMD_TXDISABLE;
    xl_win_sel(inst, 0);
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);
    
}
void xl_enable_intr(xl_instance *inst)
{
    /* Used to enable interrupts */
    
    /* In order to enable interrupts, 2 commands must be issued
     * 1) Interrupt Enable  (allows interrupts to fire)
     * 2) Indication Enable (allows the driver to see that interrupts 
     *                       have fired)
     */

    uint16_t r_cmd;
    uint16_t intStatus;

    /* Debug statements follow */
    xl_win_sel(inst, 5);
    intStatus=xl_reg_get16(inst, 0xA);
    cmn_err(CE_NOTE,"xl_enable_intr: BEFORE: intEnable=%04x", intStatus);
    /* End of debug statements */
    
    /* Execute an Interrupt Enable Command, with our usual set of 
     * interrupts
     */
    r_cmd = XL_CMD_INTRNORM;
    xl_win_sel(inst, 0);
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);

    /* Likewise execute an Indication Enable Command, with our usual set of 
     * interrupts that we want to see
     */
    r_cmd = XL_CMD_INDNORM;
    xl_win_sel(inst, 0);
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);

    /* Debug statements follow */
    xl_win_sel(inst, 5);
    intStatus=xl_reg_get16(inst, 0xA);
    cmn_err(CE_NOTE,"xl_enable_intr: AFTER: intEnable=%04x", intStatus);
    /* End of debug statements */

}
void xl_disable_intr(xl_instance *inst)
{
    /* Used to disable interrupts */

    uint16_t r_cmd = XL_CMD_INTRDISABLE;
    xl_win_sel(inst, 0);
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);

}


mblk_t *xl_build_recv_msg(xl_instance *inst)
{
    /* This function is to be called when the NIC
     * has finished uploading a packet into the upfrag
     * of our uplist. It then builds a mblk_t from the
     * uploaded packet, and returns a pointer to it.
     *
     *
     * This function can return a NULL pointer under certain
     * conditions, so please check the return value!
     */
    int err;
    mblk_t *mp;
    upd_t *the_upd;
    uint32_t pktstatus;
    size_t mblen;
    void *recv_buf;

    /* dma sync uplist_da and upfrag_da */
    err = ddi_dma_sync((inst->upfrag_da).handle, 0 ,
            0,DDI_DMA_SYNC_FORKERNEL);
            
    if(err != DDI_SUCCESS)
    {
         cmn_err(CE_WARN, "xl_gld_build_recv_msg-- cannot dma_sync buffer");
    }

    err = ddi_dma_sync((inst->uplist_da).handle, 0 ,
            0,DDI_DMA_SYNC_FORKERNEL);
            
    if(err != DDI_SUCCESS)
    {
        cmn_err(CE_WARN, "xl_gld_build_recv_msg-- cannot dma_sync buffer");
    }

    the_upd  = (inst->uplist_da).addr; /* Use the virtual address */
    pktstatus = the_upd->up_pktstatus;
     

    if(pktstatus & XL_PKT_UPCOMPLETE == NULL)
    {
        /* Upload not complete. Return a NULL pointer.
         * Complain also.
         */
        cmn_err(CE_WARN, "sol_xl:xl_build_recv_msg--packet not ready");
        return NULL;
    }

    mblen = (pktstatus & XL_PKT_LENGTH);
    mp    = allocb(mblen, BPRI_MED);
    
    if(mp == NULL)
    {
        /* No memory. Complain, then return a NULL pointer
         */
        cmn_err(CE_WARN, "sol_xl:xl_build_recv_msg--cannot allocb()");
        return NULL;
    }
    
    mp->b_wptr = mp->b_rptr + mblen;
    recv_buf   = (inst->upfrag_da).addr; /* where our actual packet has
                                            been uploaded to. */
    bcopy(recv_buf, mp->b_rptr, mblen);

    /* Success! Now return our mblk_t */
    return mp;

}

void xl_enable_stats(xl_instance *inst)
{
    /* Enables statistics recording on the NIC */
    uint16_t r_cmd;
    r_cmd = XL_CMD_ENSTATS;

    xl_win_sel(inst, 0);
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);
    
}

void xl_disable_stats(xl_instance *inst)
{
    /* Disables statistics recording on the NIC */
    uint16_t r_cmd;
    r_cmd = XL_CMD_DISSTATS;

    xl_win_sel(inst, 0);
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);
    
}

uint_t xl_reschedule(caddr_t arg)
{
    /* Soft interrupt handler to be triggered
     * when GLD called xl_gld_send, and xl_gld_send
     * couldn't satisfy the send request
     */
    xl_instance *inst;
    inst = (xl_instance *)arg;

    if(inst->tx_waiting == 1)
    {
        gld_sched(inst->macinfo);
        inst->tx_waiting = 0;
        return DDI_INTR_CLAIMED;
    }

    return DDI_INTR_UNCLAIMED;

}
/*GLD required functions.
 *
 */
static int
xl_gld_reset(gld_mac_info_t *macinfo)
{
    /* Resets NIC to initial state */
    xl_instance *inst;
    inst = (xl_instance*)(macinfo->gldm_private);
    xl_total_reset(inst);
    return GLD_SUCCESS;
}

static int
xl_gld_stop(gld_mac_info_t *macinfo)
{
    /* Stops NIC from generating interrupts
     * as well as this driver from calling
     * gld_recv.
     */
    xl_instance *inst;
    inst = (xl_instance*)(macinfo->gldm_private);

    xl_disable_recv(inst);
    xl_disable_send(inst);
    xl_disable_intr(inst);
    

    return GLD_SUCCESS;
    
}

static int
xl_gld_start(gld_mac_info_t *macinfo)
{
    /* Enables interrupts, and prepares driver
     * to call gld_recv to deliver received packets
     *
     */
    uint16_t r_cmd;
    xl_instance *inst;
    inst = (xl_instance*)(macinfo->gldm_private);


    xl_enable_intr(inst);
    xl_prepare_recv(inst);
    xl_enable_recv(inst);
    xl_enable_send(inst);
    

    return GLD_SUCCESS;
    
}

static int
xl_gld_set_mac_addr(gld_mac_info_t *macinfo)
{
    /* STUB */
    return GLD_NOTSUPPORTED;
}

static int
xl_gld_set_multicast(gld_mac_info_t *macinfo)
{
    /* STUB */
    return GLD_NOTSUPPORTED;
}

static int
xl_gld_set_promiscuous(gld_mac_info_t *macinfo, int pflag)
{
    xl_instance *inst;
    inst = (xl_instance*)(macinfo->gldm_private);
    uint16_t r_cmd;

    if( pflag == GLD_MAC_PROMISC_NONE)
    {
        r_cmd = XL_CMD_RXFILTER |  XL_SET_RX_NORM | XL_SET_RX_BCAST;
    }
    else
    {
        r_cmd = XL_CMD_RXFILTER | XL_SET_RX_PROM;
    }

    xl_win_sel(inst, 0);
    xl_reg_put16(inst, XL_REG_CMD, r_cmd);
    return GLD_SUCCESS;
}



static int
xl_gld_get_stats(gld_mac_info_t *macinfo, struct gld_stats *glsp)
{
    /* Set almost everything to zero until we implement it. */
    glsp->glds_speed = 10000000;
    glsp->glds_media = GLDM_10BT;
    glsp->glds_intr = 0;
    glsp->glds_norcvbuf = 0;
    glsp->glds_errrcv = 0;
    glsp->glds_errxmt = 0;
    glsp->glds_missed = 0;
    glsp->glds_underflow = 0;
    glsp->glds_overflow = 0;
    glsp->glds_frame = 0;
    glsp->glds_crc = 0;
    glsp->glds_duplex = 0;
    glsp->glds_nocarrier = 0;
    glsp->glds_collisions = 0;
    glsp->glds_excoll = 0;
    glsp->glds_xmtlatecoll = 0;
    glsp->glds_defer = 0;
    glsp->glds_dot3_first_coll = 0;
    glsp->glds_dot3_multi_coll = 0;
    glsp->glds_dot3_sqe_error = 0;
    glsp->glds_dot3_mac_xmt_error = 0;
    glsp->glds_dot3_mac_rcv_error = 0;
    glsp->glds_dot3_frame_too_long = 0;
    glsp->glds_short = 0;
    return GLD_SUCCESS;
}

static uint_t
xl_gld_intr(gld_mac_info_t *macinfo)
{
    /* GLD interrupt handler. The logic is as follows:
     *
     * - Determine what caused the interrupt by examining
     *   the intStatus register
     * - Acknowledge the interrupt
     * - Take the appropriate action
     *
     */
    xl_instance *inst;
    uint16_t intStatus;
    uint16_t xmitOk;
    uint16_t rxOk;
    uint8_t framesTX;
    uint8_t txStatus;
    mblk_t *mp;
    
    inst = (xl_instance*)(macinfo->gldm_private);
    inst->intr_fired++;
    /* Get the intStatus register contents */
    xl_win_sel(inst, 0);
    intStatus = xl_reg_get16(inst, XL_REG_STATUS);

    txStatus = xl_reg_get8(inst, XL_REG_TXSTATUS);

    /* Determine what caused the interrupt */
    if(intStatus & XL_SET_INTR_INTRLATCH) /* Make sure not a spurious
                                           * interrupt
                                           */
    {
        /* First acknowledge the interrupt latch*/
        xl_reg_put16(inst, XL_REG_CMD, XL_CMD_INTRACK|XL_SET_INTR_INTRLATCH);

        if(intStatus & XL_SET_INTR_HOSTERROR)
        {
            /* Host error */
        }

        if((intStatus & XL_SET_INTR_TXCOMP) || (intStatus & XL_SET_INTR_DPCOMP))
        {
            /* Transmission complete or packet has been
             * copied to the NIC.
             * Acknowledge it, then
             * trigger our reschedule soft interrupt
             * in case a packet is waiting to be transmitted
             */
             /*xl_win_sel(inst, 6);
             xmitOk   = xl_reg_get16(inst,XL_REG_BYTESTXOK);
             framesTX = xl_reg_get8(inst,XL_REG_FRAMESTXOK);
             cmn_err(CE_NOTE, "xmitOk::%d",xmitOk);
             cmn_err(CE_NOTE, "framesTX::%d",framesTX);
             cmn_err(CE_NOTE, "intStatus>>%4x", intStatus);
             cmn_err(CE_NOTE, "txStatus::0x%2x", txStatus);*/

             xl_win_sel(inst, 0);
             if(intStatus & XL_SET_INTR_TXCOMP)
             {
                 /* Acknowledge by writing an arbitary value
                  * to TxStatus
                  */
                  xl_reg_put8(inst,XL_REG_TXSTATUS, 0);

             }
             if(intStatus & XL_SET_INTR_DPCOMP)
             {
                 /* Acknowledge by issuing a AckIntr command
                  * with the proper bit set.
                  */
                  xl_reg_put16(inst, XL_REG_CMD,
                               XL_CMD_INTRACK|XL_SET_INTR_DPCOMP);

             }
             ddi_trigger_softintr(inst->reschedule_idp);
        }

        if(intStatus & XL_SET_INTR_UPCOMP)
        {
           /* Upload complete. ie. Packet has been
            * copied from the NIC to our DMA area.
            * We need to do the following:
            * - Acknowledge the interrupt
            * - Build a return mblk_t linked list and return it
            *   to GLD using gld_recv()
            * - call xl_prepare_recv() to put an address in
            *   UpListPtr again to continue reception
            */
            /*xl_win_sel(inst, 6);
            rxOk = xl_reg_get16(inst,XL_REG_BYTESRXOK);*/
            xl_win_sel(inst, 0);

            /* Acknowledge the interrupt */
            xl_reg_put16(inst, XL_REG_CMD,
                         XL_CMD_INTRACK|XL_SET_INTR_UPCOMP);

            /* Build a return mblk_t */
            mp = xl_build_recv_msg(inst);
            if( mp )
            {
                gld_recv(macinfo,mp);
            }
            xl_prepare_recv(inst);
        }

        return DDI_INTR_CLAIMED;
    }
    /* If we ever reached here, it is a spurious interrupt */
    return DDI_INTR_UNCLAIMED;
}
void xl_debug_temp(void *ptr)
{
}
static int
xl_gld_send(gld_mac_info_t *macinfo, mblk_t *mp)
{
    int err;
    xl_instance *inst;
    inst = (xl_instance*)(macinfo->gldm_private);
    dpd_t *the_dpd;
    void *dn_fragbuf;
    mblk_t *bp;
    size_t msg_size;
    size_t total_copied;
    uint32_t DnListPtr;

    /* To send a packet, we must
     * do the following:
     *
     * - check to see if dpd has finished downloading into NIC.
     * - if it has, then proceed with the below, else schedule a resend
     *   later via the resched soft interrupt.
     * - copy the contents of the mblk_t linked list into
         our contiguous block of memory known as the DownFrag
     * - check to see if DnListPtr register is 0. If it is, the NIC
     *   is waiting for the next packet, so we proceed to write
     *   downlist_start into DnListPtr ie. call xl_prepare_send again.
     *
     */

    the_dpd = (inst->downlist_da).addr;

    err = ddi_dma_sync((inst->downlist_da).handle, 0 ,
            (inst->downlist_da).alloc_length,DDI_DMA_SYNC_FORKERNEL);
            
    if(err != DDI_SUCCESS)
    {
        cmn_err(CE_WARN, "xl_gld_send-- cannot dma_sync buffer");
    }
    
    /* Has the NIC finished downloading our DPD? */
    if(the_dpd->frame_startheader & XL_FSH_DNCOMPLETE == NULL)
    {
        /* No. So this packet has to wait. We will have to
         * call gld_sched() later to ask GLD to retry.
         */
        
        inst->tx_waiting=1;

        
        return GLD_NORESOURCES;
    }

    /* Is DnListPtr 0? Since we only have 1 DPD, we
     * must wait until the NIC has finished with it.
     */
    DnListPtr = xl_reg_get32(inst, XL_REG_DOWNLISTPTR);
    if(DnListPtr != 0)
    {
        /* No. So this packet has to wait. We will have to
         * call gld_sched() later to ask GLD to retry.
         */
        
        inst->tx_waiting=1;

        
        return GLD_NORESOURCES;
    }

    /* Traverse forward through the linked list of mblk_t,
     * copying each one to
     * our downfrag buffer.
     */
    if(mp == NULL)
    {
        cmn_err(CE_WARN,"mp is NULL!\n");
        return GLD_FAILURE;
    }
    /*Copy the packet in the mblk_t linked list into the downfrag  */
    dn_fragbuf   = (inst->downfrag_da).addr;
    
    bzero(dn_fragbuf, (inst->downfrag_da).alloc_length);
    
    total_copied = 0;
    bp           = mp;
    for(; bp != NULL; bp = bp->b_cont)
    {
        msg_size = MBLKL(bp);

        if(msg_size >0 )
        {
            if( total_copied + msg_size < (inst->downfrag_da).alloc_length)
            {
                bcopy(bp->b_rptr, dn_fragbuf, msg_size);
                dn_fragbuf   += msg_size;
                total_copied += msg_size;
            }

        }
    }

    the_dpd->down_fraglength = 0x80000000 | total_copied;
    xl_prepare_send(inst);
    
    /* Free the mblk_t linked list */
    freemsg(mp); /* Use mp, not bp. bp was just a scratch variable */
    return GLD_SUCCESS;

}

int xl_cleanup(xl_instance *inst)
{
    /* This function is responsible for cleanup, be it 
     * due to failure in xl_attach, or simply called 
     * as part of xl_detach
     */
     
    uint16_t flags; 
    int gld_unreg_retval; 
    
    
    flags = inst->status_flags;
    
    /* Have to cleanup after ourselves.
     * - free downfrag(s) (currently only 1 upfrag)
     * - free downlist
     * - free upfrag(s) (currently only 1 upfrag)
     * - free uplist
     * - gld_unregister
     * tear down
     * - reschedule_idp
     * - iblk
     * - io_handle
     * - cfg_handle
     * free
     * - *macinfo
     * - *inst
     */
     
    if( flags & XL_FLAG_DOWNFRAG_ALLOC )
    {
        xl_free_downfrag(inst);    
    }
    
    if( flags & XL_FLAG_DOWNLIST_ALLOC )
    {
        xl_free_downlist(inst);        
    }
    
    if( flags & XL_FLAG_UPFRAG_ALLOC )
    {
        xl_free_upfrag(inst);         
    }
    
    if( flags & XL_FLAG_UPLIST_ALLOC )
    {
        xl_free_uplist(inst);             
    }
    
    if( flags & XL_FLAG_GLDREG_ALLOC )
    {
        gld_unreg_retval = gld_unregister(inst->macinfo);
    }
    
    if( flags & XL_FLAG_SINTR_ALLOC )
    {
        ddi_remove_softintr(inst->reschedule_idp);                
    }
    
    if( flags & XL_FLAG_HINTR_ALLOC )
    {
        ddi_remove_intr(inst->devinfo, 0, inst->iblk);                 
    }
    
    if( flags & XL_FLAG_IO_ALLOC )
    {
        ddi_regs_map_free(&inst->io_handle);                 
    }
    
    if( flags & XL_FLAG_PCICFG_ALLOC )
    {
        pci_config_teardown(&inst->cfg_handle);                 
    }
    
    if( flags & XL_FLAG_GLD_ALLOC )
    {
        gld_mac_free(inst->macinfo);
        kmem_free(inst, sizeof(xl_instance) );                 
    }
    
    return gld_unreg_retval;
    
}
/*
 * Standard module entry points.
 */
int
_info(struct modinfo *modinfop)
{
    return (mod_info(&modlinkage, modinfop));
}


int
_init(void)
{
    int status;

    status = mod_install(&modlinkage);

    return (status);
}

int
_fini(void)
{
    int status;

    status = mod_remove(&modlinkage);

    return (status);
}

int
xl_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
    gld_mac_info_t *macinfop;
    xl_instance *this_instance;
    int instance;
    int err;
    caddr_t regs;
    uint16_t command;
    cmn_err(CE_NOTE, "inside xl_attach!");


    /* This is where real work gets done for the first time.
     *
     * There are a number of things we must perform in order to
     * satisfy the GLD layer:
     *
     *  - Map in the registers of our device
     *  - Get the vendor ID and device ID and save it
     *  - Reset/Initialize the network card
     *  - Get the MAC address
     *  - Fill in a macinfo structure
     *  - Register it with gld using gld_register
     *  - Return DDI_SUCCESS
     */

    /* We only support a DDI_ATTACH command
     *
     */
    if(cmd != DDI_ATTACH) 
    {
        return DDI_FAILURE;
    }
    instance = ddi_get_instance(devinfo);

    /* Allocate memory to create an xl_instance structure.
     * This struct will store loads of info about this card we
     * are attaching to.
     * Also initialize macinfop.
     * Cross link devinfo and macinfop and this_instance
     */
    macinfop = gld_mac_alloc(devinfo);
    ddi_set_driver_private(devinfo, (caddr_t)macinfop);

    this_instance = kmem_zalloc(sizeof (xl_instance), KM_SLEEP);
    this_instance->devinfo = devinfo;
    this_instance->macinfo = macinfop;
    macinfop->gldm_private = (caddr_t)this_instance;
    
    /* Set status flags for progress so far */
    this_instance->status_flags |= XL_FLAG_GLD_ALLOC;
    

    /* Map in the registers of our device
     * This entails the following
     *
     * - Getting an handle from pci_config_setup
     * - configuring PCI address space to allow us to read/write
     * - Getting an handle from ddi_regs_map_setup
     *
     */

    /* - First get an handle from pci_config_setup
     *
     */
    err = pci_config_setup(devinfo, &this_instance->cfg_handle);
    if(err != DDI_SUCCESS)
    {
        cmn_err(CE_WARN, "sol_xl -- pci_config_setup() failed");
        goto attach_fail;
    }
    /* Set status flags for progress so far */
    this_instance->status_flags |= XL_FLAG_PCICFG_ALLOC;
    
    /* Get vendor ID, device ID using pci_config_get*
     *
     */

    this_instance->device_id = pci_config_get16(this_instance->cfg_handle,
            PCI_CONF_DEVID);
    this_instance->vendor_id = pci_config_get16(this_instance->cfg_handle,
            PCI_CONF_VENID);
            
    cmn_err(CE_NOTE, "Attaching to vendor_id %4x device_id %4x",
            this_instance->vendor_id,
            this_instance->device_id);
    /* Configure PCI address space to allow us to read/write
     *
     */
    command  = pci_config_get16(this_instance->cfg_handle, PCI_CONF_COMM);
    command |= PCI_COMM_MAE;
    command &= ~(PCI_COMM_ME|PCI_COMM_MEMWR_INVAL);
    command |= PCI_COMM_ME;
    pci_config_put16(this_instance->cfg_handle, PCI_CONF_COMM, command);

    /*
     * Get an handle from ddi_regs_map_setup
     */

    err = ddi_regs_map_setup(devinfo, XL_PCI_OPREGS,&regs,
                              0,0,
                              &xl_reg_accattr,&this_instance->io_handle);

    if( err != DDI_SUCCESS) 
    {
        cmn_err(CE_WARN, "sol_xl -- ddi_regs_map_setup() failed");
        goto attach_fail;
    }
       
    this_instance->io_regs = regs;
    
    /* Set status flags for progress so far */
    this_instance->status_flags |= XL_FLAG_IO_ALLOC;

    /* Register the hardware interrupt */
    err = ddi_add_intr(devinfo, 0, &this_instance->iblk, NULL, gld_intr,
            (caddr_t)macinfop);
    if (err != DDI_SUCCESS) 
    {
        cmn_err(CE_WARN, "sol_xl -- ddi_add_intr() failed");
        goto attach_fail;
    }
    
    /* Set status flags for progress so far */
    this_instance->status_flags |= XL_FLAG_HINTR_ALLOC;
    
    /* Register the soft interrupt */
    err = ddi_add_softintr(devinfo, DDI_SOFTINT_LOW,
                            &this_instance->reschedule_idp, 
                            NULL, NULL, xl_reschedule,
                            (caddr_t)this_instance);
    if (err != DDI_SUCCESS) 
    {
        cmn_err(CE_WARN, "sol_xl -- ddi_add_softintr() failed");
        goto attach_fail;
    }
    
    /* Set status flags for progress so far */
    this_instance->status_flags |= XL_FLAG_SINTR_ALLOC;
    
    /* Reset the chip entirely */
    xl_total_reset(this_instance);

    /* Fill in the functions we have to provide to GLD */
    macinfop->gldm_reset            = xl_gld_reset;
    macinfop->gldm_stop             = xl_gld_stop;
    macinfop->gldm_start            = xl_gld_start;
    macinfop->gldm_set_mac_addr     = xl_gld_set_mac_addr;
    macinfop->gldm_set_multicast    = xl_gld_set_multicast;
    macinfop->gldm_set_promiscuous  = xl_gld_set_promiscuous;
    macinfop->gldm_ioctl            = NULL;
    macinfop->gldm_get_stats        = xl_gld_get_stats;
    macinfop->gldm_intr             = xl_gld_intr;
    macinfop->gldm_send             = xl_gld_send;

    /*
     * Initialize board characteristics needed by the generic layer.
     */
    macinfop->gldm_ident            = xl_gld_ident;
    macinfop->gldm_type             = DL_ETHER;
    macinfop->gldm_minpkt           = 0;    /* no padding required  */
    macinfop->gldm_maxpkt           = ETHERMTU;
    macinfop->gldm_addrlen          = ETHERADDRL;
    macinfop->gldm_saplen           = -2;
    macinfop->gldm_broadcast_addr   = xl_broadcast_addr;
    macinfop->gldm_vendor_addr      = this_instance->mac_addr;
    macinfop->gldm_ppa              = instance;
    macinfop->gldm_devinfo          = devinfo;
    macinfop->gldm_cookie           = this_instance->iblk;

    /* Get the mac address from EEPROM, then set it. */
    xl_getmacaddr(this_instance);
    xl_setmacaddr(this_instance);

    /* Register ourselves with GLD */
    if (gld_register(devinfo, XL_DRIVER_NAME, macinfop) != DDI_SUCCESS)
        goto attach_fail;

    /* Set status flags for progress so far */
    this_instance->status_flags |= XL_FLAG_GLDREG_ALLOC;

    err = xl_alloc_uplist(this_instance);
    if(err != DDI_SUCCESS )
    {
        cmn_err(CE_WARN,"xl_attach--xl_alloc_uplist failed");
        xl_free_uplist(this_instance);
        goto attach_fail;
    }
    
    /* Set status flags for progress so far */
    this_instance->status_flags |= XL_FLAG_UPLIST_ALLOC;
    
    err = xl_alloc_upfrag(this_instance);
    if(err != DDI_SUCCESS )
    {
        cmn_err(CE_WARN,"xl_attach--xl_alloc_upfrag failed");
        xl_free_upfrag(this_instance);
        goto attach_fail;
    }

    /* Set status flags for progress so far */
    this_instance->status_flags |= XL_FLAG_UPFRAG_ALLOC;
    
    err = xl_alloc_downlist(this_instance);
    if(err != DDI_SUCCESS )
    {
        cmn_err(CE_WARN,"xl_attach--xl_alloc_downlist failed");
        xl_free_downlist(this_instance);
        goto attach_fail;
    }
    
    /* Set status flags for progress so far */
    this_instance->status_flags |= XL_FLAG_DOWNLIST_ALLOC;

    err = xl_alloc_downfrag(this_instance);
    if(err != DDI_SUCCESS )
    {
        cmn_err(CE_WARN,"xl_attach--xl_alloc_downfrag failed");
        xl_free_downfrag(this_instance);
        goto attach_fail;
    }
    
    /* Set status flags for progress so far */
    this_instance->status_flags |= XL_FLAG_DOWNFRAG_ALLOC;
    
    cmn_err(CE_NOTE, "Success in sol_xl attach");
    return DDI_SUCCESS;
    
    attach_fail:
        /* Cleanup after ourselves
         *
         */
         (void)xl_cleanup(this_instance);
         return DDI_FAILURE;


}

static int
xl_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
    gld_mac_info_t *macinfo;
    xl_instance *inst;
    
    macinfo = (gld_mac_info_t *)ddi_get_driver_private(devinfo);
    inst = (xl_instance*)(macinfo->gldm_private);
    
    return xl_cleanup(inst);
    
}

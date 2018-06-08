#include <media/v4l2-mem2mem.h>
#include <media/videobuf2-dma-contig.h>

#include "codec_h264.h"
#include "codec_helpers.h"
#include "canvas.h"

#define SIZE_EXT_FW	(SZ_1K * 20)
#define SIZE_WORKSPACE	0x1ee000
#define SIZE_SEI	(SZ_1K * 8)

/* Offset added by the firmware which must be substracted
 * from the workspace paddr
 */
#define DEF_BUF_START_ADDR 0x1000000


/* DOS registers */
#define ASSIST_MBOX1_CLR_REG 0x01d4
#define ASSIST_MBOX1_MASK    0x01d8

#define LMEM_DMA_CTRL 0x0d40

#define PSCALE_CTRL 0x2444

#define MDEC_PIC_DC_CTRL   0x2638
#define ANC0_CANVAS_ADDR   0x2640
#define MDEC_PIC_DC_THRESH 0x26e0

#define AV_SCRATCH_0  0x2700
#define AV_SCRATCH_1  0x2704
#define AV_SCRATCH_2  0x2708
#define AV_SCRATCH_3  0x270c
#define AV_SCRATCH_4  0x2710
#define AV_SCRATCH_5  0x2714
#define AV_SCRATCH_6  0x2718
#define AV_SCRATCH_7  0x271c
#define AV_SCRATCH_8  0x2720
#define AV_SCRATCH_9  0x2724
#define AV_SCRATCH_D  0x2734
#define AV_SCRATCH_F  0x273c
#define AV_SCRATCH_G  0x2740
#define AV_SCRATCH_H  0x2744
#define AV_SCRATCH_I  0x2748
#define AV_SCRATCH_J  0x274c
	#define SEI_DATA_READY BIT(15)

#define POWER_CTL_VLD 0x3020

#define DCAC_DMA_CTRL 0x3848

#define DOS_SW_RESET0 0xfc00

struct codec_h264 {
	/* H.264 decoder requires an extended firmware loaded in contiguous RAM */
	void      *ext_fw_vaddr;
	dma_addr_t ext_fw_paddr;

	/* Buffer for the H.264 Workspace */
	void      *workspace_vaddr;
	dma_addr_t workspace_paddr;
	
	/* Buffer for the H.264 references MV */
	void      *ref_vaddr;
	dma_addr_t ref_paddr;
	u32	   ref_size;

	/* Buffer for parsed SEI data ; > M8 ? */
	void      *sei_vaddr;
	dma_addr_t sei_paddr;

	/* Housekeeping thread for marking buffers to DONE
	 * and recycling them into the hardware
	 */
	struct task_struct *buffers_thread;
};

static int codec_h264_buffers_thread(void *data)
{
	struct vdec_buffer *tmp;
	struct vb2_v4l2_buffer *vbuf;
	unsigned long flags;
	struct vdec_session *sess = data;
	struct vdec_core *core = sess->core;;

	while (!kthread_should_stop()) {
		spin_lock_irqsave(&sess->bufs_spinlock, flags);
		while (!list_empty(&sess->bufs))
		{
			tmp = list_first_entry(&sess->bufs, struct vdec_buffer, list);
			if (tmp->index == -1)
				break;

			vbuf = v4l2_m2m_dst_buf_remove_by_idx(sess->m2m_ctx, tmp->index);
			if (!vbuf) {
				printk("HW buffer ready but we don't have the vb2 buffer !!!\n");
				break;
			}

			vbuf->vb2_buf.planes[0].bytesused = vdec_get_output_size(sess);
			vbuf->vb2_buf.planes[1].bytesused = vdec_get_output_size(sess) / 2;
			vbuf->vb2_buf.timestamp = tmp->timestamp;
			vbuf->sequence = sess->sequence_cap++;
			if (!(vbuf->sequence % 100))
				printk("%d\n", vbuf->sequence);
				
			printk("Buffer %d done\n", tmp->index);

			v4l2_m2m_buf_done(vbuf, VB2_BUF_STATE_DONE);
			list_del(&tmp->list);
			kfree(tmp);
		}
		spin_unlock_irqrestore(&sess->bufs_spinlock, flags);

		mutex_lock(&sess->bufs_recycle_lock);
		while (!list_empty(&sess->bufs_recycle) &&
		      (!readl_relaxed(core->dos_base + AV_SCRATCH_7) ||
		       !readl_relaxed(core->dos_base + AV_SCRATCH_8)))
		{
			tmp = list_first_entry(&sess->bufs_recycle, struct vdec_buffer, list);

			/* Tell the decoder he can recycle this buffer.
			 * AV_SCRATCH_8 serves the same purpose.
			 */
			if (!readl_relaxed(core->dos_base + AV_SCRATCH_7))
				writel_relaxed(tmp->index + 1, core->dos_base + AV_SCRATCH_7);
			else
				writel_relaxed(tmp->index + 1, core->dos_base + AV_SCRATCH_8);
				
			printk("Buffer %d recycled\n", tmp->index);

			list_del(&tmp->list);
			kfree(tmp);

			up(&sess->queue_sema);
		}
		mutex_unlock(&sess->bufs_recycle_lock);

		usleep_range(5000, 10000);
	}

	return 0;
}

static int codec_h264_start(struct vdec_session *sess) {
	u32 workspace_offset;
	struct vdec_core *core = sess->core;
	struct codec_h264 *h264 = sess->priv;

	printk("codec_h264_start\n");

	/* Allocate some memory for the H.264 decoder's state */
	h264->workspace_vaddr = dma_alloc_coherent(core->dev, SIZE_WORKSPACE, &h264->workspace_paddr, GFP_KERNEL);
	if (!h264->workspace_vaddr) {
		printk("Failed to request H.264 Workspace\n");
		return -ENOMEM;
	}
	printk("Allocated Workspace: %08X - %08X\n", h264->workspace_paddr, h264->workspace_paddr + SIZE_WORKSPACE);

	/* Allocate some memory for the H.264 SEI dump */
	h264->sei_vaddr = dma_alloc_coherent(core->dev, SIZE_SEI, &h264->sei_paddr, GFP_KERNEL);
	if (!h264->sei_vaddr) {
		printk("Failed to request H.264 SEI\n");
		return -ENOMEM;
	}
	printk("Allocated SEI: %08X - %08X\n", h264->sei_paddr, h264->sei_paddr + SIZE_SEI);

	while (readl_relaxed(core->dos_base + DCAC_DMA_CTRL) & 0x8000) { }
	while (readl_relaxed(core->dos_base + LMEM_DMA_CTRL) & 0x8000) { }

	/* Taken from old AMLogic code. No idea. */
	writel_relaxed((1<<7) | (1<<6) | (1<<4), core->dos_base + DOS_SW_RESET0);
	writel_relaxed(0, core->dos_base + DOS_SW_RESET0);
	readl_relaxed(core->dos_base + DOS_SW_RESET0);

	writel_relaxed((1<<7) | (1<<6) | (1<<4), core->dos_base + DOS_SW_RESET0);
	writel_relaxed(0, core->dos_base + DOS_SW_RESET0);
	writel_relaxed((1<<9) | (1<<8), core->dos_base + DOS_SW_RESET0);
	writel_relaxed(0, core->dos_base + DOS_SW_RESET0);
	readl_relaxed(core->dos_base + DOS_SW_RESET0);

	writel_relaxed(readl_relaxed(core->dos_base + POWER_CTL_VLD) | (1 << 9) | (1 << 6), core->dos_base + POWER_CTL_VLD);

	writel_relaxed(0, core->dos_base + PSCALE_CTRL);

	writel_relaxed(0, core->dos_base + AV_SCRATCH_0);

	workspace_offset = h264->workspace_paddr - DEF_BUF_START_ADDR;
	writel_relaxed(workspace_offset, core->dos_base + AV_SCRATCH_1);
	writel_relaxed(h264->ext_fw_paddr, core->dos_base + AV_SCRATCH_G);
	writel_relaxed(h264->sei_paddr - workspace_offset, core->dos_base + AV_SCRATCH_I);

	writel_relaxed(0, core->dos_base + AV_SCRATCH_7);
	writel_relaxed(0, core->dos_base + AV_SCRATCH_8);
	writel_relaxed(0, core->dos_base + AV_SCRATCH_9);

	/* Enable "error correction", don't know what it means */
	writel_relaxed((readl_relaxed(core->dos_base + AV_SCRATCH_F) & 0xffffffc3) | (1 << 4), core->dos_base + AV_SCRATCH_F);

	/* Enable IRQ */
	writel_relaxed(1, core->dos_base + ASSIST_MBOX1_CLR_REG);
	writel_relaxed(1, core->dos_base + ASSIST_MBOX1_MASK);

	/* Enable NV21 */
	writel_relaxed(readl_relaxed(core->dos_base + MDEC_PIC_DC_CTRL) | (1 << 17), core->dos_base + MDEC_PIC_DC_CTRL);

	/* ?? */
	writel_relaxed(0x404038aa, core->dos_base + MDEC_PIC_DC_THRESH);
	
	writel_relaxed((1<<12)|(1<<11), core->dos_base + DOS_SW_RESET0);
	writel_relaxed(0, core->dos_base + DOS_SW_RESET0);

	readl_relaxed(core->dos_base + DOS_SW_RESET0);
	
	h264->buffers_thread = kthread_run(codec_h264_buffers_thread, sess, "buffers_done");
	
	return 0;
}

static int codec_h264_stop(struct vdec_session *sess)
{
	struct codec_h264 *h264 = sess->priv;
	struct vdec_core *core = sess->core;

	printk("codec_h264_stop\n");

	kthread_stop(h264->buffers_thread);

	if (h264->ext_fw_vaddr) {
		dma_free_coherent(core->dev, SIZE_EXT_FW, h264->ext_fw_vaddr, h264->ext_fw_paddr);
		h264->ext_fw_vaddr = 0;
	}
	
	if (h264->workspace_vaddr) {
		dma_free_coherent(core->dev, SIZE_WORKSPACE, h264->workspace_vaddr, h264->workspace_paddr);
		h264->workspace_vaddr = 0;
	}
	
	if (h264->ref_vaddr) {
		dma_free_coherent(core->dev, h264->ref_size, h264->ref_vaddr, h264->ref_paddr);
		h264->ref_vaddr = 0;
	}
	
	if (h264->sei_vaddr) {
		dma_free_coherent(core->dev, SIZE_SEI, h264->sei_vaddr, h264->sei_paddr);
		h264->sei_vaddr = 0;
	}

	kfree(h264);
	sess->priv = 0;
	
	return 0;
}

static int codec_h264_load_extended_firmware(struct vdec_session *sess, const u8 *data, u32 len)
{
	struct codec_h264 *h264;
	struct vdec_core *core = sess->core;

	printk("codec_h264_load_extended_firmware\n");
	
	h264 = kzalloc(sizeof(*h264), GFP_KERNEL);
	if (!h264)
		return -ENOMEM;
		
	sess->priv = h264;

	if (len != SIZE_EXT_FW)
		return -EINVAL;
	
	h264->ext_fw_vaddr = dma_alloc_coherent(core->dev, SIZE_EXT_FW, &h264->ext_fw_paddr, GFP_KERNEL);
	if (!h264->ext_fw_vaddr) {
		dev_err(core->dev, "Couldn't allocate memory for H.264 extended firmware\n");
		return -ENOMEM;
	}

	memcpy(h264->ext_fw_vaddr, data, SIZE_EXT_FW);

	return 0;
}

/* Configure the H.264 decoder when the esparser finished parsing
 * the first buffer.
 */
static void codec_h264_set_param(struct vdec_session *sess) {
	u32 max_reference_size;
	u32 parsed_info, mb_width, mb_height, mb_total;
	u32 mb_mv_byte;
	u32 actual_dpb_size = v4l2_m2m_num_dst_bufs_ready(sess->m2m_ctx);
	u32 max_dpb_size = 4;
	struct vdec_core *core = sess->core;
	struct codec_h264 *h264 = sess->priv;

	writel_relaxed(0, core->dos_base + AV_SCRATCH_7);
	writel_relaxed(0, core->dos_base + AV_SCRATCH_8);
	writel_relaxed(0, core->dos_base + AV_SCRATCH_9);

	parsed_info = readl_relaxed(core->dos_base + AV_SCRATCH_1);

	/* Total number of 16x16 macroblocks */
	mb_total = (parsed_info >> 8) & 0xffff;

	/* Size of Motion Vector per macroblock ? */
	mb_mv_byte = (parsed_info & 0x80000000) ? 24 : 96;

	/* Number of macroblocks per line */
	mb_width = parsed_info & 0xff;

	/* Number of macroblock lines */
	mb_height = mb_total / mb_width;

	max_reference_size = (parsed_info >> 24) & 0x7f;

	/* Align to a multiple of 4 macroblocks */
	mb_width = (mb_width + 3) & 0xfffffffc;
	mb_height = (mb_height + 3) & 0xfffffffc;
	mb_total = mb_width * mb_height;

	codec_helper_set_canvases(sess, core->dos_base + ANC0_CANVAS_ADDR);

	if (max_reference_size >= max_dpb_size)
		max_dpb_size = max_reference_size;

	max_reference_size++;

	printk("mb_total = %d; mb_mv_byte = %d; actual_dpb_size = %d; max_dpb_size = %d\n max_reference_size = %d; mb_width = %d; mb_height = %d\n", mb_total, mb_mv_byte, actual_dpb_size, max_dpb_size, max_reference_size, mb_width, mb_height);

	h264->ref_size = mb_total * mb_mv_byte * max_reference_size;
	h264->ref_vaddr = dma_alloc_coherent(core->dev, h264->ref_size, &h264->ref_paddr, GFP_ATOMIC);

	/* Address to store the references' MVs ? */
	writel_relaxed(h264->ref_paddr, core->dos_base + AV_SCRATCH_1);
	printk("Max references buffer size: %d\n", mb_total * mb_mv_byte * max_reference_size);

	/* End of ref MV */
	writel_relaxed(h264->ref_paddr + h264->ref_size, core->dos_base + AV_SCRATCH_4);

	writel_relaxed((max_reference_size << 24) | (actual_dpb_size << 16) | (max_dpb_size << 8), core->dos_base + AV_SCRATCH_0);
}

static irqreturn_t codec_h264_isr(struct vdec_session *sess)
{
	unsigned int cpu_cmd;
	unsigned int buffer_index;
	int i;
	u32 slice_type;
	struct vdec_core *core = sess->core;

	writel_relaxed(1, core->dos_base + ASSIST_MBOX1_CLR_REG);
	cpu_cmd = readl_relaxed(core->dos_base + AV_SCRATCH_0);

	//printk("vdec_isr ; cpu_cmd = %08X!\n", cpu_cmd);

	if ((cpu_cmd & 0xff) == 1) {
		codec_h264_set_param(sess);
	} else if ((cpu_cmd & 0xff) == 2) {
		int error_count, error, num_frame, status, eos = 0;
		error_count = readl_relaxed(core->dos_base + AV_SCRATCH_D);
		num_frame = (cpu_cmd >> 8) & 0xff;
		if (error_count) {
			printk("decoder error(s) happened, count %d\n", error_count);
			writel_relaxed(0, core->dos_base + AV_SCRATCH_D);
		}

		//printk("Decoded %d frames\n", num_frame);

		for (i = 0 ; (i < num_frame) && (!eos) ; i++) {
			slice_type = (readl_relaxed(core->dos_base + AV_SCRATCH_H) >> (i * 4)) & 0xf;
			status = readl_relaxed(core->dos_base + AV_SCRATCH_1 + i*4);
			buffer_index = status & 0x1f;
			error = status & 0x200;

			/* A buffer decode error means it was decoded,
			 * but part of the picture will have artifacts.
			 * Typical reason is a temporarily corrupted bitstream
			 */
			if (error) {
				printk("Buffer %d decode error: %08X\n", buffer_index, error);
			} else {
				//printk("Buffer %d decoded & ready!\n", buffer_index);
			}

			eos = (status >> 15) & 1;
		
			if (eos) {
				printk("Reached EOS!\n");
			}

			/* Fatal error ? */
			if (buffer_index >= 24) {
				printk("buffer_index >= 24 !! (%u)\n", buffer_index);
				continue;
			}

			codec_helper_fill_buf_idx(sess, buffer_index);
		}

		writel_relaxed(0, core->dos_base + AV_SCRATCH_0);
	} else if ((cpu_cmd & 0xff) != 0) {
		printk("Unexpected cpu_cmd: %08X\n", cpu_cmd);
		writel_relaxed(0, core->dos_base + AV_SCRATCH_0);
	}

	/* Decoder has some SEI data for us ; ignore */
	if (readl_relaxed(core->dos_base + AV_SCRATCH_J) & SEI_DATA_READY)
		writel_relaxed(0, core->dos_base + AV_SCRATCH_J);

	return IRQ_HANDLED;
}

struct vdec_codec_ops codec_h264_ops = {
	.start = codec_h264_start,
	.stop = codec_h264_stop,
	.load_extended_firmware = codec_h264_load_extended_firmware,
	.isr = codec_h264_isr,
};


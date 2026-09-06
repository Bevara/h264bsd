/*
 *			GPAC - Multimedia Framework C SDK
 *
 *  This file is part of GPAC / H.264 (ITU-T H.264 | MPEG-4 AVC) decoder filter
 *  built on h264bsd, the baseline-profile decoder extracted from Android's
 *  software AVC stack.
 *
 *  h264bsd covers the Constrained Baseline Profile only: no B pictures, no
 *  CABAC, no interlace, no 8x8 transform. That is a deliberate scope, and the
 *  filter reports a clean error rather than producing garbage when the stream
 *  needs more.
 *
 *  A link in a chain, not a whole-file reader. Whatever produces the AVC pid -
 *  rfnalu for a raw .264, mp4dmx for an MP4 track - has already parsed the SPS,
 *  so the picture size is known at configure time. That matters more than it
 *  looks: the graph is resolved at configure time, and a decoder that only
 *  announces its pixel format later is skipped over by the resolver, which then
 *  hands the raw pid straight to the muxer.
 *
 *  Two details of the library shape the code below:
 *
 *  - it eats Annex-B, while an AVC pid carries length-prefixed NAL units, so
 *    each sample is rewritten with start codes before being fed in.
 *  - pictures come out macroblock-aligned. A 320x180 stream decodes into a
 *    320x192 buffer, so every plane is copied line by line into a packet of the
 *    cropped size rather than memcpy'd in one go. The layout is planar I420,
 *    which is GF_PIXEL_YUV as-is.
 */

#include <gpac/filters.h>

#include "h264bsd_decoder.h"
#include "h264bsd_util.h"

typedef struct
{
	storage_t decoder;
	GF_FilterPid *ipid;
	GF_FilterPid *opid;
	/* cropped size, i.e. what the stream actually displays */
	u32 width, height, out_size;
	/* macroblock-aligned size, i.e. what h264bsd writes into */
	u32 dec_width, dec_height;
	/* bytes of the length prefix in front of each NAL, from the avcC */
	u32 nalu_size_len;
	/* Annex-B scratch, grown as needed and reused across samples */
	u8 *annexb;
	u32 annexb_alloc;
	Bool hdrs_done;
} GF_H264bsdDecCtx;

static const u8 h264bsd_start_code[4] = {0, 0, 0, 1};

/* h264bsd hands out one buffer holding the three planes at the aligned size;
 * copy the visible part of each into the packet. */
static void h264bsd_copy_cropped(GF_H264bsdDecCtx *ctx, const u8 *pic, u8 *dst)
{
	u32 i;
	u32 dw = ctx->dec_width, dh = ctx->dec_height;
	u32 w = ctx->width, h = ctx->height;
	const u8 *src_y = pic;
	const u8 *src_cb = pic + dw * dh;
	const u8 *src_cr = src_cb + (dw / 2) * (dh / 2);
	u8 *dst_y = dst;
	u8 *dst_cb = dst + w * h;
	u8 *dst_cr = dst_cb + (w / 2) * (h / 2);

	for (i = 0; i < h; i++)
		memcpy(dst_y + i * w, src_y + i * dw, w);
	for (i = 0; i < h / 2; i++)
	{
		memcpy(dst_cb + i * (w / 2), src_cb + i * (dw / 2), w / 2);
		memcpy(dst_cr + i * (w / 2), src_cr + i * (dw / 2), w / 2);
	}
}

/* The size announced on the pid is the display size, but h264bsd writes into a
 * macroblock-aligned buffer; read both back from the decoder once the sequence
 * header has been seen so the crop is done against the real layout. */
static void h264bsd_update_layout(GF_H264bsdDecCtx *ctx)
{
	u32 crop_flag, left, top, width, height;

	ctx->dec_width = h264bsdPicWidth(&ctx->decoder) * 16;
	ctx->dec_height = h264bsdPicHeight(&ctx->decoder) * 16;

	h264bsdCroppingParams(&ctx->decoder, &crop_flag, &left, &width, &top, &height);
	if (!crop_flag)
	{
		width = ctx->dec_width;
		height = ctx->dec_height;
	}
	if ((width != ctx->width) || (height != ctx->height))
	{
		ctx->width = width;
		ctx->height = height;
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(ctx->width));
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(ctx->height));
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STRIDE, &PROP_UINT(ctx->width));
	}
	ctx->out_size = ctx->width * ctx->height * 3 / 2;
	ctx->hdrs_done = GF_TRUE;
}

/* Emit every picture the decoder has ready. h264bsd is initialized without
 * output reordering, so for a baseline stream this is one picture per sample
 * and the input timestamps carry over unchanged. */
static void h264bsd_send_pictures(GF_H264bsdDecCtx *ctx, GF_FilterPacket *src_pck)
{
	u32 pic_id, is_idr, nb_err;
	u8 *pic;

	if (!ctx->hdrs_done)
		return;

	while ((pic = h264bsdNextOutputPicture(&ctx->decoder, &pic_id, &is_idr, &nb_err)) != NULL)
	{
		u8 *output;
		GF_FilterPacket *dst_pck = gf_filter_pck_new_alloc(ctx->opid, ctx->out_size, &output);
		if (!dst_pck)
			return;

		h264bsd_copy_cropped(ctx, pic, output);

		if (src_pck)
		{
			gf_filter_pck_merge_properties(src_pck, dst_pck);
			gf_filter_pck_set_cts(dst_pck, gf_filter_pck_get_cts(src_pck));
			gf_filter_pck_set_dts(dst_pck, gf_filter_pck_get_cts(src_pck));
		}
		gf_filter_pck_set_sap(dst_pck, is_idr ? GF_FILTER_SAP_1 : GF_FILTER_SAP_NONE);
		gf_filter_pck_send(dst_pck);
	}
}

static GF_Err h264bsd_feed(GF_H264bsdDecCtx *ctx, const u8 *data, u32 size, GF_FilterPacket *src_pck)
{
	u32 offset = 0;
	/* h264bsd answers HDRS_RDY without consuming anything, meaning "I have
	 * activated a new sequence header, now call me again on the same bytes".
	 * Treating a zero-byte return as end of data drops the very first slice,
	 * and every picture after it then fails to reference it. So allow one
	 * no-progress call per position, and only give up on the second. */
	s64 stalled_at = -1;

	while (offset < size)
	{
		u32 read = 0;
		u32 res = h264bsdDecode(&ctx->decoder, (u8 *)data + offset, size - offset, 0, &read);

		switch (res)
		{
		case H264BSD_HDRS_RDY:
			h264bsd_update_layout(ctx);
			break;
		case H264BSD_PIC_RDY:
			h264bsd_send_pictures(ctx, src_pck);
			break;
		case H264BSD_MEMALLOC_ERROR:
			return GF_OUT_OF_MEM;
		case H264BSD_PARAM_SET_ERROR:
			/* the usual cause is a stream past Constrained Baseline: h264bsd
			 * rejects the parameter set rather than mis-decoding it */
			GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC,
			       ("[h264bsd] unsupported parameter set - h264bsd only decodes the Constrained Baseline Profile\n"));
			return GF_NOT_SUPPORTED;
		default:
			break;
		}

		if (!read)
		{
			if (stalled_at == (s64)offset)
				break;
			stalled_at = (s64)offset;
			continue;
		}
		stalled_at = -1;
		offset += read;
	}
	return GF_OK;
}

/* Read the parameter sets out of an avcC and hand them to the decoder as
 * Annex-B. Parsed here rather than through gf_odf_avc_cfg_read: the layout is
 * a handful of bytes and this keeps the module's imports to the filter API. */
static GF_Err h264bsd_send_dsi(GF_H264bsdDecCtx *ctx, const u8 *dsi, u32 dsi_size)
{
	u32 i, count, pos = 5;
	GF_Err e;

	if (dsi_size < 7)
		return GF_NON_COMPLIANT_BITSTREAM;

	ctx->nalu_size_len = (dsi[4] & 0x03) + 1;

	/* SPS array, then PPS array, both as u8 count followed by u16-length NALs */
	count = dsi[pos++] & 0x1F;
	for (i = 0; i < 2; i++)
	{
		while (count--)
		{
			u32 nal_size;
			if (pos + 2 > dsi_size)
				return GF_NON_COMPLIANT_BITSTREAM;
			nal_size = ((u32)dsi[pos] << 8) | dsi[pos + 1];
			pos += 2;
			if (pos + nal_size > dsi_size)
				return GF_NON_COMPLIANT_BITSTREAM;

			{
				u8 *buf = gf_malloc(nal_size + 4);
				if (!buf)
					return GF_OUT_OF_MEM;
				memcpy(buf, h264bsd_start_code, 4);
				memcpy(buf + 4, dsi + pos, nal_size);
				e = h264bsd_feed(ctx, buf, nal_size + 4, NULL);
				gf_free(buf);
				if (e)
					return e;
			}
			pos += nal_size;
		}
		if (i == 0)
		{
			if (pos >= dsi_size)
				break;
			count = dsi[pos++];
		}
	}
	return GF_OK;
}

static GF_Err h264bsd_configure_pid(GF_Filter *filter, GF_FilterPid *pid, Bool is_remove)
{
	const GF_PropertyValue *p;
	GF_H264bsdDecCtx *ctx = gf_filter_get_udta(filter);

	if (is_remove)
	{
		if (ctx->opid)
		{
			gf_filter_pid_remove(ctx->opid);
			ctx->opid = NULL;
		}
		ctx->ipid = NULL;
		return GF_OK;
	}
	if (!gf_filter_pid_check_caps(pid))
		return GF_NOT_SUPPORTED;

	p = gf_filter_pid_get_property(pid, GF_PROP_PID_CODECID);
	if (!p || (p->value.uint != GF_CODECID_AVC))
		return GF_NOT_SUPPORTED;

	ctx->ipid = pid;
	gf_filter_pid_set_framing_mode(pid, GF_TRUE);

	if (!ctx->opid)
		ctx->opid = gf_filter_pid_new(filter);

	/* The upstream parser already knows the picture size; announcing it now is
	 * what lets the resolver see a complete raw video pid and put an encoder
	 * behind us instead of routing us straight into a muxer. */
	p = gf_filter_pid_get_property(pid, GF_PROP_PID_WIDTH);
	if (p)
		ctx->width = p->value.uint;
	p = gf_filter_pid_get_property(pid, GF_PROP_PID_HEIGHT);
	if (p)
		ctx->height = p->value.uint;
	if (!ctx->width || !ctx->height)
		return GF_NOT_SUPPORTED;
	ctx->out_size = ctx->width * ctx->height * 3 / 2;

	gf_filter_pid_copy_properties(ctx->opid, ctx->ipid);
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STREAM_TYPE, &PROP_UINT(GF_STREAM_VISUAL));
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CODECID, &PROP_UINT(GF_CODECID_RAW));
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(ctx->width));
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(ctx->height));
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STRIDE, &PROP_UINT(ctx->width));
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PIXFMT, &PROP_UINT(GF_PIXEL_YUV));
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_DECODER_CONFIG, NULL);

	/* default for a stream handed over without an avcC: Annex-B start codes */
	ctx->nalu_size_len = 0;
	p = gf_filter_pid_get_property(pid, GF_PROP_PID_DECODER_CONFIG);
	if (p && p->value.data.ptr && p->value.data.size)
	{
		GF_Err e = h264bsd_send_dsi(ctx, p->value.data.ptr, p->value.data.size);
		if (e)
			return e;
	}

	return GF_OK;
}

static GF_Err h264bsd_process(GF_Filter *filter)
{
	const u8 *data;
	u32 size, pos = 0, out_pos = 0, needed;
	GF_Err e;
	GF_FilterPacket *pck;
	GF_H264bsdDecCtx *ctx = (GF_H264bsdDecCtx *)gf_filter_get_udta(filter);

	pck = gf_filter_pid_get_packet(ctx->ipid);
	if (!pck)
	{
		if (gf_filter_pid_is_eos(ctx->ipid))
		{
			h264bsdFlushBuffer(&ctx->decoder);
			h264bsd_send_pictures(ctx, NULL);
			gf_filter_pid_set_eos(ctx->opid);
			return GF_EOS;
		}
		return GF_OK;
	}

	data = gf_filter_pck_get_data(pck, &size);
	if (!data || !size)
	{
		gf_filter_pid_drop_packet(ctx->ipid);
		return GF_OK;
	}

	/* already Annex-B, feed it through untouched */
	if (!ctx->nalu_size_len)
	{
		e = h264bsd_feed(ctx, data, size, pck);
		gf_filter_pid_drop_packet(ctx->ipid);
		return e;
	}

	/* Each start code is 4 bytes where the length prefix was nalu_size_len, so
	 * the rewritten sample is at most one byte per NAL longer; sizing for the
	 * worst case (every NAL one byte long) keeps this to a single allocation. */
	needed = size + 4 * (size / (ctx->nalu_size_len + 1) + 1);
	if (needed > ctx->annexb_alloc)
	{
		ctx->annexb = gf_realloc(ctx->annexb, needed);
		if (!ctx->annexb)
		{
			ctx->annexb_alloc = 0;
			gf_filter_pid_drop_packet(ctx->ipid);
			return GF_OUT_OF_MEM;
		}
		ctx->annexb_alloc = needed;
	}

	while (pos + ctx->nalu_size_len <= size)
	{
		u32 i, nal_size = 0;
		for (i = 0; i < ctx->nalu_size_len; i++)
			nal_size = (nal_size << 8) | data[pos + i];
		pos += ctx->nalu_size_len;

		if (!nal_size || (pos + nal_size > size))
			break;

		memcpy(ctx->annexb + out_pos, h264bsd_start_code, 4);
		out_pos += 4;
		memcpy(ctx->annexb + out_pos, data + pos, nal_size);
		out_pos += nal_size;
		pos += nal_size;
	}

	e = h264bsd_feed(ctx, ctx->annexb, out_pos, pck);
	gf_filter_pid_drop_packet(ctx->ipid);
	return e;
}

static GF_Err h264bsd_initialize(GF_Filter *filter)
{
	GF_H264bsdDecCtx *ctx = gf_filter_get_udta(filter);

	/* no output reordering: baseline never needs it, and it makes the mapping
	 * from input sample to output picture one to one */
	if (h264bsdInit(&ctx->decoder, HANTRO_TRUE) != HANTRO_OK)
	{
		GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[h264bsd] failed to initialize decoder\n"));
		return GF_IO_ERR;
	}
	return GF_OK;
}

static void h264bsd_finalize(GF_Filter *filter)
{
	GF_H264bsdDecCtx *ctx = gf_filter_get_udta(filter);
	h264bsdShutdown(&ctx->decoder);
	if (ctx->annexb)
		gf_free(ctx->annexb);
}

static const GF_FilterCapability h264bsdCaps[] =
	{
		CAP_UINT(GF_CAPS_INPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
		CAP_UINT(GF_CAPS_INPUT, GF_PROP_PID_CODECID, GF_CODECID_AVC),
		CAP_BOOL(GF_CAPS_INPUT_EXCLUDED, GF_PROP_PID_UNFRAMED, GF_TRUE),
		CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
		CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_CODECID, GF_CODECID_RAW)};

GF_FilterRegister h264bsdRegister = {
	.name = "h264bsd",
	GF_FS_SET_DESCRIPTION("H.264 Constrained Baseline decoder")
		GF_FS_SET_HELP("This filter decodes ITU-T H.264 | MPEG-4 AVC of the Constrained Baseline Profile through the h264bsd library. It takes a framed AVC pid, as produced by rfnalu from a raw .264 or by mp4dmx from an MP4 track. B pictures, CABAC and the 8x8 transform are outside that profile and are refused rather than mis-decoded.")
			.private_size = sizeof(GF_H264bsdDecCtx),
	.priority = 1,
	SETCAPS(h264bsdCaps),
	.initialize = h264bsd_initialize,
	.finalize = h264bsd_finalize,
	.configure_pid = h264bsd_configure_pid,
	.process = h264bsd_process,
};

const GF_FilterRegister *EMSCRIPTEN_KEEPALIVE h264bsd_register(GF_FilterSession *session)
{
	return &h264bsdRegister;
}

#include "filter_register.h"
__attribute__((constructor))
void register_h264bsd(void)
{
	gf_filter_auto_register("h264bsd", h264bsd_register);
}

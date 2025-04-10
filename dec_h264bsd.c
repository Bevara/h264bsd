/*
 *			GPAC - Multimedia Framework C SDK
 *
 *			Authors: Jean Le Feuvre
 *			Copyright (c) Telecom ParisTech 2000-2021
 *					All rights reserved
 *
 *  This file is part of GPAC / XIPH Theora decoder filter
 *
 *  GPAC is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  GPAC is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */


#include <gpac/filters.h>

#include "h264bsd_decoder.h"
#include "h264bsd_util.h"


typedef struct
{
  storage_t decoder;
  GF_FilterPid *ipid;
  GF_FilterPid *opid;
  u8 *byte_stream;
  u32 byte_stream_size;
  u32 width, height, out_size;
  u8 *nal_store;
	u32 nal_store_size, nal_store_alloc;
} GF_H264bsdDecCtx;

static GF_Err h264bsd_configure_pid(GF_Filter *filter, GF_FilterPid *pid, Bool is_remove)
{

  GF_H264bsdDecCtx *ctx = gf_filter_get_udta(filter);

	if (is_remove) {
		if (ctx->opid) {
			gf_filter_pid_remove(ctx->opid);
			ctx->opid = NULL;
		}
		ctx->ipid = NULL;
		return GF_OK;
	}

  GF_FilterEvent fevt;


	ctx->ipid = pid;

    				//we work with full file only, send a play event on source to indicate that
            GF_FEVT_INIT(fevt, GF_FEVT_PLAY, pid);
            fevt.play.start_range = 0;
            fevt.base.on_pid = ctx->ipid;
            fevt.play.full_file_only = GF_TRUE;
            gf_filter_pid_send_event(ctx->ipid, &fevt);

	if (!ctx->opid) {


		//ctx->opid = gf_filter_pid_new(filter);

	}
	//copy properties at init or reconfig
	gf_filter_pid_copy_properties(ctx->opid, ctx->ipid);
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CODECID, &PROP_UINT(GF_CODECID_RAW) );

	return GF_OK;
}

static GF_Err h264bsd_process(GF_Filter *filter)
{
  u8 *data_dst;
	u8 *data_src;
	u32 size;
	u8 *buffer;
  u8* pic;
  u32 readBytes = 0;
  u32 consumed = 0;
  u32 picId, isIdrPic, numErrMbs;
  u32 top, left, width, height, croppingFlag;


	GF_FilterPacket *pck_dst;
	GF_H264bsdDecCtx *ctx = (GF_H264bsdDecCtx *) gf_filter_get_udta(filter);

	GF_FilterPacket *pck = gf_filter_pid_get_packet(ctx->ipid);
	if (!pck)
    {
        if (gf_filter_pid_is_eos(ctx->ipid))
        {
            gf_filter_pid_set_eos(ctx->opid);
            return GF_EOS;
        }
        return GF_OK;
    }

	data_src = gf_filter_pck_get_data(pck, &size);
	if (!data_src)
    {
        gf_filter_pid_drop_packet(ctx->ipid);
        return GF_IO_ERR;
  }
  int len = size;
  u32 cpt = 0;
  while (len > 0) {
    len -= readBytes;
    data_src += readBytes;
    u32 res = h264bsdDecode(&ctx->decoder, data_src, len, 0, &readBytes);
    cpt++;

    switch (res) {
      case H264BSD_PIC_RDY:
        pic = h264bsdNextOutputPicture(&ctx->decoder, &picId, &isIdrPic, &numErrMbs);
        //++numPics;
        //if (outputPath) savePic(pic, width, height, numPics);
        //if (comparePath) totalErrors += comparePics(pic, width, height, numPics);
        break;
      case H264BSD_HDRS_RDY:
        h264bsdCroppingParams(&ctx->decoder, &croppingFlag, &left, &width, &top, &height);
        if (!croppingFlag) {
          width = h264bsdPicWidth(&ctx->decoder) * 16;
          height = h264bsdPicHeight(&ctx->decoder) * 16;
        }

        ctx-> width = width;
        ctx-> height = height;
        gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(ctx-> width) );
        gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(ctx-> height) );
        gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STRIDE, &PROP_UINT(ctx-> width) );
        gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PIXFMT, &PROP_UINT(GF_PIXEL_YUV) );
        ctx->out_size = ctx-> width * ctx-> height  * 3 / 2;
        break;
      case H264BSD_RDY:
        break;
      case H264BSD_ERROR:
        break;
      case H264BSD_PARAM_SET_ERROR:
        break;
    }
  }
	gf_filter_pid_drop_packet(ctx->ipid);

	return GF_OK;
}

static GF_Err h264bsd_initialize(GF_Filter *filter)
{
  u32 status;
  GF_H264bsdDecCtx *ctx = gf_filter_get_udta(filter);

  status = h264bsdInit(&ctx->decoder, HANTRO_FALSE);

  if (status != HANTRO_OK) {
    fprintf(stderr, "h264bsdInit failed\n");
    exit(1);
  }

    ctx->byte_stream_size = 0;
    ctx->byte_stream = NULL;

	return GF_OK;
}
static void h264bsd_finalize(GF_Filter *filter)
{
	GF_H264bsdDecCtx *ctx = gf_filter_get_udta(filter);
  h264bsdShutdown(&ctx->decoder);

  if (ctx->byte_stream)
      gf_free(ctx->byte_stream);

}

static const GF_FilterCapability h264bsdCaps[] =
{
  CAP_UINT(GF_CAPS_INPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_FILE),
	CAP_STRING(GF_CAPS_INPUT, GF_PROP_PID_FILE_EXT, "264|h264|26l|h26l|avc|svc|mvc|hevc|hvc|265|h265|lhvc|shvc|mhvc|266|h266|vvc|lvvc"),
	CAP_STRING(GF_CAPS_INPUT, GF_PROP_PID_MIME, "video/avc|video/h264|video/svc|video/mvc|video/hevc|video/lhvc|video/shvc|video/mhvc|video/vvc"),

  //CAP_UINT(GF_CAPS_INPUT,GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
  //CAP_UINT(GF_CAPS_INPUT,GF_PROP_PID_CODECID, GF_CODECID_AVC),

  CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
	CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_CODECID, GF_CODECID_RAW)
};

GF_FilterRegister h264bsdRegister = {
	.name = "h264bsd",
	GF_FS_SET_DESCRIPTION("H264 decoder")
	GF_FS_SET_HELP("This filter decodes H264 CBP streams through h264 bsd library.")
	.private_size = sizeof(GF_H264bsdDecCtx),
	.priority = 1,
	SETCAPS(h264bsdCaps),
	.initialize = h264bsd_initialize,
	.finalize = h264bsd_finalize,
	.configure_pid = h264bsd_configure_pid,
	.process = h264bsd_process,
};


const GF_FilterRegister * EMSCRIPTEN_KEEPALIVE dynCall_h264bsd_register(GF_FilterSession *session)
{
	return &h264bsdRegister;
}


/*
 * include/uapi/linux/if_flow.h - Flow table interface for Switch devices
 * Copyright (c) 2014 John Fastabend <john.r.fastabend@intel.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Author: John Fastabend <john.r.fastabend@intel.com>
 */

/* Netlink description:
 *
 * Table definition used to describe running tables. The following
 * describes the netlink format used by the flow API.
 *
 * Flow table definitions used to define tables.
 *
 * [NFL_TABLE_IDENTIFIER_TYPE]
 * [NFL_TABLE_IDENTIFIER]
 * [NFL_TABLE_TABLES]
 *     [NFL_TABLE]
 *	 [NFL_TABLE_ATTR_NAME]
 *	 [NFL_TABLE_ATTR_UID]
 *	 [NFL_TABLE_ATTR_SOURCE]
 *	 [NFL_TABLE_ATTR_APPLY]
 *	 [NFL_TABLE_ATTR_SIZE]
 *	 [NFL_TABLE_ATTR_MATCHES]
 *	   [NFL_FIELD_REF]
 *	     [NFL_FIELD_REF_INSTANCE]
 *	     [NFL_FIELD_REF_HEADER]
 *	     [NFL_FIELD_REF_FIELD]
 *	     [NFL_FIELD_REF_MASK]
 *	     [NFL_FIELD_REF_TYPE]
 *	   [...]
 *	 [NFL_TABLE_ATTR_ACTIONS]
 *	     [NFL_ACTION_ATTR_UID]
 *	     [...]
 *     [NFL_TABLE]
 *       [...]
 *
 * Header definitions used to define headers with user friendly
 * names.
 *
 * [NFL_TABLE_HEADERS]
 *   [NFL_HEADER]
 *	[NFL_HEADER_ATTR_NAME]
 *	[NFL_HEADER_ATTR_UID]
 *	[NFL_HEADER_ATTR_FIELDS]
 *	  [NFL_HEADER_ATTR_FIELD]
 *	    [NFL_FIELD_ATTR_NAME]
 *	    [NFL_FIELD_ATTR_UID]
 *	    [NFL_FIELD_ATTR_BITWIDTH]
 *	  [NFL_HEADER_ATTR_FIELD]
 *	    [...]
 *	  [...]
 *   [NFL_HEADER]
 *      [...]
 *   [...]
 *
 * Action definitions supported by tables
 *
 * [NFL_TABLE_ACTIONS]
 *   [NFL_TABLE_ATTR_ACTIONS]
 *	[NFL_ACTION]
 *	  [NFL_ACTION_ATTR_NAME]
 *	  [NFL_ACTION_ATTR_UID]
 *	  [NFL_ACTION_ATTR_SIGNATURE]
 *		 [NFL_ACTION_ARG]
 *			[NFL_ACTION_ARG_NAME]
 *			[NFL_ACTION_ARG_TYPE]
 *               [...]
 *	[NFL_ACTION]
 *	     [...]
 *
 * Then two get definitions for the headers graph and the table graph
 * The header graph gives an encoded graph to describe how the device
 * parses the headers. Use this to learn if a specific protocol is
 * supported in the current device configuration. The table graph
 * reports how tables are traversed by packets.
 *
 * Get Headers Graph <Request> only requires msg preamble.
 *
 * Get Headers Graph <Reply> description
 *
 * [NFL_HEADER_GRAPH]
 *   [NFL_HEADER_GRAPH_NODE]
 *	[NFL_HEADER_NODE_NAME]
 *	[NFL_HEADER_NODE_HDRS]
 *	    [NFL_HEADER_NODE_HDRS_VALUE]
 *	    [...]
 *	[NFL_HEADER_NODE_JUMP]]
 *	  [NFL_JUMP_ENTRY]
 *	    [NFL_FIELD_REF_NEXT_NODE]
 *	    [NFL_FIELD_REF_INSTANCE]
 *	    [NFL_FIELD_REF_HEADER]
 *	    [NFL_FIELD_REF_FIELD]
 *	    [NFL_FIELD_REF_MASK]
 *	    [NFL_FIELD_REF_TYPE]
 *	    [NFL_FIELD_REF_VALUE]
 *	    [NFL_FIELD_REF_MASK]
 *	  [...]
 *   [NFL_HEADER_GRAPH_NODE]
 *	[
 *
 * Get Table Graph <Request> only requires msg preamble.
 *
 * Get Table Graph <Reply> description
 *
 * [NFL_TABLE_GRAPH]
 *   [NFL_TABLE_GRAPH_NODE]
 *	[NFL_TABLE_GRAPH_NODE_UID]
 *	[NFL_TABLE_GRAPH_NODE_JUMP]
 *	  [NFL_JUMP_ENTRY]
 *	    [NFL_FIELD_REF_NEXT_NODE]
 *	    [NFL_FIELD_REF_INSTANCE]
 *	    [NFL_FIELD_REF_HEADER]
 *	    [NFL_FIELD_REF_FIELD]
 *	    [NFL_FIELD_REF_MASK]
 *	    [NFL_FIELD_REF_TYPE]
 *	    [NFL_FIELD_REF_VALUE]
 *	    [NFL_FIELD_REF_MASK]
 *	  [...]
 *   [NFL_TABLE_GRAPH_NODE]
 *	[..]
 */

#ifndef _UAPI_LINUX_IF_FLOW
#define _UAPI_LINUX_IF_FLOW

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/if.h>

enum {
	NFL_FIELD_UNSPEC,
	NFL_FIELD,
	__NFL_FIELD_MAX,
};

#define NFL_FIELD_MAX (__NFL_FIELD_MAX - 1)

enum {
	NFL_FIELD_ATTR_UNSPEC,
	NFL_FIELD_ATTR_NAME,
	NFL_FIELD_ATTR_UID,
	NFL_FIELD_ATTR_BITWIDTH,
	__NFL_FIELD_ATTR_MAX,
};

#define NFL_FIELD_ATTR_MAX (__NFL_FIELD_ATTR_MAX - 1)

enum {
	NFL_HEADER_UNSPEC,
	NFL_HEADER,
	__NFL_HEADER_MAX,
};

#define NFL_HEADER_MAX (__NFL_HEADER_MAX - 1)

enum {
	NFL_HEADER_ATTR_UNSPEC,
	NFL_HEADER_ATTR_NAME,
	NFL_HEADER_ATTR_UID,
	NFL_HEADER_ATTR_FIELDS,
	__NFL_HEADER_ATTR_MAX,
};

#define NFL_HEADER_ATTR_MAX (__NFL_HEADER_ATTR_MAX - 1)

enum {
	NFL_MASK_TYPE_UNSPEC,
	NFL_MASK_TYPE_EXACT,
	NFL_MASK_TYPE_LPM,
	NFL_MASK_TYPE_MASK,
};

enum {
	NFL_FIELD_REF_UNSPEC,
	NFL_FIELD_REF_NEXT_NODE,
	NFL_FIELD_REF_INSTANCE,
	NFL_FIELD_REF_HEADER,
	NFL_FIELD_REF_FIELD,
	NFL_FIELD_REF_MASK_TYPE,
	NFL_FIELD_REF_TYPE,
	NFL_FIELD_REF_VALUE,
	NFL_FIELD_REF_MASK,
	__NFL_FIELD_REF_MAX,
};

#define NFL_FIELD_REF_MAX (__NFL_FIELD_REF_MAX - 1)

enum {
	NFL_FIELD_REFS_UNSPEC,
	NFL_FIELD_REF,
	__NFL_FIELD_REFS_MAX,
};

#define NFL_FIELD_REFS_MAX (__NFL_FIELD_REFS_MAX - 1)

enum {
	NFL_FIELD_REF_ATTR_TYPE_UNSPEC,
	NFL_FIELD_REF_ATTR_TYPE_U8,
	NFL_FIELD_REF_ATTR_TYPE_U16,
	NFL_FIELD_REF_ATTR_TYPE_U32,
	NFL_FIELD_REF_ATTR_TYPE_U64,
};

enum net_flow_action_arg_type {
	NFL_ACTION_ARG_TYPE_NULL,
	NFL_ACTION_ARG_TYPE_U8,
	NFL_ACTION_ARG_TYPE_U16,
	NFL_ACTION_ARG_TYPE_U32,
	NFL_ACTION_ARG_TYPE_U64,
	__NFL_ACTION_ARG_TYPE_VAL_MAX,
};

enum {
	NFL_ACTION_ARG_UNSPEC,
	NFL_ACTION_ARG_NAME,
	NFL_ACTION_ARG_TYPE,
	NFL_ACTION_ARG_VALUE,
	__NFL_ACTION_ARG_MAX,
};

#define NFL_ACTION_ARG_MAX (__NFL_ACTION_ARG_MAX - 1)

enum {
	NFL_ACTION_ARGS_UNSPEC,
	NFL_ACTION_ARG,
	__NFL_ACTION_ARGS_MAX,
};

#define NFL_ACTION_ARGS_MAX (__NFL_ACTION_ARGS_MAX - 1)

enum {
	NFL_ACTION_UNSPEC,
	NFL_ACTION,
	__NFL_ACTION_MAX,
};

#define NFL_ACTION_MAX (__NFL_ACTION_MAX - 1)

enum {
	NFL_ACTION_ATTR_UNSPEC,
	NFL_ACTION_ATTR_NAME,
	NFL_ACTION_ATTR_UID,
	NFL_ACTION_ATTR_SIGNATURE,
	__NFL_ACTION_ATTR_MAX,
};

#define NFL_ACTION_ATTR_MAX (__NFL_ACTION_ATTR_MAX - 1)

enum {
	NFL_ACTION_SET_UNSPEC,
	NFL_ACTION_SET_ACTIONS,
	__NFL_ACTION_SET_MAX,
};

#define NFL_ACTION_SET_MAX (__NFL_ACTION_SET_MAX - 1)

enum {
	NFL_TABLE_UNSPEC,
	NFL_TABLE,
	__NFL_TABLE_MAX,
};

#define NFL_TABLE_MAX (__NFL_TABLE_MAX - 1)

enum {
	NFL_TABLE_ATTR_UNSPEC,
	NFL_TABLE_ATTR_NAME,
	NFL_TABLE_ATTR_UID,
	NFL_TABLE_ATTR_SOURCE,
	NFL_TABLE_ATTR_APPLY,
	NFL_TABLE_ATTR_SIZE,
	NFL_TABLE_ATTR_MATCHES,
	NFL_TABLE_ATTR_ACTIONS,
	__NFL_TABLE_ATTR_MAX,
};

#define NFL_TABLE_ATTR_MAX (__NFL_TABLE_ATTR_MAX - 1)

#define NFL_JUMP_TABLE_DONE 0
enum {
	NFL_JUMP_ENTRY_UNSPEC,
	NFL_JUMP_ENTRY,
	__NFL_JUMP_ENTRY_MAX,
};

enum {
	NFL_HEADER_NODE_HDRS_UNSPEC,
	NFL_HEADER_NODE_HDRS_VALUE,
	__NFL_HEADER_NODE_HDRS_MAX,
};

#define NFL_HEADER_NODE_HDRS_MAX (__NFL_HEADER_NODE_HDRS_MAX - 1)

enum {
	NFL_HEADER_NODE_UNSPEC,
	NFL_HEADER_NODE_NAME,
	NFL_HEADER_NODE_UID,
	NFL_HEADER_NODE_HDRS,
	NFL_HEADER_NODE_JUMP,
	__NFL_HEADER_NODE_MAX,
};

#define NFL_HEADER_NODE_MAX (__NFL_HEADER_NODE_MAX - 1)

enum {
	NFL_HEADER_GRAPH_UNSPEC,
	NFL_HEADER_GRAPH_NODE,
	__NFL_HEADER_GRAPH_MAX,
};

#define NFL_HEADER_GRAPH_MAX (__NFL_HEADER_GRAPH_MAX - 1)

#define	NFL_TABLE_EGRESS_ROOT 1
#define	NFL_TABLE_INGRESS_ROOT 2

enum {
	NFL_TABLE_GRAPH_NODE_UNSPEC,
	NFL_TABLE_GRAPH_NODE_UID,
	NFL_TABLE_GRAPH_NODE_FLAGS,
	NFL_TABLE_GRAPH_NODE_JUMP,
	__NFL_TABLE_GRAPH_NODE_MAX,
};

#define NFL_TABLE_GRAPH_NODE_MAX (__NFL_TABLE_GRAPH_NODE_MAX - 1)

enum {
	NFL_TABLE_GRAPH_UNSPEC,
	NFL_TABLE_GRAPH_NODE,
	__NFL_TABLE_GRAPH_MAX,
};

#define NFL_TABLE_GRAPH_MAX (__NFL_TABLE_GRAPH_MAX - 1)

enum {
	NFL_NFL_UNSPEC,
	NFL_FLOW,
	__NFL_NFL_MAX,
};

#define NFL_NFL_MAX (__NFL_NFL_MAX - 1)

enum {
	NFL_IDENTIFIER_UNSPEC,
	NFL_IDENTIFIER_IFINDEX, /* net_device ifindex */
};

enum {
	NFL_UNSPEC,
	NFL_IDENTIFIER_TYPE,
	NFL_IDENTIFIER,

	NFL_TABLES,
	NFL_HEADERS,
	NFL_ACTIONS,
	NFL_HEADER_GRAPH,
	NFL_TABLE_GRAPH,

	__NFL_MAX,
	NFL_MAX = (__NFL_MAX - 1),
};

enum {
	NFL_TABLE_CMD_GET_TABLES,
	NFL_TABLE_CMD_GET_HEADERS,
	NFL_TABLE_CMD_GET_ACTIONS,
	NFL_TABLE_CMD_GET_HDR_GRAPH,
	NFL_TABLE_CMD_GET_TABLE_GRAPH,

	__NFL_CMD_MAX,
	NFL_CMD_MAX = (__NFL_CMD_MAX - 1),
};

#define NFL_GENL_NAME "net_flow_nl"
#define NFL_GENL_VERSION 0x1
#endif /* _UAPI_LINUX_IF_FLOW */

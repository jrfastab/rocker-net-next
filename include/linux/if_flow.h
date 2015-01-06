/*
 * include/linux/net/if_flow.h - Flow table interface for Switch devices
 * Copyright (c) 2014 John Fastabend <john.r.fastabend@intel.com>
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

#ifndef _IF_FLOW_H
#define _IF_FLOW_H

#include <uapi/linux/if_flow.h>
#include <linux/rhashtable.h>

/**
 * @struct net_flow_fields
 * @brief defines a field in a header
 *
 * @name string identifier for pretty printing
 * @uid  unique identifier for field
 * @bitwidth length of field in bits
 */
struct net_flow_field {
	char *name;
	__u32 uid;
	__u32 bitwidth;
};

/**
 * @struct net_flow_hdr
 * @brief defines a match (header/field) an endpoint can use
 *
 * @name string identifier for pretty printing
 * @uid unique identifier for header
 * @field_sz number of fields are in the set
 * @fields the set of fields in the net_flow_hdr
 */
struct net_flow_hdr {
	char *name;
	__u32 uid;
	__u32 field_sz;
	struct net_flow_field *fields;
};

/**
 * @struct net_flow_action_arg
 * @brief encodes action arguments in structures one per argument
 *
 * @name    string identifier for pretty printing
 * @type    type of argument either u8, u16, u32, u64
 * @value_# indicate value/mask value type on of u8, u16, u32, or u64
 */
struct net_flow_action_arg {
	char *name;
	enum net_flow_action_arg_type type;
	union {
		__u8  value_u8;
		__u16 value_u16;
		__u32 value_u32;
		__u64 value_u64;
	};
};

/**
 * @struct net_flow_action
 * @brief a description of a endpoint defined action
 *
 * @name printable name
 * @uid unique action identifier
 * @instance set to field_ref instance id when set_field action otherwise 0
 * @args null terminated list of action arguments
 */
struct net_flow_action {
	char *name;
	__u32 uid;
	__u32 instance;
	struct net_flow_action_arg *args;
};

/**
 * @struct net_flow_field_ref
 * @brief uniquely identify field as instance:header:field tuple
 *
 * @instance identify unique instance of field reference
 * @header   identify unique header reference
 * @field    identify unique field in above header reference
 * @mask_type indicate mask type
 * @type     indicate value/mask value type on of u8, u16, u32, or u64
 * @value_u# value of field reference
 * @mask_u#  mask value of field reference
 */
struct net_flow_field_ref {
	__u32 instance;
	__u32 header;
	__u32 field;
	__u32 mask_type;
	__u32 type;
	union {
		struct {
			__u8 value_u8;
			__u8 mask_u8;
		};
		struct {
			__u16 value_u16;
			__u16 mask_u16;
		};
		struct {
			__u32 value_u32;
			__u32 mask_u32;
		};
		struct {
			__u64 value_u64;
			__u64 mask_u64;
		};
	};
};

/**
 * @struct net_flow_tbl
 * @brief define flow table with supported match/actions
 *
 * @name string identifier for pretty printing
 * @uid unique identifier for table
 * @source uid of parent table
 * @apply_action actions in the same apply group are applied in one step
 * @size max number of entries for table or -1 for unbounded
 * @matches null terminated set of supported match types given by match uid
 * @actions null terminated set of supported action types given by action uid
 * @cache software cache of hardware flows
 */
struct net_flow_tbl {
	char *name;
	__u32 uid;
	__u32 source;
	__u32 apply_action;
	__u32 size;
	struct net_flow_field_ref *matches;
	__u32 *actions;
	struct rhashtable cache;
};

/**
 * @struct net_flow_jump_table
 * @brief encodes an edge of the table graph or header graph
 *
 * @field   field reference must be true to follow edge
 * @node    node identifier to connect edge to
 */

struct net_flow_jump_table {
	struct net_flow_field_ref field;
	__u32 node; /* <0 is a parser error */
};

/* @struct net_flow_hdr_node
 * @brief node in a header graph of header fields.
 *
 * @name string identifier for pretty printing
 * @uid  unique id of the graph node
 * @hdrs null terminated list of hdrs identified by this node
 * @jump encoding of graph structure as a case jump statement
 */
struct net_flow_hdr_node {
	char *name;
	__u32 uid;
	__u32 *hdrs;
	struct net_flow_jump_table *jump;
};

/* @struct net_flow_tbl_node
 * @brief
 *
 * @uid	  unique id of the table node
 * @flags bitmask of table attributes
 * @jump  encoding of graph structure as a case jump statement
 */
struct net_flow_tbl_node {
	__u32 uid;
	__u32 flags;
	struct net_flow_jump_table *jump;
};

/**
 * @struct netdev_switch_model
 * @brief defines a netdev switch model
 *
 * @hdrs pointer to a null terminated array of supported headers
 * @hdr_graph pointer to a header parse graph
 * @actions pointer to a null terminated array of supported actions
 * @tbls pointer to a null terminated array of tables
 * @tbl_graph pointer to a graph giving table pipeline
 */
struct net_flow_switch_model {
	struct net_flow_hdr **hdrs;
	struct net_flow_hdr_node **hdr_graph;
	struct net_flow_action **actions;
	struct net_flow_tbl **tbls;
	struct net_flow_tbl_node **tbl_graph;
};

int register_flow_table(struct net_device *dev,
			struct net_flow_switch_model *model);
int unregister_flow_table(struct net_device *dev);

/**
 * @struct net_flow_rule
 * @brief describes the match/action entry
 *
 * @node node for resizable hash table used for software cache of rules
 * @rcu used to support delayed freeing via call_rcu in software cache
 * @uid unique identifier for flow
 * @priority priority to execute flow match/action in table
 * @match null terminated set of match uids match criteria
 * @action null terminated set of action uids to apply to match
 *
 * Flows must match all entries in match set.
 */
struct net_flow_rule {
	struct rhash_head node;
	struct rcu_head rcu;
	__u32 table_id;
	__u32 uid;
	__u32 priority;
	struct net_flow_field_ref *matches;
	struct net_flow_action *actions;
};

#ifdef CONFIG_NET_FLOW_TABLES
int net_flow_init_cache(struct net_flow_tbl *table);
void net_flow_destroy_cache(struct net_flow_tbl *table);
#else
static inline int
net_flow_init_cache(struct net_flow_tbl *table)
{
	return 0;
}

static inline void
net_flow_destroy_cache(struct net_flow_tbl *table)
{
	return;
}
#endif /* CONFIG_NET_FLOW_TABLES */
#endif /* _IF_FLOW_H_ */

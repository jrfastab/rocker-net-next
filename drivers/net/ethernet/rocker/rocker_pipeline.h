/*
 * drivers/net/ethernet/rocker/rocker_pipeline.h - Rocker switch device driver
 * Copyright (c) 2014 John Fastabend <john.r.fastabend@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ROCKER_PIPELINE_H_
#define _ROCKER_PIPELINE_H_

#include <linux/if_flow.h>
#include <linux/if_flow_common.h>

struct net_flow_hdr *rocker_header_list[] = {
	&net_flow_ethernet,
	&net_flow_vlan,
	&net_flow_ipv4,
	&net_flow_metadata_t,
	NULL,
};

struct net_flow_action *rocker_action_list[] = {
	&net_flow_set_vlan_id,
	&net_flow_copy_to_cpu,
	&net_flow_set_eth_src,
	&net_flow_set_eth_dst,
	&net_flow_check_ttl_drop,
	NULL,
};

/* headers graph */
enum rocker_header_instance_ids {
	ROCKER_HEADER_INSTANCE_UNSPEC,
	ROCKER_HEADER_INSTANCE_ETHERNET,
	ROCKER_HEADER_INSTANCE_VLAN_OUTER,
	ROCKER_HEADER_INSTANCE_IPV4,
	ROCKER_HEADER_INSTANCE_INGRESS_LPORT,
};

struct net_flow_jump_table rocker_parse_ethernet[] = {
	{
		.field = {
		   .header = HEADER_ETHERNET,
		   .field = HEADER_ETHERNET_ETHERTYPE,
		   .type = NFL_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = ETH_P_IP,
		},
		.node = ROCKER_HEADER_INSTANCE_IPV4,
	},
	{
		.field = {
		   .header = HEADER_ETHERNET,
		   .field = HEADER_ETHERNET_ETHERTYPE,
		   .type = NFL_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = ETH_P_8021Q,
		},
		.node = ROCKER_HEADER_INSTANCE_VLAN_OUTER,
	},
	{
		.field = {0},
		.node = 0,
	},
};

int rocker_ethernet_headers[] = {HEADER_ETHERNET, 0};

struct net_flow_hdr_node rocker_ethernet_header_node = {
	.name = "ethernet",
	.uid = ROCKER_HEADER_INSTANCE_ETHERNET,
	.hdrs = rocker_ethernet_headers,
	.jump = rocker_parse_ethernet,
};

struct net_flow_jump_table rocker_parse_vlan[] = {
	{
		.field = {
		   .header = HEADER_VLAN,
		   .field = HEADER_VLAN_ETHERTYPE,
		   .type = NFL_FIELD_REF_ATTR_TYPE_U16,
		   .value_u16 = ETH_P_IP,
		},
		.node = ROCKER_HEADER_INSTANCE_IPV4,
	},
	{
		.field = {0},
		.node = 0,
	},
};

int rocker_vlan_headers[] = {HEADER_VLAN, 0};
struct net_flow_hdr_node rocker_vlan_header_node = {
	.name = "vlan",
	.uid = ROCKER_HEADER_INSTANCE_VLAN_OUTER,
	.hdrs = rocker_vlan_headers,
	.jump = rocker_parse_vlan,
};

struct net_flow_jump_table rocker_terminal_headers[] = {
	{
		.field = {0},
		.node = NFL_JUMP_TABLE_DONE,
	},
	{
		.field = {0},
		.node = 0,
	},
};

int rocker_ipv4_headers[] = {HEADER_IPV4, 0};
struct net_flow_hdr_node rocker_ipv4_header_node = {
	.name = "ipv4",
	.uid = ROCKER_HEADER_INSTANCE_IPV4,
	.hdrs = rocker_ipv4_headers,
	.jump = rocker_terminal_headers,
};

int rocker_metadata_headers[] = {HEADER_METADATA, 0};
struct net_flow_hdr_node rocker_in_lport_header_node = {
	.name = "in_lport",
	.uid = ROCKER_HEADER_INSTANCE_INGRESS_LPORT,
	.hdrs = rocker_metadata_headers,
	.jump = rocker_terminal_headers,
};

struct net_flow_hdr_node *rocker_header_nodes[] = {
	&rocker_ethernet_header_node,
	&rocker_vlan_header_node,
	&rocker_ipv4_header_node,
	&rocker_in_lport_header_node,
	NULL,
};

/* table definition */
struct net_flow_field_ref rocker_matches_ig_port[] = {
	{ .instance = ROCKER_HEADER_INSTANCE_INGRESS_LPORT,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_INGRESS_LPORT,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref rocker_matches_vlan[] = {
	{ .instance = ROCKER_HEADER_INSTANCE_INGRESS_LPORT,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_INGRESS_LPORT,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = ROCKER_HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_VID,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref rocker_matches_term_mac[] = {
	{ .instance = ROCKER_HEADER_INSTANCE_INGRESS_LPORT,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_INGRESS_LPORT,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = ROCKER_HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_ETHERTYPE,
	  .mask_type = NFL_MASK_TYPE_EXACT},
	{ .instance = ROCKER_HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_DST_MAC,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = ROCKER_HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_VID,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref rocker_matches_ucast_routing[] = {
	{ .instance = ROCKER_HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_ETHERTYPE,
	  .mask_type = NFL_MASK_TYPE_EXACT},
	{ .instance = ROCKER_HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_DST_IP,
	  .mask_type = NFL_MASK_TYPE_LPM},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref rocker_matches_bridge[] = {
	{ .instance = ROCKER_HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_DST_MAC,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = ROCKER_HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_VID,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = 0, .field = 0},
};

struct net_flow_field_ref rocker_matches_acl[] = {
	{ .instance = ROCKER_HEADER_INSTANCE_INGRESS_LPORT,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_INGRESS_LPORT,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = ROCKER_HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_SRC_MAC,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = ROCKER_HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_DST_MAC,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = ROCKER_HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_ETHERTYPE,
	  .mask_type = NFL_MASK_TYPE_EXACT},
	{ .instance = ROCKER_HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_VID,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = ROCKER_HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_PROTOCOL,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = ROCKER_HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_DSCP,
	  .mask_type = NFL_MASK_TYPE_MASK},
	{ .instance = 0, .field = 0},
};

int rocker_actions_ig_port[] = {0};
int rocker_actions_vlan[] = {ACTION_SET_VLAN_ID, 0};
int rocker_actions_term_mac[] = {ACTION_COPY_TO_CPU, 0};
int rocker_actions_ucast_routing[] = {0};
int rocker_actions_bridge[] = {ACTION_COPY_TO_CPU, 0};
int rocker_actions_acl[] = {0};

enum rocker_flow_table_id_space {
	ROCKER_FLOW_TABLE_NULL,
	ROCKER_FLOW_TABLE_ID_INGRESS_PORT,
	ROCKER_FLOW_TABLE_ID_VLAN,
	ROCKER_FLOW_TABLE_ID_TERMINATION_MAC,
	ROCKER_FLOW_TABLE_ID_UNICAST_ROUTING,
	ROCKER_FLOW_TABLE_ID_MULTICAST_ROUTING,
	ROCKER_FLOW_TABLE_ID_BRIDGING,
	ROCKER_FLOW_TABLE_ID_ACL_POLICY,
};

struct net_flow_tbl rocker_ingress_port_table = {
	.name = "ingress_port",
	.uid = ROCKER_FLOW_TABLE_ID_INGRESS_PORT,
	.source = 1,
	.size = -1,
	.matches = rocker_matches_ig_port,
	.actions = rocker_actions_ig_port,
	.cache = {0},
};

struct net_flow_tbl rocker_vlan_table = {
	.name = "vlan",
	.uid = ROCKER_FLOW_TABLE_ID_VLAN,
	.source = 1,
	.size = -1,
	.matches = rocker_matches_vlan,
	.actions = rocker_actions_vlan,
	.cache = {0},
};

struct net_flow_tbl rocker_term_mac_table = {
	.name = "term_mac",
	.uid = ROCKER_FLOW_TABLE_ID_TERMINATION_MAC,
	.source = 1,
	.size = -1,
	.matches = rocker_matches_term_mac,
	.actions = rocker_actions_term_mac,
	.cache = {0},
};

struct net_flow_tbl rocker_ucast_routing_table = {
	.name = "ucast_routing",
	.uid = ROCKER_FLOW_TABLE_ID_UNICAST_ROUTING,
	.source = 1,
	.size = -1,
	.matches = rocker_matches_ucast_routing,
	.actions = rocker_actions_ucast_routing,
	.cache = {0},
};

struct net_flow_tbl rocker_bridge_table = {
	.name = "bridge",
	.uid = ROCKER_FLOW_TABLE_ID_BRIDGING,
	.source = 1,
	.size = -1,
	.matches = rocker_matches_bridge,
	.actions = rocker_actions_bridge,
	.cache = {0},
};

struct net_flow_tbl rocker_acl_table = {
	.name = "acl",
	.uid = ROCKER_FLOW_TABLE_ID_ACL_POLICY,
	.source = 1,
	.size = -1,
	.matches = rocker_matches_acl,
	.actions = rocker_actions_acl,
	.cache = {0},
};

struct net_flow_tbl *rocker_table_list[] = {
	&rocker_ingress_port_table,
	&rocker_vlan_table,
	&rocker_term_mac_table,
	&rocker_ucast_routing_table,
	&rocker_bridge_table,
	&rocker_acl_table,
	NULL,
};

/* Define the table graph layout */
struct net_flow_jump_table rocker_table_node_ig_port_next[] = {
	{ .field = {0}, .node = ROCKER_FLOW_TABLE_ID_VLAN},
	{ .field = {0}, .node = 0},
};

struct net_flow_tbl_node rocker_table_node_ingress_port = {
	.uid = ROCKER_FLOW_TABLE_ID_INGRESS_PORT,
	.jump = rocker_table_node_ig_port_next};

struct net_flow_jump_table rocker_table_node_vlan_next[] = {
	{ .field = {0}, .node = ROCKER_FLOW_TABLE_ID_TERMINATION_MAC},
	{ .field = {0}, .node = 0},
};

struct net_flow_tbl_node rocker_table_node_vlan = {
	.uid = ROCKER_FLOW_TABLE_ID_VLAN,
	.jump = rocker_table_node_vlan_next};

struct net_flow_jump_table rocker_table_node_term_mac_next[] = {
	{ .field = {0}, .node = ROCKER_FLOW_TABLE_ID_UNICAST_ROUTING},
	{ .field = {0}, .node = 0},
};

struct net_flow_tbl_node rocker_table_node_term_mac = {
	.uid = ROCKER_FLOW_TABLE_ID_TERMINATION_MAC,
	.jump = rocker_table_node_term_mac_next};

struct net_flow_jump_table rocker_table_node_bridge_next[] = {
	{ .field = {0}, .node = ROCKER_FLOW_TABLE_ID_ACL_POLICY},
	{ .field = {0}, .node = 0},
};

struct net_flow_tbl_node rocker_table_node_bridge = {
	.uid = ROCKER_FLOW_TABLE_ID_BRIDGING,
	.jump = rocker_table_node_bridge_next};

struct net_flow_jump_table rocker_table_node_ucast_routing_next[] = {
	{ .field = {0}, .node = ROCKER_FLOW_TABLE_ID_ACL_POLICY},
	{ .field = {0}, .node = 0},
};

struct net_flow_tbl_node rocker_table_node_ucast_routing = {
	.uid = ROCKER_FLOW_TABLE_ID_UNICAST_ROUTING,
	.jump = rocker_table_node_ucast_routing_next};

struct net_flow_jump_table rocker_table_node_acl_next[] = {
	{ .field = {0}, .node = 0},
};

struct net_flow_tbl_node rocker_table_node_acl = {
	.uid = ROCKER_FLOW_TABLE_ID_ACL_POLICY,
	.jump = rocker_table_node_acl_next};

struct net_flow_tbl_node *rocker_table_nodes[] = {
	&rocker_table_node_ingress_port,
	&rocker_table_node_vlan,
	&rocker_table_node_term_mac,
	&rocker_table_node_ucast_routing,
	&rocker_table_node_bridge,
	&rocker_table_node_acl,
	NULL,
};

struct net_flow_switch_model rocker_flow_model = {
	.hdrs = rocker_header_list,
	.hdr_graph = rocker_header_nodes,
	.actions = rocker_action_list,
	.tbls = rocker_table_list,
	.tbl_graph = rocker_table_nodes,
};
#endif /*_ROCKER_PIPELINE_H_*/

#ifndef _IF_FLOW_COMMON_H_
#define _IF_FLOW_COMMON_H_

#include <linux/if_flow.h>

/* Common header definition this section provides a set of common or
 * standard headers that device driver writers may use to simplify the
 * driver creation. We do not want vendor or driver specific headers
 * here though. Driver authors can keep these contained to their driver
 *
 * Driver authors may use unique IDs greater than HEADER_MAX_UID it is
 * guaranteed to be larger than any unique IDs used here.
 */
#define HEADER_MAX_UID 100

enum net_flow_headers {
	HEADER_UNSPEC,
	HEADER_ETHERNET,
	HEADER_VLAN,
	HEADER_IPV4,
	HEADER_METADATA,
	HEADER_METADATA_INTER_TABLE,
};

enum net_flow_ethernet_fields_ids {
	HEADER_ETHERNET_UNSPEC,
	HEADER_ETHERNET_SRC_MAC,
	HEADER_ETHERNET_DST_MAC,
	HEADER_ETHERNET_ETHERTYPE,
};

struct net_flow_field net_flow_ethernet_fields[] = {
	{ .name = "src_mac", .uid = HEADER_ETHERNET_SRC_MAC, .bitwidth = 48},
	{ .name = "dst_mac", .uid = HEADER_ETHERNET_DST_MAC, .bitwidth = 48},
	{ .name = "ethertype",
	  .uid = HEADER_ETHERNET_ETHERTYPE,
	  .bitwidth = 16},
};

struct net_flow_hdr net_flow_ethernet = {
	.name = "ethernet",
	.uid = HEADER_ETHERNET,
	.field_sz = ARRAY_SIZE(net_flow_ethernet_fields),
	.fields = net_flow_ethernet_fields,
};

enum net_flow_vlan_fields_ids {
	HEADER_VLAN_UNSPEC,
	HEADER_VLAN_PCP,
	HEADER_VLAN_CFI,
	HEADER_VLAN_VID,
	HEADER_VLAN_ETHERTYPE,
};

struct net_flow_field net_flow_vlan_fields[] = {
	{ .name = "pcp", .uid = HEADER_VLAN_PCP, .bitwidth = 3,},
	{ .name = "cfi", .uid = HEADER_VLAN_CFI, .bitwidth = 1,},
	{ .name = "vid", .uid = HEADER_VLAN_VID, .bitwidth = 12,},
	{ .name = "ethertype", .uid = HEADER_VLAN_ETHERTYPE, .bitwidth = 16,},
};

struct net_flow_hdr net_flow_vlan = {
	.name = "vlan",
	.uid = HEADER_VLAN,
	.field_sz = ARRAY_SIZE(net_flow_vlan_fields),
	.fields = net_flow_vlan_fields,
};

enum net_flow_ipv4_fields_ids {
	HEADER_IPV4_UNSPEC,
	HEADER_IPV4_VERSION,
	HEADER_IPV4_IHL,
	HEADER_IPV4_DSCP,
	HEADER_IPV4_ECN,
	HEADER_IPV4_LENGTH,
	HEADER_IPV4_IDENTIFICATION,
	HEADER_IPV4_FLAGS,
	HEADER_IPV4_FRAGMENT_OFFSET,
	HEADER_IPV4_TTL,
	HEADER_IPV4_PROTOCOL,
	HEADER_IPV4_CSUM,
	HEADER_IPV4_SRC_IP,
	HEADER_IPV4_DST_IP,
	HEADER_IPV4_OPTIONS,
};

struct net_flow_field net_flow_ipv4_fields[] = {
	{ .name = "version",
	  .uid = HEADER_IPV4_VERSION,
	  .bitwidth = 4,},
	{ .name = "ihl",
	  .uid = HEADER_IPV4_IHL,
	  .bitwidth = 4,},
	{ .name = "dscp",
	  .uid = HEADER_IPV4_DSCP,
	  .bitwidth = 6,},
	{ .name = "ecn",
	  .uid = HEADER_IPV4_ECN,
	  .bitwidth = 2,},
	{ .name = "length",
	  .uid = HEADER_IPV4_LENGTH,
	  .bitwidth = 8,},
	{ .name = "identification",
	  .uid = HEADER_IPV4_IDENTIFICATION,
	  .bitwidth = 8,},
	{ .name = "flags",
	  .uid = HEADER_IPV4_FLAGS,
	  .bitwidth = 3,},
	{ .name = "fragment_offset",
	  .uid = HEADER_IPV4_FRAGMENT_OFFSET,
	  .bitwidth = 13,},
	{ .name = "ttl",
	  .uid = HEADER_IPV4_TTL,
	  .bitwidth = 1,},
	{ .name = "protocol",
	  .uid = HEADER_IPV4_PROTOCOL,
	  .bitwidth = 8,},
	{ .name = "csum",
	  .uid = HEADER_IPV4_CSUM,
	  .bitwidth = 8,},
	{ .name = "src_ip",
	  .uid = HEADER_IPV4_SRC_IP,
	  .bitwidth = 32,},
	{ .name = "dst_ip",
	  .uid = HEADER_IPV4_DST_IP,
	  .bitwidth = 32,},
	{ .name = "options",
	  .uid = HEADER_IPV4_OPTIONS,
	  .bitwidth = 0,},
};

struct net_flow_hdr net_flow_ipv4 = {
	.name = "ipv4",
	.uid = HEADER_IPV4,
	.field_sz = ARRAY_SIZE(net_flow_ipv4_fields),
	.fields = net_flow_ipv4_fields,
};

/* Common set of supported metadata */
enum net_flow_metadata_fields_ids {
	HEADER_METADATA_UNSPEC,
	HEADER_METADATA_INGRESS_LPORT,
};

struct net_flow_field net_flow_metadata_fields[] = {
	{ .name = "ingress_lport",
	  .uid = HEADER_METADATA_INGRESS_LPORT,
	  .bitwidth = 32,},
};

struct net_flow_hdr net_flow_metadata_t = {
	.name = "metadata_t",
	.uid = HEADER_METADATA,
	.field_sz = ARRAY_SIZE(net_flow_metadata_fields),
	.fields = net_flow_metadata_fields,
};

enum net_flow_metadata_inter_table_field_ids {
	HEADER_METADATA_INTER_TABLE_UNSPEC,
	HEADER_METADATA_INTER_TABLE_FIELD,
};

struct net_flow_field net_flow_metadata_inter_table_fields[] = {
	{ .name = "inter_table",
	  .uid = HEADER_METADATA_INTER_TABLE_FIELD,
	  .bitwidth = 32,},
};

struct net_flow_hdr net_flow_metadata_inter_table_t = {
	.name = "metadata_inter_table_t",
	.uid = HEADER_METADATA_INTER_TABLE,
	.field_sz = ARRAY_SIZE(net_flow_metadata_inter_table_fields),
	.fields = net_flow_metadata_inter_table_fields,
};

/* Common set of actions. Below are the list of actions that are supported
 * by the Flow API.
 */
enum net_flow_action_ids {
	ACTION_SET_UNSPEC,
	ACTION_SET_VLAN_ID,
	ACTION_COPY_TO_CPU,
	ACTION_SET_ETH_SRC,
	ACTION_SET_ETH_DST,
	ACTION_SET_OUT_PORT,
	ACTION_CHECK_TTL_DROP,
	ACTION_DROP,
	__ACTION_MAX,
};

struct net_flow_action_arg net_flow_null_args[] = {
	{
		.name = "",
		.type = NFL_ACTION_ARG_TYPE_NULL,
	},
};

struct net_flow_action net_flow_null_action = {
	.name = "", .uid = 0, .args = NULL,
};

struct net_flow_action_arg net_flow_set_vlan_id_args[] = {
	{
		.name = "vlan_id",
		.type = NFL_ACTION_ARG_TYPE_U16,
		.value_u16 = 0,
	},
	{
		.name = "",
		.type = NFL_ACTION_ARG_TYPE_NULL,
	},
};

struct net_flow_action net_flow_set_vlan_id = {
	.name = "set_vlan_id",
	.uid = ACTION_SET_VLAN_ID,
	.args = net_flow_set_vlan_id_args,
};

struct net_flow_action net_flow_copy_to_cpu = {
	.name = "copy_to_cpu",
	.uid = ACTION_COPY_TO_CPU,
	.args = net_flow_null_args,
};

struct net_flow_action_arg net_flow_set_eth_src_args[] = {
	{
		.name = "eth_src",
		.type = NFL_ACTION_ARG_TYPE_U64,
		.value_u64 = 0,
	},
	{
		.name = "",
		.type = NFL_ACTION_ARG_TYPE_NULL,
	},
};

struct net_flow_action net_flow_set_eth_src = {
	.name = "set_eth_src",
	.uid = ACTION_SET_ETH_SRC,
	.args = net_flow_set_eth_src_args,
};

struct net_flow_action_arg net_flow_set_eth_dst_args[] = {
	{
		.name = "eth_dst",
		.type = NFL_ACTION_ARG_TYPE_U64,
		.value_u64 = 0,
	},
	{
		.name = "",
		.type = NFL_ACTION_ARG_TYPE_NULL,
	},
};

struct net_flow_action net_flow_set_eth_dst = {
	.name = "set_eth_dst",
	.uid = ACTION_SET_ETH_DST,
	.args = net_flow_set_eth_dst_args,
};

struct net_flow_action_arg net_flow_set_out_port_args[] = {
	{
		.name = "set_out_port",
		.type = NFL_ACTION_ARG_TYPE_U32,
		.value_u32 = 0,
	},
	{
		.name = "",
		.type = NFL_ACTION_ARG_TYPE_NULL,
	},
};

struct net_flow_action net_flow_set_out_port = {
	.name = "set_out_port",
	.uid = ACTION_SET_OUT_PORT,
	.args = net_flow_set_out_port_args,
};

struct net_flow_action net_flow_check_ttl_drop = {
	.name = "check_ttl_drop",
	.uid = ACTION_CHECK_TTL_DROP,
	.args = net_flow_null_args,
};

struct net_flow_action net_flow_drop = {
	.name = "drop",
	.uid = ACTION_DROP,
	.args = net_flow_null_args,
};

#endif

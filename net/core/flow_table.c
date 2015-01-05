/*
 * net/core/flow_table.c - Flow table interface for Switch devices
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

#include <uapi/linux/if_flow.h>
#include <linux/if_flow_common.h>
#include <linux/if_flow.h>
#include <linux/if_bridge.h>
#include <linux/types.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>
#include <linux/module.h>
#include <net/switchdev.h>
#include <linux/rhashtable.h>
#include <linux/jhash.h>

static const struct rhashtable_params tsk_rht_params;

struct net_flow_model {
	struct list_head list;
	struct net_device *dev;
	struct net_flow_switch_model *model;
};

static DEFINE_SPINLOCK(net_flow_models_lock);
static struct list_head __rcu net_flow_models __read_mostly;

static DEFINE_MUTEX(net_flow_mutex);

void net_flow_lock(void)
{
	mutex_lock(&net_flow_mutex);
}

void net_flow_unlock(void)
{
	mutex_unlock(&net_flow_mutex);
}

static struct genl_family net_flow_nl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= NFL_GENL_NAME,
	.version	= NFL_GENL_VERSION,
	.maxattr	= NFL_MAX,
	.netnsok	= true,
};

static
struct net_flow_switch_model *net_flow_get_model_by_dev(struct net_device *dev)
{
	struct net_flow_model *m;

	list_for_each_entry_rcu(m, &net_flow_models, list) {
		int err = netdev_switch_parent_id_eq(dev, m->dev);

		if (!err)
			return m->model;
	}

	return NULL;
}

static struct net_device *net_flow_get_dev(struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	int type, ifindex;

	if (!info->attrs[NFL_IDENTIFIER_TYPE] ||
	    !info->attrs[NFL_IDENTIFIER])
		return NULL;

	type = nla_get_u32(info->attrs[NFL_IDENTIFIER_TYPE]);
	switch (type) {
	case NFL_IDENTIFIER_IFINDEX:
		ifindex = nla_get_u32(info->attrs[NFL_IDENTIFIER]);
		break;
	default:
		return NULL;
	}

	return dev_get_by_index(net, ifindex);
}

static int net_flow_put_act_types(struct sk_buff *skb,
				  struct net_flow_action_arg *args)
{
	struct nlattr *arg;
	int i, err;

	for (i = 0; args[i].type; i++) {
		arg = nla_nest_start(skb, NFL_ACTION_ARG);
		if (!arg)
			return -EMSGSIZE;

		if (args[i].name) {
			err = nla_put_string(skb, NFL_ACTION_ARG_NAME,
					     args[i].name);
			if (err)
				goto out;
		}

		err = nla_put_u32(skb, NFL_ACTION_ARG_TYPE, args[i].type);
		if (err)
			goto out;

		switch (args[i].type) {
		case NFL_ACTION_ARG_TYPE_NULL:
			err = 0;
			break;
		case NFL_ACTION_ARG_TYPE_U8:
			err = nla_put_u8(skb, NFL_ACTION_ARG_VALUE,
					 args[i].value_u8);
			break;
		case NFL_ACTION_ARG_TYPE_U16:
			err = nla_put_u16(skb, NFL_ACTION_ARG_VALUE,
					  args[i].value_u16);
			break;
		case NFL_ACTION_ARG_TYPE_U32:
			err = nla_put_u32(skb, NFL_ACTION_ARG_VALUE,
					  args[i].value_u32);
			break;
		case NFL_ACTION_ARG_TYPE_U64:
			err = nla_put_u64(skb, NFL_ACTION_ARG_VALUE,
					  args[i].value_u64);
			break;
		default:
			err = -EINVAL;
			break;
		}

		if (err)
			goto out;

		nla_nest_end(skb, arg);
	}
	return 0;
out:
	nla_nest_cancel(skb, arg);
	return err;
}

static const
struct nla_policy net_flow_action_policy[NFL_ACTION_ATTR_MAX + 1] = {
	[NFL_ACTION_ATTR_NAME]	    = {.type = NLA_STRING },
	[NFL_ACTION_ATTR_UID]	    = {.type = NLA_U32 },
	[NFL_ACTION_ATTR_SIGNATURE] = {.type = NLA_NESTED },
};

static int net_flow_put_action(struct sk_buff *skb, struct net_flow_action *a)
{
	struct nlattr *nest;
	int err;

	if (a->name && nla_put_string(skb, NFL_ACTION_ATTR_NAME, a->name))
		return -EMSGSIZE;

	if (nla_put_u32(skb, NFL_ACTION_ATTR_UID, a->uid))
		return -EMSGSIZE;

	if (a->args) {
		nest = nla_nest_start(skb, NFL_ACTION_ATTR_SIGNATURE);
		if (!nest)
			return -EMSGSIZE;

		err = net_flow_put_act_types(skb, a->args);
		if (err) {
			nla_nest_cancel(skb, nest);
			return err;
		}
		nla_nest_end(skb, nest);
	}

	return 0;
}

static int net_flow_put_actions(struct sk_buff *skb,
				struct net_flow_action **acts)
{
	struct nlattr *actions;
	int i, err;

	actions = nla_nest_start(skb, NFL_ACTIONS);
	if (!actions)
		return -EMSGSIZE;

	for (i = 0; acts[i]; i++) {
		struct nlattr *action = nla_nest_start(skb, NFL_ACTION);

		if (!action)
			goto action_put_failure;

		err = net_flow_put_action(skb, acts[i]);
		if (err)
			goto action_put_failure;
		nla_nest_end(skb, action);
	}
	nla_nest_end(skb, actions);

	return 0;
action_put_failure:
	nla_nest_cancel(skb, actions);
	return -EMSGSIZE;
}

static struct sk_buff *net_flow_build_actions_msg(struct net_flow_action **a,
						  struct net_device *dev,
						  u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *hdr;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb,
			NFL_IDENTIFIER_TYPE,
			NFL_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NFL_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	err = net_flow_put_actions(skb, a);
	if (err < 0)
		goto out;

	genlmsg_end(skb, hdr);
	return skb;
out:
	nlmsg_free(skb);
	return ERR_PTR(err);
}

static int net_flow_cmd_get_actions(struct sk_buff *skb,
				    struct genl_info *info)
{
	struct net_flow_switch_model *m;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_get_dev(info);
	if (!dev)
		return -EINVAL;

	rcu_read_lock();
	m = net_flow_get_model_by_dev(dev);
	if (!m || !m->actions) {
		rcu_read_unlock();
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	msg = net_flow_build_actions_msg(m->actions, dev,
					 info->snd_portid,
					 info->snd_seq,
					 NFL_TABLE_CMD_GET_ACTIONS);
	rcu_read_unlock();
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

static int net_flow_put_field_ref(struct sk_buff *skb,
				  struct net_flow_field_ref *ref)
{
	if (nla_put_u32(skb, NFL_FIELD_REF_INSTANCE, ref->instance) ||
	    nla_put_u32(skb, NFL_FIELD_REF_HEADER, ref->header) ||
	    nla_put_u32(skb, NFL_FIELD_REF_FIELD, ref->field) ||
	    nla_put_u32(skb, NFL_FIELD_REF_MASK_TYPE, ref->mask_type) ||
	    nla_put_u32(skb, NFL_FIELD_REF_TYPE, ref->type))
		return -EMSGSIZE;

	return 0;
}

static int net_flow_put_field_value(struct sk_buff *skb,
				    struct net_flow_field_ref *r)
{
	int err = -EINVAL;

	switch (r->type) {
	case NFL_FIELD_REF_ATTR_TYPE_UNSPEC:
		err = 0;
		break;
	case NFL_FIELD_REF_ATTR_TYPE_U8:
		err = nla_put_u8(skb, NFL_FIELD_REF_VALUE, r->value_u8);
		if (err)
			break;
		err = nla_put_u8(skb, NFL_FIELD_REF_MASK, r->mask_u8);
		break;
	case NFL_FIELD_REF_ATTR_TYPE_U16:
		err = nla_put_u16(skb, NFL_FIELD_REF_VALUE, r->value_u16);
		if (err)
			break;
		err = nla_put_u16(skb, NFL_FIELD_REF_MASK, r->mask_u16);
		break;
	case NFL_FIELD_REF_ATTR_TYPE_U32:
		err = nla_put_u32(skb, NFL_FIELD_REF_VALUE, r->value_u32);
		if (err)
			break;
		err = nla_put_u32(skb, NFL_FIELD_REF_MASK, r->mask_u32);
		break;
	case NFL_FIELD_REF_ATTR_TYPE_U64:
		err = nla_put_u64(skb, NFL_FIELD_REF_VALUE, r->value_u64);
		if (err)
			break;
		err = nla_put_u64(skb, NFL_FIELD_REF_MASK, r->mask_u64);
		break;
	default:
		break;
	}
	return err;
}

static int net_flow_put_table(struct net_device *dev,
			      struct sk_buff *skb,
			      struct net_flow_tbl *t)
{
	struct nlattr *matches, *actions, *field;
	int i, err;

	if (nla_put_string(skb, NFL_TABLE_ATTR_NAME, t->name) ||
	    nla_put_u32(skb, NFL_TABLE_ATTR_UID, t->uid) ||
	    nla_put_u32(skb, NFL_TABLE_ATTR_SOURCE, t->source) ||
	    nla_put_u32(skb, NFL_TABLE_ATTR_APPLY, t->apply_action) ||
	    nla_put_u32(skb, NFL_TABLE_ATTR_SIZE, t->size))
		return -EMSGSIZE;

	matches = nla_nest_start(skb, NFL_TABLE_ATTR_MATCHES);
	if (!matches)
		return -EMSGSIZE;

	for (i = 0; t->matches[i].instance; i++) {
		field = nla_nest_start(skb, NFL_FIELD_REF);

		err = net_flow_put_field_ref(skb, &t->matches[i]);
		if (err) {
			nla_nest_cancel(skb, matches);
			return -EMSGSIZE;
		}

		nla_nest_end(skb, field);
	}
	nla_nest_end(skb, matches);

	actions = nla_nest_start(skb, NFL_TABLE_ATTR_ACTIONS);
	if (!actions)
		return -EMSGSIZE;

	for (i = 0; t->actions[i]; i++) {
		if (nla_put_u32(skb,
				NFL_ACTION_ATTR_UID,
				t->actions[i])) {
			nla_nest_cancel(skb, actions);
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, actions);

	return 0;
}

static int net_flow_put_tables(struct net_device *dev,
			       struct sk_buff *skb,
			       struct net_flow_tbl **tables)
{
	struct nlattr *nest, *t;
	int i, err = 0;

	nest = nla_nest_start(skb, NFL_TABLES);
	if (!nest)
		return -EMSGSIZE;

	for (i = 0; tables[i]; i++) {
		t = nla_nest_start(skb, NFL_TABLE);
		if (!t) {
			err = -EMSGSIZE;
			goto errout;
		}

		err = net_flow_put_table(dev, skb, tables[i]);
		if (err) {
			nla_nest_cancel(skb, t);
			goto errout;
		}
		nla_nest_end(skb, t);
	}
	nla_nest_end(skb, nest);
	return 0;
errout:
	nla_nest_cancel(skb, nest);
	return err;
}

static struct sk_buff *net_flow_build_tables_msg(struct net_flow_tbl **t,
						 struct net_device *dev,
						 u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *hdr;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb,
			NFL_IDENTIFIER_TYPE,
			NFL_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NFL_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	err = net_flow_put_tables(dev, skb, t);
	if (err < 0)
		goto out;

	genlmsg_end(skb, hdr);
	return skb;
out:
	nlmsg_free(skb);
	return ERR_PTR(err);
}

static int net_flow_cmd_get_tables(struct sk_buff *skb,
				   struct genl_info *info)
{
	struct net_flow_switch_model *m;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_get_dev(info);
	if (!dev)
		return -EINVAL;

	rcu_read_lock();
	m = net_flow_get_model_by_dev(dev);
	if (!m || !m->tbls) {
		rcu_read_unlock();
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	msg = net_flow_build_tables_msg(m->tbls, dev,
					info->snd_portid,
					info->snd_seq,
					NFL_TABLE_CMD_GET_TABLES);
	rcu_read_unlock();
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

static
int net_flow_put_fields(struct sk_buff *skb, const struct net_flow_hdr *h)
{
	struct net_flow_field *f;
	int count = h->field_sz;
	struct nlattr *field;

	for (f = h->fields; count; count--, f++) {
		field = nla_nest_start(skb, NFL_FIELD);
		if (!field)
			goto field_put_failure;

		if (nla_put_string(skb, NFL_FIELD_ATTR_NAME, f->name) ||
		    nla_put_u32(skb, NFL_FIELD_ATTR_UID, f->uid) ||
		    nla_put_u32(skb, NFL_FIELD_ATTR_BITWIDTH, f->bitwidth))
			goto out;

		nla_nest_end(skb, field);
	}

	return 0;
out:
	nla_nest_cancel(skb, field);
field_put_failure:
	return -EMSGSIZE;
}

static int net_flow_put_headers(struct sk_buff *skb,
				struct net_flow_hdr **headers)
{
	struct nlattr *nest, *hdr, *fields;
	struct net_flow_hdr *h;
	int i, err;

	nest = nla_nest_start(skb, NFL_HEADERS);
	if (!nest)
		return -EMSGSIZE;

	for (i = 0; headers[i]; i++) {
		err = -EMSGSIZE;
		h = headers[i];

		hdr = nla_nest_start(skb, NFL_HEADER);
		if (!hdr)
			goto put_failure;

		if (nla_put_string(skb, NFL_HEADER_ATTR_NAME, h->name) ||
		    nla_put_u32(skb, NFL_HEADER_ATTR_UID, h->uid))
			goto put_failure;

		fields = nla_nest_start(skb, NFL_HEADER_ATTR_FIELDS);
		if (!fields)
			goto put_failure;

		err = net_flow_put_fields(skb, h);
		if (err)
			goto put_failure;

		nla_nest_end(skb, fields);

		nla_nest_end(skb, hdr);
	}
	nla_nest_end(skb, nest);

	return 0;
put_failure:
	nla_nest_cancel(skb, nest);
	return err;
}

static struct sk_buff *net_flow_build_headers_msg(struct net_flow_hdr **h,
						  struct net_device *dev,
						  u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *hdr;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb,
			NFL_IDENTIFIER_TYPE,
			NFL_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NFL_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	err = net_flow_put_headers(skb, h);
	if (err < 0)
		goto out;

	genlmsg_end(skb, hdr);
	return skb;
out:
	nlmsg_free(skb);
	return ERR_PTR(err);
}

static int net_flow_cmd_get_headers(struct sk_buff *skb,
				    struct genl_info *info)
{
	struct net_flow_switch_model *m;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_get_dev(info);
	if (!dev)
		return -EINVAL;

	rcu_read_lock();
	m = net_flow_get_model_by_dev(dev);
	if (!m || !m->hdrs) {
		rcu_read_unlock();
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	msg = net_flow_build_headers_msg(m->hdrs, dev,
					 info->snd_portid,
					 info->snd_seq,
					 NFL_TABLE_CMD_GET_HEADERS);
	rcu_read_unlock();
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

static int net_flow_put_header_node(struct sk_buff *skb,
				    struct net_flow_hdr_node *node)
{
	struct nlattr *hdrs, *jumps;
	int i, err;

	if (nla_put_string(skb, NFL_HEADER_NODE_NAME, node->name) ||
	    nla_put_u32(skb, NFL_HEADER_NODE_UID, node->uid))
		return -EMSGSIZE;

	/* Insert the set of headers that get extracted at this node */
	hdrs = nla_nest_start(skb, NFL_HEADER_NODE_HDRS);
	if (!hdrs)
		return -EMSGSIZE;
	for (i = 0; node->hdrs[i]; i++) {
		if (nla_put_u32(skb, NFL_HEADER_NODE_HDRS_VALUE,
				node->hdrs[i])) {
			nla_nest_cancel(skb, hdrs);
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, hdrs);

	/* Then give the jump table to find next header node in graph */
	jumps = nla_nest_start(skb, NFL_HEADER_NODE_JUMP);
	if (!jumps)
		return -EMSGSIZE;

	for (i = 0; node->jump[i].node; i++) {
		struct nlattr *entry;

		entry = nla_nest_start(skb, NFL_JUMP_ENTRY);
		if (!entry) {
			nla_nest_cancel(skb, jumps);
			return -EMSGSIZE;
		}

		err = nla_put_u32(skb, NFL_FIELD_REF_NEXT_NODE,
				  node->jump[i].node);
		if (err) {
			nla_nest_cancel(skb, jumps);
			return err;
		}

		err = net_flow_put_field_ref(skb, &node->jump[i].field);
		if (err) {
			nla_nest_cancel(skb, jumps);
			return err;
		}

		err = net_flow_put_field_value(skb, &node->jump[i].field);
		if (err) {
			nla_nest_cancel(skb, jumps);
			return err;
		}
		nla_nest_end(skb, entry);
	}
	nla_nest_end(skb, jumps);

	return 0;
}

static int net_flow_put_header_graph(struct sk_buff *skb,
				     struct net_flow_hdr_node **g)
{
	struct nlattr *nodes, *node;
	int i, err;

	nodes = nla_nest_start(skb, NFL_HEADER_GRAPH);
	if (!nodes)
		return -EMSGSIZE;

	for (i = 0; g[i]; i++) {
		node = nla_nest_start(skb, NFL_HEADER_GRAPH_NODE);
		if (!node) {
			err = -EMSGSIZE;
			goto nodes_put_error;
		}

		err = net_flow_put_header_node(skb, g[i]);
		if (err)
			goto nodes_put_error;

		nla_nest_end(skb, node);
	}

	nla_nest_end(skb, nodes);
	return 0;
nodes_put_error:
	nla_nest_cancel(skb, nodes);
	return err;
}

static
struct sk_buff *net_flow_build_header_graph_msg(struct net_flow_hdr_node **g,
						struct net_device *dev,
						u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *hdr;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb,
			NFL_IDENTIFIER_TYPE,
			NFL_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NFL_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	err = net_flow_put_header_graph(skb, g);
	if (err < 0)
		goto out;

	genlmsg_end(skb, hdr);
	return skb;
out:
	nlmsg_free(skb);
	return ERR_PTR(err);
}

static int net_flow_cmd_get_header_graph(struct sk_buff *skb,
					 struct genl_info *info)
{
	struct net_flow_switch_model *m;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_get_dev(info);
	if (!dev)
		return -EINVAL;

	rcu_read_lock();
	m = net_flow_get_model_by_dev(dev);
	if (!m || !m->hdr_graph) {
		rcu_read_unlock();
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	msg = net_flow_build_header_graph_msg(m->hdr_graph, dev,
					      info->snd_portid,
					      info->snd_seq,
					      NFL_TABLE_CMD_GET_HDR_GRAPH);
	rcu_read_unlock();
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

static int net_flow_put_table_node(struct sk_buff *skb,
				   struct net_flow_tbl_node *node)
{
	struct nlattr *nest, *jump;
	int i, err = -EMSGSIZE;

	nest = nla_nest_start(skb, NFL_TABLE_GRAPH_NODE);
	if (!nest)
		return err;

	if (nla_put_u32(skb, NFL_TABLE_GRAPH_NODE_UID, node->uid) ||
	    nla_put_u32(skb, NFL_TABLE_GRAPH_NODE_FLAGS, node->flags))
		goto node_put_failure;

	jump = nla_nest_start(skb, NFL_TABLE_GRAPH_NODE_JUMP);
	if (!jump)
		goto node_put_failure;

	for (i = 0; node->jump[i].node; i++) {
		struct nlattr *entry;

		entry = nla_nest_start(skb, NFL_JUMP_ENTRY);
		if (!entry)
			goto node_put_failure;

		err = nla_put_u32(skb, NFL_FIELD_REF_NEXT_NODE,
				  node->jump[i].node);
		if (err) {
			nla_nest_cancel(skb, jump);
			return err;
		}

		err = net_flow_put_field_ref(skb, &node->jump[i].field);
		if (err)
			goto node_put_failure;

		err = net_flow_put_field_value(skb, &node->jump[i].field);
		if (err)
			goto node_put_failure;

		nla_nest_end(skb, entry);
	}

	nla_nest_end(skb, jump);
	nla_nest_end(skb, nest);
	return 0;
node_put_failure:
	nla_nest_cancel(skb, nest);
	return err;
}

static int net_flow_put_table_graph(struct sk_buff *skb,
				    struct net_flow_tbl_node **nodes)
{
	struct nlattr *graph;
	int i, err;

	graph = nla_nest_start(skb, NFL_TABLE_GRAPH);
	if (!graph)
		return -EMSGSIZE;

	for (i = 0; nodes[i]; i++) {
		err = net_flow_put_table_node(skb, nodes[i]);
		if (err) {
			nla_nest_cancel(skb, graph);
			return -EMSGSIZE;
		}
	}

	nla_nest_end(skb, graph);
	return 0;
}

static
struct sk_buff *net_flow_build_graph_msg(struct net_flow_tbl_node **g,
					 struct net_device *dev,
					 u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *hdr;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb,
			NFL_IDENTIFIER_TYPE,
			NFL_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NFL_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	err = net_flow_put_table_graph(skb, g);
	if (err < 0)
		goto out;

	genlmsg_end(skb, hdr);
	return skb;
out:
	nlmsg_free(skb);
	return ERR_PTR(err);
}

static int net_flow_cmd_get_table_graph(struct sk_buff *skb,
					struct genl_info *info)
{
	struct net_flow_switch_model *m;
	struct net_device *dev;
	struct sk_buff *msg;

	dev = net_flow_get_dev(info);
	if (!dev)
		return -EINVAL;

	rcu_read_lock();
	m = net_flow_get_model_by_dev(dev);
	if (!m || !m->tbl_graph) {
		rcu_read_unlock();
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	msg = net_flow_build_graph_msg(m->tbl_graph, dev,
				       info->snd_portid,
				       info->snd_seq,
				       NFL_TABLE_CMD_GET_TABLE_GRAPH);
	rcu_read_unlock();
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
}

static struct net_flow_tbl *net_flow_get_table(struct net_device *dev,
					       int table_id)
{
	struct net_flow_switch_model *m;
	struct net_flow_tbl **tables;
	int i;

	m = net_flow_get_model_by_dev(dev);
	if (!m || !m->tbls)
		return NULL;

	tables = m->tbls;

	for (i = 0; tables[i]; i++) {
		if (tables[i]->uid == table_id)
			return tables[i];
	}

	return NULL;
}

static int net_flow_put_flow_action(struct sk_buff *skb,
				    struct net_flow_action *a)
{
	struct nlattr *action, *sigs;
	int err = 0;

	action = nla_nest_start(skb, NFL_ACTION);
	if (!action)
		return -EMSGSIZE;

	if (nla_put_u32(skb, NFL_ACTION_ATTR_UID, a->uid))
		return -EMSGSIZE;

	if (!a->args)
		goto done;

	sigs = nla_nest_start(skb, NFL_ACTION_ATTR_SIGNATURE);
	if (!sigs) {
		nla_nest_cancel(skb, action);
		return -EMSGSIZE;
	}

	err = net_flow_put_act_types(skb, a->args);
	if (err) {
		nla_nest_cancel(skb, action);
		return err;
	}
	nla_nest_end(skb, sigs);
done:
	nla_nest_end(skb, action);
	return 0;
}

static int net_flow_put_rule(struct sk_buff *skb, struct net_flow_rule *rule)
{
	struct nlattr *flows, *actions, *matches;
	int j, i = 0;
	int err = -EMSGSIZE;

	flows = nla_nest_start(skb, NFL_FLOW);
	if (!flows)
		goto put_failure;

	if (nla_put_u32(skb, NFL_ATTR_TABLE, rule->table_id) ||
	    nla_put_u32(skb, NFL_ATTR_UID, rule->uid) ||
	    nla_put_u32(skb, NFL_ATTR_PRIORITY, rule->priority))
		goto flows_put_failure;

	if (rule->matches) {
		matches = nla_nest_start(skb, NFL_ATTR_MATCHES);
		if (!matches)
			goto flows_put_failure;

		for (j = 0; rule->matches && rule->matches[j].header; j++) {
			struct net_flow_field_ref *f = &rule->matches[j];
			struct nlattr *field;

			field = nla_nest_start(skb, NFL_FIELD_REF);
			if (!field) {
				err = -EMSGSIZE;
				goto flows_put_failure;
			}

			err = net_flow_put_field_ref(skb, f);
			if (err)
				goto flows_put_failure;

			err = net_flow_put_field_value(skb, f);
			if (err)
				goto flows_put_failure;

			nla_nest_end(skb, field);
		}
		nla_nest_end(skb, matches);
	}

	if (rule->actions) {
		actions = nla_nest_start(skb, NFL_ATTR_ACTIONS);
		if (!actions)
			goto flows_put_failure;

		for (i = 0; rule->actions && rule->actions[i].uid; i++) {
			err = net_flow_put_flow_action(skb, &rule->actions[i]);
			if (err)
				goto flows_put_failure;
		}
		nla_nest_end(skb, actions);
	}

	nla_nest_end(skb, flows);
	return 0;

flows_put_failure:
	nla_nest_cancel(skb, flows);
put_failure:
	return err;
}

static int net_flow_get_rule_cache(struct sk_buff *skb,
				   struct net_flow_tbl *table,
				   int min, int max)
{
	const struct bucket_table *tbl;
	struct net_flow_rule *he;
	int i, err = 0;

	rcu_read_lock();
	tbl = rht_dereference_rcu(table->cache.tbl, &table->cache);

	for (i = 0; i < tbl->size; i++) {
		struct rhash_head *pos;

		rht_for_each_entry_rcu(he, pos, tbl, i, node) {
			if (he->uid < min || (max > 0 && he->uid > max))
				continue;
			err = net_flow_put_rule(skb, he);
			if (err)
				goto out;
		}
	}
out:
	rcu_read_unlock();
	return err;
}

static struct sk_buff *net_flow_build_flows_msg(struct net_device *dev,
						u32 portid, int seq, u8 cmd,
						int min, int max, int table)
{
	struct genlmsghdr *hdr;
	struct net_flow_tbl *t;
	struct nlattr *flows;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOBUFS);

	rcu_read_lock();
	hdr = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!hdr)
		goto out;

	if (nla_put_u32(skb,
			NFL_IDENTIFIER_TYPE,
			NFL_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NFL_IDENTIFIER, dev->ifindex)) {
		err = -ENOBUFS;
		goto out;
	}

	t = net_flow_get_table(dev, table);
	if (!t) {
		err = -EINVAL;
		goto out;
	}

	flows = nla_nest_start(skb, NFL_FLOWS);
	if (!flows) {
		err = -EMSGSIZE;
		goto out;
	}

	err = net_flow_get_rule_cache(skb, t, min, max);
	if (err < 0) {
		nla_nest_cancel(skb, flows);
		goto out;
	}

	nla_nest_end(skb, flows);

	genlmsg_end(skb, hdr);
	rcu_read_unlock();
	return skb;
out:
	rcu_read_unlock();
	nlmsg_free(skb);
	return ERR_PTR(err);
}

static const
struct nla_policy net_flow_table_flows_policy[NFL_TABLE_FLOWS_MAX + 1] = {
	[NFL_TABLE_FLOWS_TABLE]   = { .type = NLA_U32,},
	[NFL_TABLE_FLOWS_MINPRIO] = { .type = NLA_U32,},
	[NFL_TABLE_FLOWS_MAXPRIO] = { .type = NLA_U32,},
	[NFL_TABLE_FLOWS_FLOWS]   = { .type = NLA_NESTED,},
};

static int net_flow_table_cmd_get_flows(struct sk_buff *skb,
					struct genl_info *info)
{
	struct nlattr *tb[NFL_TABLE_FLOWS_MAX + 1];
	int table, min = -1, max = -1;
	struct net_device *dev;
	struct sk_buff *msg;
	int err = -EINVAL;

	dev = net_flow_get_dev(info);
	if (!dev)
		return -EINVAL;

	if (!info->attrs[NFL_IDENTIFIER_TYPE] ||
	    !info->attrs[NFL_IDENTIFIER] ||
	    !info->attrs[NFL_FLOWS])
		goto out;

	err = nla_parse_nested(tb, NFL_TABLE_FLOWS_MAX,
			       info->attrs[NFL_FLOWS],
			       net_flow_table_flows_policy);
	if (err)
		goto out;

	if (!tb[NFL_TABLE_FLOWS_TABLE])
		goto out;

	table = nla_get_u32(tb[NFL_TABLE_FLOWS_TABLE]);

	if (tb[NFL_TABLE_FLOWS_MINPRIO])
		min = nla_get_u32(tb[NFL_TABLE_FLOWS_MINPRIO]);
	if (tb[NFL_TABLE_FLOWS_MAXPRIO])
		max = nla_get_u32(tb[NFL_TABLE_FLOWS_MAXPRIO]);

	msg = net_flow_build_flows_msg(dev,
				       info->snd_portid,
				       info->snd_seq,
				       NFL_TABLE_CMD_GET_FLOWS,
				       min, max, table);
	dev_put(dev);

	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return genlmsg_reply(msg, info);
out:
	dev_put(dev);
	return err;
}

static struct sk_buff *net_flow_start_errmsg(struct net_device *dev,
					     struct genlmsghdr **hdr,
					     u32 portid, int seq, u8 cmd)
{
	struct genlmsghdr *h;
	struct sk_buff *skb;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-EMSGSIZE);

	h = genlmsg_put(skb, portid, seq, &net_flow_nl_family, 0, cmd);
	if (!h)
		return ERR_PTR(-EMSGSIZE);

	if (nla_put_u32(skb,
			NFL_IDENTIFIER_TYPE,
			NFL_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(skb, NFL_IDENTIFIER, dev->ifindex))
		return ERR_PTR(-EMSGSIZE);

	*hdr = h;
	return skb;
}

const struct nla_policy net_flow_field_policy[NFL_FIELD_REF_MAX + 1] = {
	[NFL_FIELD_REF_NEXT_NODE] = { .type = NLA_U32,},
	[NFL_FIELD_REF_INSTANCE]  = { .type = NLA_U32,},
	[NFL_FIELD_REF_HEADER]	  = { .type = NLA_U32,},
	[NFL_FIELD_REF_FIELD]	  = { .type = NLA_U32,},
	[NFL_FIELD_REF_MASK_TYPE] = { .type = NLA_U32,},
	[NFL_FIELD_REF_TYPE]	  = { .type = NLA_U32,},
	[NFL_FIELD_REF_VALUE]	  = { .type = NLA_BINARY,
				      .len = sizeof(u64)},
	[NFL_FIELD_REF_MASK]	  = { .type = NLA_BINARY,
				      .len = sizeof(u64)},
};

static int net_flow_get_field(struct net_flow_field_ref *field,
			      struct nlattr *nla)
{
	struct nlattr *ref[NFL_FIELD_REF_MAX + 1];
	int err;

	err = nla_parse_nested(ref, NFL_FIELD_REF_MAX,
			       nla, net_flow_field_policy);
	if (err)
		return err;

	if (!ref[NFL_FIELD_REF_INSTANCE] ||
	    !ref[NFL_FIELD_REF_HEADER] ||
	    !ref[NFL_FIELD_REF_FIELD] ||
	    !ref[NFL_FIELD_REF_MASK_TYPE] ||
	    !ref[NFL_FIELD_REF_TYPE])
		return -EINVAL;

	field->instance = nla_get_u32(ref[NFL_FIELD_REF_INSTANCE]);
	field->header = nla_get_u32(ref[NFL_FIELD_REF_HEADER]);
	field->field = nla_get_u32(ref[NFL_FIELD_REF_FIELD]);
	field->mask_type = nla_get_u32(ref[NFL_FIELD_REF_MASK_TYPE]);
	field->type = nla_get_u32(ref[NFL_FIELD_REF_TYPE]);

	if (!ref[NFL_FIELD_REF_VALUE])
		return 0;

	switch (field->type) {
	case NFL_FIELD_REF_ATTR_TYPE_U8:
		if (nla_len(ref[NFL_FIELD_REF_VALUE]) < sizeof(u8)) {
			err = -EINVAL;
			break;
		}
		field->value_u8 = nla_get_u8(ref[NFL_FIELD_REF_VALUE]);

		if (!ref[NFL_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NFL_FIELD_REF_MASK]) < sizeof(u8)) {
			err = -EINVAL;
			break;
		}
		field->mask_u8 = nla_get_u8(ref[NFL_FIELD_REF_MASK]);
		break;
	case NFL_FIELD_REF_ATTR_TYPE_U16:
		if (nla_len(ref[NFL_FIELD_REF_VALUE]) < sizeof(u16)) {
			err = -EINVAL;
			break;
		}
		field->value_u16 = nla_get_u16(ref[NFL_FIELD_REF_VALUE]);

		if (!ref[NFL_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NFL_FIELD_REF_MASK]) < sizeof(u16)) {
			err = -EINVAL;
			break;
		}
		field->mask_u16 = nla_get_u16(ref[NFL_FIELD_REF_MASK]);
		break;
	case NFL_FIELD_REF_ATTR_TYPE_U32:
		if (nla_len(ref[NFL_FIELD_REF_VALUE]) < sizeof(u32)) {
			err = -EINVAL;
			break;
		}
		field->value_u32 = nla_get_u32(ref[NFL_FIELD_REF_VALUE]);

		if (!ref[NFL_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NFL_FIELD_REF_MASK]) < sizeof(u32)) {
			err = -EINVAL;
			break;
		}
		field->mask_u32 = nla_get_u32(ref[NFL_FIELD_REF_MASK]);
		break;
	case NFL_FIELD_REF_ATTR_TYPE_U64:
		if (nla_len(ref[NFL_FIELD_REF_VALUE]) < sizeof(u64)) {
			err = -EINVAL;
			break;
		}
		field->value_u64 = nla_get_u64(ref[NFL_FIELD_REF_VALUE]);

		if (!ref[NFL_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NFL_FIELD_REF_MASK]) < sizeof(u64)) {
			err = -EINVAL;
			break;
		}
		field->mask_u64 = nla_get_u64(ref[NFL_FIELD_REF_MASK]);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

static void net_flow_free_actions(struct net_flow_action *actions)
{
	int i;

	if (!actions)
		return;

	for (i = 0; actions[i].args; i++) {
		kfree(actions[i].args->name);
		kfree(actions[i].args);
	}
	kfree(actions);
}

static void net_flow_rule_free(struct net_flow_rule *rule)
{
	if (!rule)
		return;

	kfree(rule->matches);
	net_flow_free_actions(rule->actions);
	kfree(rule);
}

static void net_flow_rule_free_rcu(struct rcu_head *head)
{
	struct net_flow_rule *r = container_of(head, struct net_flow_rule, rcu);

	net_flow_rule_free(r);
}

static const
struct nla_policy net_flow_actarg_policy[NFL_ACTION_ARG_MAX + 1] = {
	[NFL_ACTION_ARG_NAME]  = { .type = NLA_STRING },
	[NFL_ACTION_ARG_TYPE]  = { .type = NLA_U32 },
	[NFL_ACTION_ARG_VALUE] = { .type = NLA_BINARY, .len = sizeof(u64)},
};

static int net_flow_get_actarg(struct net_flow_action_arg *arg,
			       struct nlattr *attr)
{
	struct nlattr *r[NFL_ACTION_ARG_MAX + 1];
	int err;

	err = nla_parse_nested(r, NFL_ACTION_ARG_MAX,
			       attr, net_flow_actarg_policy);
	if (err)
		return err;

	if (!r[NFL_ACTION_ARG_TYPE] ||
	    !r[NFL_ACTION_ARG_VALUE])
		return -EINVAL;

	arg->type = nla_get_u32(r[NFL_ACTION_ARG_TYPE]);
	switch (arg->type) {
	case NFL_ACTION_ARG_TYPE_U8:
		if (nla_len(r[NFL_ACTION_ARG_VALUE]) < sizeof(u8))
			return -EINVAL;
		arg->value_u8 = nla_get_u8(r[NFL_ACTION_ARG_VALUE]);
		break;
	case NFL_ACTION_ARG_TYPE_U16:
		if (nla_len(r[NFL_ACTION_ARG_VALUE]) < sizeof(u16))
			return -EINVAL;
		arg->value_u16 = nla_get_u16(r[NFL_ACTION_ARG_VALUE]);
		break;
	case NFL_ACTION_ARG_TYPE_U32:
		if (nla_len(r[NFL_ACTION_ARG_VALUE]) < sizeof(u32))
			return -EINVAL;
		arg->value_u32 = nla_get_u32(r[NFL_ACTION_ARG_VALUE]);
		break;
	case NFL_ACTION_ARG_TYPE_U64:
		if (nla_len(r[NFL_ACTION_ARG_VALUE]) < sizeof(u64))
			return -EINVAL;
		arg->value_u64 = nla_get_u64(r[NFL_ACTION_ARG_VALUE]);
		break;
	default:
		return -EINVAL;
	}

	if (r[NFL_ACTION_ARG_NAME]) {
		int max = nla_len(r[NFL_ACTION_ARG_NAME]);

		if (max > NFL_MAX_NAME)
			max = NFL_MAX_NAME;

		arg->name = kzalloc(max, GFP_KERNEL);
		if (!arg->name)
			return -ENOMEM;
		nla_strlcpy(arg->name, r[NFL_ACTION_ARG_NAME], max);
	}

	return 0;
}

static int net_flow_get_action(struct net_flow_action *a, struct nlattr *attr)
{
	struct nlattr *act[NFL_ACTION_ATTR_MAX + 1];
	struct nlattr *args;
	int rem;
	int err, count = 0;

	if (nla_type(attr) != NFL_ACTION) {
		pr_warn("%s: expected NFL_ACTION\n", __func__);
		return 0;
	}

	err = nla_parse_nested(act, NFL_ACTION_ATTR_MAX,
			       attr, net_flow_action_policy);
	if (err < 0)
		return err;

	if (!act[NFL_ACTION_ATTR_UID])
		return -EINVAL;

	a->uid = nla_get_u32(act[NFL_ACTION_ATTR_UID]);

	/* Only need to parse signature if it is provided otherwise assume
	 * action does not need any arguments
	 */
	if (!act[NFL_ACTION_ATTR_SIGNATURE])
		return 0;

	nla_for_each_nested(args, act[NFL_ACTION_ATTR_SIGNATURE], rem)
		count++;

	a->args = kcalloc(count + 1,
			  sizeof(struct net_flow_action_arg),
			  GFP_KERNEL);
	count = 0;

	nla_for_each_nested(args, act[NFL_ACTION_ATTR_SIGNATURE], rem) {
		if (nla_type(args) != NFL_ACTION_ARG)
			continue;

		err = net_flow_get_actarg(&a->args[count], args);
		if (err) {
			kfree(a->args);
			a->args = NULL;
			return err;
		}
		count++;
	}
	return 0;
}

static const
struct nla_policy net_flow_rule_policy[NFL_ATTR_MAX + 1] = {
	[NFL_ATTR_TABLE]	= { .type = NLA_U32 },
	[NFL_ATTR_UID]		= { .type = NLA_U32 },
	[NFL_ATTR_PRIORITY]	= { .type = NLA_U32 },
	[NFL_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[NFL_ATTR_ACTIONS]	= { .type = NLA_NESTED },
};

static int net_flow_get_rule(struct net_flow_rule *rule, struct nlattr *attr)
{
	struct nlattr *f[NFL_ATTR_MAX + 1];
	struct nlattr *match, *act;
	int rem, err;
	int count = 0;

	err = nla_parse_nested(f, NFL_ATTR_MAX,
			       attr, net_flow_rule_policy);
	if (err < 0)
		return -EINVAL;

	if (!f[NFL_ATTR_TABLE] || !f[NFL_ATTR_UID] ||
	    !f[NFL_ATTR_PRIORITY])
		return -EINVAL;

	rule->table_id = nla_get_u32(f[NFL_ATTR_TABLE]);
	rule->uid = nla_get_u32(f[NFL_ATTR_UID]);
	rule->priority = nla_get_u32(f[NFL_ATTR_PRIORITY]);

	rule->matches = NULL;
	rule->actions = NULL;

	if (f[NFL_ATTR_MATCHES]) {
		nla_for_each_nested(match, f[NFL_ATTR_MATCHES], rem) {
			if (nla_type(match) == NFL_FIELD_REF)
				count++;
		}

		/* Null terminated list of matches */
		rule->matches = kcalloc(count + 1,
					sizeof(struct net_flow_field_ref),
					GFP_KERNEL);
		if (!rule->matches)
			return -ENOMEM;

		count = 0;
		nla_for_each_nested(match, f[NFL_ATTR_MATCHES], rem) {
			err = net_flow_get_field(&rule->matches[count], match);
			if (err) {
				kfree(rule->matches);
				rule->matches = NULL;
				return err;
			}
			count++;
		}
	}

	if (f[NFL_ATTR_ACTIONS]) {
		count = 0;
		nla_for_each_nested(act, f[NFL_ATTR_ACTIONS], rem) {
			if (nla_type(act) == NFL_ACTION)
				count++;
		}

		/* Null terminated list of actions */
		rule->actions = kcalloc(count + 1,
					sizeof(struct net_flow_action),
					GFP_KERNEL);
		if (!rule->actions) {
			kfree(rule->matches);
			rule->matches = NULL;
			return -ENOMEM;
		}

		count = 0;
		nla_for_each_nested(act, f[NFL_ATTR_ACTIONS], rem) {
			err = net_flow_get_action(&rule->actions[count], act);
			if (err) {
				kfree(rule->matches);
				rule->matches = NULL;
				net_flow_free_actions(rule->actions);
				rule->actions = NULL;
				return err;
			}
			count++;
		}
	}

	return 0;
}

#define NFL_TABLE_ELEM_HINT 10
int net_flow_init_cache(struct net_flow_tbl *table)
{
	struct rhashtable_params params = {
		.nelem_hint = NFL_TABLE_ELEM_HINT,
		.head_offset = offsetof(struct net_flow_rule, node),
		.key_offset = offsetof(struct net_flow_rule, uid),
		.key_len = sizeof(__u32),
		.hashfn = jhash,
	};

	return rhashtable_init(&table->cache, &params);
}
EXPORT_SYMBOL(net_flow_init_cache);

void net_flow_destroy_cache(struct net_flow_tbl *table)
{
	struct rhashtable *cache = &table->cache;
	const struct bucket_table *tbl;
	struct net_flow_rule *he;
	struct rhash_head *pos, *next;
	unsigned int i;

	/* Stop an eventual async resizing */
	mutex_lock(&cache->mutex);

	tbl = rht_dereference(cache->tbl, cache);
	for (i = 0; i < tbl->size; i++) {
		rht_for_each_entry_safe(he, pos, next, tbl, i, node) {
			rhashtable_remove_fast(&table->cache, &he->node,
					       tsk_rht_params);
			call_rcu(&he->rcu, net_flow_rule_free_rcu);
		}
	}

	mutex_unlock(&cache->mutex);
	rhashtable_destroy(cache);
}
EXPORT_SYMBOL(net_flow_destroy_cache);

static void net_flow_add_rule_cache(struct net_flow_tbl *table,
				    struct net_flow_rule *this)
{
	rhashtable_insert_fast(&table->cache, &this->node, tsk_rht_params);
}

static int net_flow_del_rule_cache(struct net_flow_tbl *table,
				   struct net_flow_rule *this)
{
	struct net_flow_rule *he;

	he = rhashtable_lookup_fast(&table->cache, &this->uid, tsk_rht_params);
	if (he) {
		rhashtable_remove_fast(&table->cache, &he->node,
				       tsk_rht_params);
		synchronize_rcu();
		net_flow_rule_free(he);
		return 0;
	}

	return -EEXIST;
}

static int net_flow_is_valid_action(struct net_flow_action *a, int *actions)
{
	int i;

	if (a->uid >= __ACTION_MAX)
		return -EINVAL;

	for (i = 0; actions[i]; i++) {
		if (actions[i] == a->uid)
			return 0;
	}
	return -EINVAL;
}

static int net_flow_is_valid_match(struct net_flow_field_ref *f,
				   struct net_flow_field_ref *fields)
{
	int i;

	for (i = 0; fields[i].header; i++) {
		if (f->header == fields[i].header &&
		    f->field == fields[i].field)
			return 0;
	}

	return -EINVAL;
}

static int net_flow_is_valid_rule(struct net_flow_tbl *table,
				  struct net_flow_rule *flow)
{
	struct net_flow_field_ref *fields = table->matches;
	int *actions = table->actions;
	int i, err;

	/* Only accept rules with matches AND actions it does not seem
	 * correct to allow a match without actions or action chains
	 * that will never be hit
	 */
	if (!flow->actions || !flow->matches)
		return -EINVAL;

	for (i = 0; flow->actions[i].uid; i++) {
		err = net_flow_is_valid_action(&flow->actions[i], actions);
		if (err)
			return -EINVAL;
	}

	for (i = 0; flow->matches[i].header; i++) {
		err = net_flow_is_valid_match(&flow->matches[i], fields);
		if (err)
			return -EINVAL;
	}

	return 0;
}

static int net_flow_table_cmd_flows(struct sk_buff *recv_skb,
				    struct genl_info *info)
{
	int rem, err_handle = NFL_FLOWS_ERROR_ABORT;
	struct net_flow_rule *this = NULL;
	struct sk_buff *skb = NULL;
	struct genlmsghdr *hdr;
	struct net_device *dev;
	struct nlattr *flow, *flows;
	int cmd = info->genlhdr->cmd;
	int err = -EOPNOTSUPP;

	dev = net_flow_get_dev(info);
	if (!dev)
		return -EINVAL;

	switch (cmd) {
	case NFL_TABLE_CMD_SET_FLOWS:
		if (!dev->netdev_ops->ndo_flow_set_rule)
			goto out;
		break;
	case NFL_TABLE_CMD_DEL_FLOWS:
		if (!dev->netdev_ops->ndo_flow_del_rule)
			goto out;
		break;
	default:
		goto out;
	}

	if (!info->attrs[NFL_IDENTIFIER_TYPE] ||
	    !info->attrs[NFL_IDENTIFIER] ||
	    !info->attrs[NFL_FLOWS]) {
		err = -EINVAL;
		goto out;
	}

	if (info->attrs[NFL_FLOWS_ERROR])
		err_handle = nla_get_u32(info->attrs[NFL_FLOWS_ERROR]);

	net_flow_lock();
	nla_for_each_nested(flow, info->attrs[NFL_FLOWS], rem) {
		struct net_flow_tbl *table;

		if (nla_type(flow) != NFL_FLOW)
			continue;

		this = kzalloc(sizeof(*this), GFP_KERNEL);
		if (!this) {
			err = -ENOMEM;
			goto skip;
		}

		/* If userspace is passing invalid messages so that we can not
		 * even build correct flow structures abort with an error. And
		 * do not try to proceed regardless of error structure.
		 */
		err = net_flow_get_rule(this, flow);
		if (err)
			goto out_locked;

		rcu_read_lock();
		table = net_flow_get_table(dev, this->table_id);
		if (!table) {
			rcu_read_unlock();
			err = -EINVAL;
			goto skip;
		}

		switch (cmd) {
		case NFL_TABLE_CMD_SET_FLOWS:
			err = net_flow_is_valid_rule(table, this);
			if (err)
				break;
			err = dev->netdev_ops->ndo_flow_set_rule(dev, this);
			if (!err)
				net_flow_add_rule_cache(table, this);
			break;
		case NFL_TABLE_CMD_DEL_FLOWS:
			err = dev->netdev_ops->ndo_flow_del_rule(dev, this);
			if (!err)
				err = net_flow_del_rule_cache(table, this);
			break;
		default:
			err = -EOPNOTSUPP;
			break;
		}
		rcu_read_unlock();

skip:
		if (err && err_handle != NFL_FLOWS_ERROR_CONTINUE) {
			if (!skb) {
				skb = net_flow_start_errmsg(dev, &hdr,
							    info->snd_portid,
							    info->snd_seq,
							    cmd);
				if (IS_ERR(skb)) {
					err = PTR_ERR(skb);
					goto out_locked;
				}

				flows = nla_nest_start(skb, NFL_FLOWS);
				if (!flows) {
					err = -EMSGSIZE;
					goto out_locked;
				}
			}

			net_flow_put_rule(skb, this);
		}

		if (err && err_handle == NFL_FLOWS_ERROR_ABORT)
			goto out_locked;
	}
	net_flow_unlock();
	dev_put(dev);

	if (skb) {
		nla_nest_end(skb, flows);
		genlmsg_end(skb, hdr);
		return genlmsg_reply(skb, info);
	}
	return 0;

out_locked:
	net_flow_unlock();
out:
	net_flow_rule_free(this);
	nlmsg_free(skb);
	dev_put(dev);
	return err;
}

static const struct nla_policy net_flow_cmd_policy[NFL_MAX + 1] = {
	[NFL_IDENTIFIER_TYPE]	= {.type = NLA_U32, },
	[NFL_IDENTIFIER]	= {.type = NLA_U32, },
	[NFL_TABLES]		= {.type = NLA_NESTED, },
	[NFL_HEADERS]		= {.type = NLA_NESTED, },
	[NFL_ACTIONS]		= {.type = NLA_NESTED, },
	[NFL_HEADER_GRAPH]	= {.type = NLA_NESTED, },
	[NFL_TABLE_GRAPH]	= {.type = NLA_NESTED, },
};

static const struct genl_ops net_flow_table_nl_ops[] = {
	{
		.cmd = NFL_TABLE_CMD_GET_TABLES,
		.doit = net_flow_cmd_get_tables,
		.policy = net_flow_cmd_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NFL_TABLE_CMD_GET_HEADERS,
		.doit = net_flow_cmd_get_headers,
		.policy = net_flow_cmd_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NFL_TABLE_CMD_GET_ACTIONS,
		.doit = net_flow_cmd_get_actions,
		.policy = net_flow_cmd_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NFL_TABLE_CMD_GET_HDR_GRAPH,
		.doit = net_flow_cmd_get_header_graph,
		.policy = net_flow_cmd_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NFL_TABLE_CMD_GET_TABLE_GRAPH,
		.doit = net_flow_cmd_get_table_graph,
		.policy = net_flow_cmd_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NFL_TABLE_CMD_GET_FLOWS,
		.doit = net_flow_table_cmd_get_flows,
		.policy = net_flow_cmd_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NFL_TABLE_CMD_SET_FLOWS,
		.doit = net_flow_table_cmd_flows,
		.policy = net_flow_cmd_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NFL_TABLE_CMD_DEL_FLOWS,
		.doit = net_flow_table_cmd_flows,
		.policy = net_flow_cmd_policy,
		.flags = GENL_ADMIN_PERM,
	},
};

static int net_flow_is_valid_instance(__u32 instance,
				      struct net_flow_hdr_node **graph)
{
	int i;

	for (i = 0; graph[i]; i++) {
		if (instance == graph[i]->uid)
			return 0;
	}

	return -EINVAL;
}

static int net_flow_is_valid_tbl_act(struct net_flow_action **actions,
				     __u32 action)
{
	int i;

	for (i = 0; actions[i]->uid; i++) {
		if (actions[i]->uid == action)
			return 0;
	}
	return -EINVAL;
}

/* net_flow_validate_model is used to validate that the action set provided
 * by the driver only contains well-formed actions. Well-formed actoins are
 * actions that are either (a) pre-defined by if_flow_common.h or (b) are
 * set_field actions that map to a field that is defined in the model.
 *
 * This also does a check on the tables exported to ensure the actions and
 * headers used in the tables are defined by the model. This check ensures
 * that when rules are inserted/removed the rule validation code correctly
 * verifies the rules map to valid fields/actions.
 */
static int net_flow_validate_model(struct net_flow_switch_model *model)
{
	int err, i, j;

	for (i = 0; model->actions[i]; i++) {
		struct net_flow_action *a = model->actions[i];

		/* If there is an instance value this is a a set_field action
		 * and the instance needs to be checked against the hdr_graph
		 */
		if (a->instance) {
			err = net_flow_is_valid_instance(a->instance,
							 model->hdr_graph);
			if (err)
				return err;

			if (a->uid < __ACTION_MAX)
				return -EINVAL;
		/* Otherwise it is a pre-defined action and must be defined
		 * in the common include files
		 */
		} else if (a->uid >= __ACTION_MAX) {
			return -EINVAL;
		}
	}

	for (i = 0; model->tbls[i]; i++) {
		struct net_flow_field_ref *matches = model->tbls[i]->matches;
		__u32 *actions = model->tbls[i]->actions;

		for (j = 0; matches[j].instance; j++) {
			err = net_flow_is_valid_instance(matches[j].instance,
							 model->hdr_graph);

			if (err)
				return -EINVAL;
		}

		for (j = 0; actions[j]; j++) {
			err = net_flow_is_valid_tbl_act(model->actions,
							actions[j]);

			if (err)
				return -EINVAL;
		}
	}

	return 0;
}

int register_flow_table(struct net_device *dev,
			struct net_flow_switch_model *model)
{
	struct list_head *head = &net_flow_models;
	struct net_flow_model *m;
	int err;

	err = net_flow_validate_model(model);
	if (err)
		return -EINVAL;

	spin_lock(&net_flow_models_lock);
	list_for_each_entry(m, head, list) {
		int err = netdev_switch_parent_id_eq(dev, m->dev);

		if (!err) {
			spin_unlock(&net_flow_models_lock);
			return -EEXIST;
		}
	}

	m = kmalloc(sizeof(*m), GFP_KERNEL);
	if (!m) {
		spin_unlock(&net_flow_models_lock);
		return -ENOMEM;
	}

	m->dev = dev;
	m->model = model;
	list_add_rcu(&m->list, head);
	spin_unlock(&net_flow_models_lock);
	return 0;
}
EXPORT_SYMBOL(register_flow_table);

int unregister_flow_table(struct net_device *dev)
{
	struct list_head *head = &net_flow_models;
	struct net_flow_model *m;

	spin_lock(&net_flow_models_lock);
	list_for_each_entry(m, head, list) {
		if (m->dev->ifindex == dev->ifindex) {
			list_del_rcu(&m->list);
			spin_unlock(&net_flow_models_lock);
			synchronize_rcu();
			kfree(m);
			return 0;
		}
	}
	spin_unlock(&net_flow_models_lock);
	return -EINVAL;
}
EXPORT_SYMBOL(unregister_flow_table);

static int __init net_flow_nl_module_init(void)
{
	INIT_LIST_HEAD(&net_flow_models);
	return genl_register_family_with_ops(&net_flow_nl_family,
					     net_flow_table_nl_ops);
}

static void net_flow_nl_module_fini(void)
{
	genl_unregister_family(&net_flow_nl_family);
}

module_init(net_flow_nl_module_init);
module_exit(net_flow_nl_module_fini);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("John Fastabend <john.r.fastabend@intel.com>");
MODULE_DESCRIPTION("Netlink interface to Flow Tables (Net Flow Netlink)");
MODULE_ALIAS_GENL_FAMILY(NFL_GENL_NAME);

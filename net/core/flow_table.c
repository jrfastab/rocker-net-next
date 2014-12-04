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
#include <linux/if_flow.h>
#include <linux/if_bridge.h>
#include <linux/types.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>
#include <linux/module.h>
#include <net/switchdev.h>

struct net_flow_model {
	struct list_head list;
	struct net_device *dev;
	struct net_flow_switch_model *model;
};

static DEFINE_SPINLOCK(net_flow_models_lock);
static struct list_head __rcu net_flow_models __read_mostly;

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
};

int register_flow_table(struct net_device *dev,
			struct net_flow_switch_model *model)
{
	struct list_head *head = &net_flow_models;
	struct net_flow_model *m;

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

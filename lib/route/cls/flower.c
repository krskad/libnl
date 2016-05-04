#include <netlink-private/netlink.h>
#include <netlink-private/tc.h>
#include <netlink-private/route/tc-api.h>

#include <netlink/route/cls/flower.h>

#define FLOWER_ATTR_CLASSID		0x0001
#define FLOWER_ATTR_INDEV		0x0002
#define FLOWER_ATTR_ACTION		0x0004
#define FLOWER_ATTR_SRC_MAC		0x0008
#define FLOWER_ATTR_DST_MAC		0x0010
#define FLOWER_ATTR_ETH_TYPE	0x0020
#define FLOWER_ATTR_IP_PROTO	0x0040
#define FLOWER_ATTR_IPV4_SRC	0x0080
#define FLOWER_ATTR_IPV4_DST	0x0100
#define FLOWER_ATTR_IPV6_SRC	0x0200
#define FLOWER_ATTR_IPV6_DST	0x0400
#define FLOWER_ATTR_TCP_SRC		0x0800
#define FLOWER_ATTR_TCP_DST		0x1000
#define FLOWER_ATTR_UDP_SRC		0x2000
#define FLOWER_ATTR_UDP_DST		0x4000

int rtnl_flower_get_classid(struct rtnl_cls *cls, uint32_t *classid)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data_peek(TC_CAST(cls))))
		return -NLE_INVAL;

	if (!(f->cfl_mask & FLOWER_ATTR_CLASSID))
		return -NLE_INVAL;

	*classid = f->cfl_classid;
	return 0;
}

int rtnl_flower_set_classid(struct rtnl_cls *cls, uint32_t classid)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_classid = classid;
	f->cfl_mask |= FLOWER_ATTR_CLASSID;

	return 0;
}

// TODO: should this function be here?
int rtnl_flower_set_indev(struct rtnl_cls *cls, const char *indev)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	strcpy(f->cfl_indev, indev);
	f->cfl_mask |= FLOWER_ATTR_INDEV;

	return 0;
}

int rtnl_flower_add_action(struct rtnl_cls *cls, struct rtnl_act *act)
{
	struct rtnl_flower *f;

	if (!act)
		return 0;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_mask |= FLOWER_ATTR_ACTION;
	/* In case user frees it */
	rtnl_act_get(act);
	return rtnl_act_append(&f->cfl_act, act);
}

int rtnl_flower_del_action(struct rtnl_cls *cls, struct rtnl_act *act)
{
	struct rtnl_flower *f;
	int ret;

	if (!act)
		return 0;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	if (!(f->cfl_mask & FLOWER_ATTR_ACTION))
		return -NLE_INVAL;

	ret = rtnl_act_remove(&f->cfl_act, act);
	if (ret)
		return ret;

	if (!f->cfl_act)
		f->cfl_mask &= ~FLOWER_ATTR_ACTION;
	rtnl_act_put(act);
	return 0;
}

int rtnl_flower_set_src_mac(struct rtnl_cls *cls, char* addr, char* addr_mask)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_eth_src = nl_data_alloc(addr, 6);

	f->cfl_key_eth_src_mask = nl_data_alloc(addr_mask, 6);

	f->cfl_mask |= FLOWER_ATTR_SRC_MAC;
	return 0;
}


int rtnl_flower_set_dst_mac(struct rtnl_cls *cls, char* addr, char* addr_mask)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_eth_dst = nl_data_alloc(addr, 6);

	f->cfl_key_eth_dst_mask = nl_data_alloc(addr_mask, 6);

	f->cfl_mask |= FLOWER_ATTR_DST_MAC;
	return 0;
}

int rtnl_flower_set_eth_type(struct rtnl_cls *cls, uint16_t eth_type)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_eth_type = eth_type;

	f->cfl_mask |= FLOWER_ATTR_ETH_TYPE;
	return 0;
}

int rtnl_flower_set_ip_proto(struct rtnl_cls *cls, uint8_t ip_proto)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_ip_proto = ip_proto;

	f->cfl_mask |= FLOWER_ATTR_IP_PROTO;
	return 0;
}

int rtnl_flower_set_ipv4_src(struct rtnl_cls *cls, uint32_t src, uint32_t src_mask)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_ipv4_src = src;

	f->cfl_key_ipv4_src_mask = src_mask;

	f->cfl_mask |= FLOWER_ATTR_IPV4_SRC;
	return 0;
}

int rtnl_flower_set_ipv4_dst(struct rtnl_cls *cls, uint32_t dst, uint32_t dst_mask)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_ipv4_dst = dst;

	f->cfl_key_ipv4_dst_mask = dst_mask;

	f->cfl_mask |= FLOWER_ATTR_IPV4_DST;
	return 0;
}

int rtnl_flower_set_ipv6_src(struct rtnl_cls *cls,
		const struct in6_addr *addr, const struct in6_addr *addr_mask)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_ipv6_src = nl_data_alloc(addr, sizeof(*addr));

	f->cfl_key_ipv6_src_mask = nl_data_alloc(addr_mask, sizeof(*addr_mask));

	f->cfl_mask |= FLOWER_ATTR_IPV6_SRC;
	return 0;
}

int rtnl_flower_set_ipv6_dst(struct rtnl_cls *cls,
		const struct in6_addr *addr, const struct in6_addr *addr_mask)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_ipv6_dst = nl_data_alloc(addr, sizeof(*addr));

	f->cfl_key_ipv6_dst_mask = nl_data_alloc(addr_mask, sizeof(*addr_mask));

	f->cfl_mask |= FLOWER_ATTR_IPV6_DST;
	return 0;
}

int rtnl_flower_set_tcp_src(struct rtnl_cls *cls, uint16_t port)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_tcp_src = port;

	f->cfl_mask |= FLOWER_ATTR_TCP_SRC;
	return 0;
}

int rtnl_flower_set_tcp_dst(struct rtnl_cls *cls, uint16_t port)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_tcp_dst = port;

	f->cfl_mask |= FLOWER_ATTR_TCP_DST;
	return 0;
}

int rtnl_flower_set_udp_src(struct rtnl_cls *cls, uint16_t port)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_udp_src = port;

	f->cfl_mask |= FLOWER_ATTR_UDP_SRC;
	return 0;
}

int rtnl_flower_set_udp_dst(struct rtnl_cls *cls, uint16_t port)
{
	struct rtnl_flower *f;

	if (!(f = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

	f->cfl_key_udp_dst = port;

	f->cfl_mask |= FLOWER_ATTR_UDP_DST;
	return 0;
}

static struct nla_policy flower_policy[TCA_FLOWER_MAX + 1] = {
	[TCA_FLOWER_UNSPEC]		= { .type = NLA_UNSPEC },
	[TCA_FLOWER_CLASSID]		= { .type = NLA_U32 },
	[TCA_FLOWER_INDEV]		= { .type = NLA_STRING,
					    .maxlen = IFNAMSIZ },
	[TCA_FLOWER_KEY_ETH_DST]	= { .minlen = ETH_ALEN },
	[TCA_FLOWER_KEY_ETH_DST_MASK]	= { .minlen = ETH_ALEN },
	[TCA_FLOWER_KEY_ETH_SRC]	= { .minlen = ETH_ALEN },
	[TCA_FLOWER_KEY_ETH_SRC_MASK]	= { .minlen = ETH_ALEN },
	[TCA_FLOWER_KEY_ETH_TYPE]	= { .type = NLA_U16 },
	[TCA_FLOWER_KEY_IP_PROTO]	= { .type = NLA_U8 },
	[TCA_FLOWER_KEY_IPV4_SRC]	= { .type = NLA_U32 },
	[TCA_FLOWER_KEY_IPV4_SRC_MASK]	= { .type = NLA_U32 },
	[TCA_FLOWER_KEY_IPV4_DST]	= { .type = NLA_U32 },
	[TCA_FLOWER_KEY_IPV4_DST_MASK]	= { .type = NLA_U32 },
	[TCA_FLOWER_KEY_IPV6_SRC]	= { .minlen = sizeof(struct in6_addr) },
	[TCA_FLOWER_KEY_IPV6_SRC_MASK]	= { .minlen = sizeof(struct in6_addr) },
	[TCA_FLOWER_KEY_IPV6_DST]	= { .minlen = sizeof(struct in6_addr) },
	[TCA_FLOWER_KEY_IPV6_DST_MASK]	= { .minlen = sizeof(struct in6_addr) },
	[TCA_FLOWER_KEY_TCP_SRC]	= { .type = NLA_U16 },
	[TCA_FLOWER_KEY_TCP_DST]	= { .type = NLA_U16 },
	[TCA_FLOWER_KEY_UDP_SRC]	= { .type = NLA_U16 },
	[TCA_FLOWER_KEY_UDP_DST]	= { .type = NLA_U16 },
};

static int flower_msg_parser(struct rtnl_tc *tc, void *data)
{
	printf("DBG: 'flower_msg_parser' called\n");
	struct rtnl_flower *f = data;
	struct nlattr *tb[TCA_FLOWER_MAX + 1];
	int err;

	err = tca_parse(tb, TCA_FLOWER_MAX, tc, flower_policy);
	if (err < 0)
		return err;

	if (tb[TCA_FLOWER_CLASSID]) {
		f->cfl_classid = nla_get_u32(tb[TCA_FLOWER_CLASSID]);
		f->cfl_mask |= FLOWER_ATTR_CLASSID;
	}

	if (tb[TCA_FLOWER_INDEV]) {
		nla_strlcpy(f->cfl_indev, tb[TCA_FLOWER_INDEV], IFNAMSIZ);
		f->cfl_mask |= FLOWER_ATTR_INDEV;
	}

	if (tb[TCA_FLOWER_ACT]) {
		err = rtnl_act_parse(&f->cfl_act, tb[TCA_FLOWER_ACT]);
		if (err)
			return err;
		f->cfl_mask |= FLOWER_ATTR_ACTION;
	}

	if (tb[TCA_FLOWER_KEY_ETH_SRC]) {
		f->cfl_key_eth_src = nl_data_alloc_attr(tb[TCA_FLOWER_KEY_ETH_SRC]);
		if (!f->cfl_key_eth_src)
			goto errout_nomem;
		if (tb[TCA_FLOWER_KEY_ETH_SRC_MASK]) {
			f->cfl_key_eth_src_mask = nl_data_alloc_attr(tb[TCA_FLOWER_KEY_ETH_SRC_MASK]);
			if (!f->cfl_key_eth_src_mask)
				goto errout_nomem;
		}
		f->cfl_mask |= FLOWER_ATTR_SRC_MAC;
	}

	if (tb[TCA_FLOWER_KEY_ETH_DST]) {
		f->cfl_key_eth_dst = nl_data_alloc_attr(tb[TCA_FLOWER_KEY_ETH_DST]);
		if (!f->cfl_key_eth_dst)
			goto errout_nomem;
		if (tb[TCA_FLOWER_KEY_ETH_DST_MASK]) {
			f->cfl_key_eth_dst_mask = nl_data_alloc_attr(tb[TCA_FLOWER_KEY_ETH_DST_MASK]);
			if (!f->cfl_key_eth_dst_mask)
				goto errout_nomem;
		}
		f->cfl_mask |= FLOWER_ATTR_DST_MAC;
	}

	if (tb[TCA_FLOWER_KEY_ETH_TYPE]) {
		f->cfl_key_eth_type = nla_get_u16(tb[TCA_FLOWER_KEY_ETH_TYPE]);
		f->cfl_mask |= FLOWER_ATTR_ETH_TYPE;
	}

	if (tb[TCA_FLOWER_KEY_IP_PROTO]) {
		f->cfl_key_ip_proto = nla_get_u8(tb[TCA_FLOWER_KEY_IP_PROTO]);
		f->cfl_mask |= FLOWER_ATTR_IP_PROTO;
	}

	if (tb[TCA_FLOWER_KEY_IPV4_SRC]) {
		f->cfl_key_ipv4_src = nla_get_u32(tb[TCA_FLOWER_KEY_IPV4_SRC]);
		if (tb[TCA_FLOWER_KEY_IPV4_SRC_MASK]) {
			f->cfl_key_ipv4_src_mask = nla_get_u32(tb[TCA_FLOWER_KEY_IPV4_SRC_MASK]);
		}
		f->cfl_mask |= FLOWER_ATTR_IPV4_SRC;
	}

	if (tb[TCA_FLOWER_KEY_IPV4_DST]) {
		f->cfl_key_ipv4_dst = nla_get_u32(tb[TCA_FLOWER_KEY_IPV4_DST]);
		if (tb[TCA_FLOWER_KEY_IPV4_DST_MASK]) {
			f->cfl_key_ipv4_dst_mask = nla_get_u32(tb[TCA_FLOWER_KEY_IPV4_DST_MASK]);
		}
		f->cfl_mask |= FLOWER_ATTR_IPV4_DST;
	}

	if (tb[TCA_FLOWER_KEY_IPV6_SRC]) {
		f->cfl_key_ipv6_src = nl_data_alloc_attr(tb[TCA_FLOWER_KEY_IPV6_SRC]);
		if (tb[TCA_FLOWER_KEY_IPV6_SRC_MASK]) {
			f->cfl_key_ipv6_src_mask = nl_data_alloc_attr(tb[TCA_FLOWER_KEY_IPV6_SRC_MASK]);
		}
		f->cfl_mask |= FLOWER_ATTR_IPV6_SRC;
	}

	if (tb[TCA_FLOWER_KEY_IPV6_DST]) {
		f->cfl_key_ipv6_dst = nl_data_alloc_attr(tb[TCA_FLOWER_KEY_IPV6_DST]);
		if (tb[TCA_FLOWER_KEY_IPV6_DST_MASK]) {
			f->cfl_key_ipv6_dst_mask = nl_data_alloc_attr(tb[TCA_FLOWER_KEY_IPV6_DST_MASK]);
		}
		f->cfl_mask |= FLOWER_ATTR_IPV6_DST;
	}
	
	if (tb[TCA_FLOWER_KEY_TCP_SRC]) {
		f->cfl_key_tcp_src = nla_get_u16(tb[TCA_FLOWER_KEY_TCP_SRC]);
		f->cfl_mask |= FLOWER_ATTR_TCP_SRC;
	}

	if (tb[TCA_FLOWER_KEY_TCP_DST]) {
		f->cfl_key_tcp_dst = nla_get_u16(tb[TCA_FLOWER_KEY_TCP_DST]);
		f->cfl_mask |= FLOWER_ATTR_TCP_DST;
	}

	if (tb[TCA_FLOWER_KEY_UDP_SRC]) {
		f->cfl_key_udp_src = nla_get_u16(tb[TCA_FLOWER_KEY_UDP_SRC]);
		f->cfl_mask |= FLOWER_ATTR_UDP_SRC;
	}

	if (tb[TCA_FLOWER_KEY_UDP_DST]) {
		f->cfl_key_udp_dst = nla_get_u16(tb[TCA_FLOWER_KEY_UDP_DST]);
		f->cfl_mask |= FLOWER_ATTR_UDP_DST;
	}

	return 0;

errout_nomem:
	err = -NLE_NOMEM;
// errout:
	return err;
}

static void flower_free_data(struct rtnl_tc *tc, void *data)
{
	printf("DBG: 'flower_free_data' called\n");

	struct rtnl_flower *f = data;

	if (f->cfl_act)
		rtnl_act_put_all(&f->cfl_act);

	nl_data_free(f->cfl_key_eth_dst);
	nl_data_free(f->cfl_key_eth_dst_mask);
	nl_data_free(f->cfl_key_eth_src);
	nl_data_free(f->cfl_key_eth_src_mask);
}

static int flower_clone(void *_dst, void *_src)
{
	printf("DBG: 'flower_clone' called\n");
	struct rtnl_flower *dst = _dst, *src = _src;

	if (src->cfl_act) {
		if (!(dst->cfl_act = rtnl_act_alloc()))
			return -NLE_NOMEM;

		memcpy(dst->cfl_act, src->cfl_act, sizeof(struct rtnl_act));
	}

	if (src->cfl_key_eth_dst &&
			!(dst->cfl_key_eth_dst  = nl_data_clone(src->cfl_key_eth_dst)))
		return -NLE_NOMEM;

	if (src->cfl_key_eth_dst_mask &&
			!(dst->cfl_key_eth_dst_mask  = nl_data_clone(src->cfl_key_eth_dst_mask)))
		return -NLE_NOMEM;

	if (src->cfl_key_eth_src &&
			!(dst->cfl_key_eth_src  = nl_data_clone(src->cfl_key_eth_src)))
		return -NLE_NOMEM;

	if (src->cfl_key_eth_src_mask &&
			!(dst->cfl_key_eth_src_mask  = nl_data_clone(src->cfl_key_eth_src_mask)))
		return -NLE_NOMEM;

	return 0;
}


static int flower_msg_fill(struct rtnl_tc *tc, void *data, struct nl_msg *msg)
{
	printf("DBG: 'flower_msg_fill' called\n");
	struct rtnl_flower *f = data;

	if (!f) return 0;

	printf("DBG: mask = %d\n", f->cfl_mask);

	if (f->cfl_mask & FLOWER_ATTR_CLASSID) {
		NLA_PUT_U32(msg, TCA_FLOWER_CLASSID, f->cfl_classid);
	}

	if (f->cfl_mask & FLOWER_ATTR_INDEV) {
		NLA_PUT_STRING(msg, TCA_FLOWER_INDEV, f->cfl_indev);
	}

	if (f->cfl_mask & FLOWER_ATTR_ACTION) {
		int err;

		err = rtnl_act_fill(msg, TCA_FLOWER_ACT, f->cfl_act);
		if (err)
			return err;
	}

	if (f->cfl_mask & FLOWER_ATTR_SRC_MAC) {
		NLA_PUT_DATA(msg, TCA_FLOWER_KEY_ETH_SRC, f->cfl_key_eth_src);
		NLA_PUT_DATA(msg, TCA_FLOWER_KEY_ETH_SRC_MASK, f->cfl_key_eth_src_mask);
	}

	if (f->cfl_mask & FLOWER_ATTR_DST_MAC) {
		NLA_PUT_DATA(msg, TCA_FLOWER_KEY_ETH_DST, f->cfl_key_eth_dst);
		NLA_PUT_DATA(msg, TCA_FLOWER_KEY_ETH_DST_MASK, f->cfl_key_eth_dst_mask);
	}

	if (f->cfl_mask & FLOWER_ATTR_ETH_TYPE) {
		NLA_PUT_U32(msg, TCA_FLOWER_KEY_ETH_TYPE, f->cfl_key_eth_type);
	}

	if (f->cfl_mask & FLOWER_ATTR_IP_PROTO) {
		NLA_PUT_U32(msg, TCA_FLOWER_KEY_ETH_TYPE, f->cfl_key_eth_type);
	}

	if (f->cfl_mask & FLOWER_ATTR_IPV4_SRC) {
		NLA_PUT_U32(msg, TCA_FLOWER_KEY_IPV4_SRC, f->cfl_key_ipv4_src);
		NLA_PUT_U32(msg, TCA_FLOWER_KEY_IPV4_SRC_MASK, f->cfl_key_ipv4_src_mask);
	}
	
	if (f->cfl_mask & FLOWER_ATTR_IPV4_DST) {
		NLA_PUT_U32(msg, TCA_FLOWER_KEY_IPV4_DST, f->cfl_key_ipv4_dst);
		NLA_PUT_U32(msg, TCA_FLOWER_KEY_IPV4_DST_MASK, f->cfl_key_ipv4_dst_mask);
	}

	if (f->cfl_mask & FLOWER_ATTR_IPV6_SRC) {
		NLA_PUT_DATA(msg, TCA_FLOWER_KEY_IPV6_SRC, f->cfl_key_ipv6_src);
		NLA_PUT_DATA(msg, TCA_FLOWER_KEY_IPV6_SRC_MASK, f->cfl_key_ipv6_src_mask);
	}

	if (f->cfl_mask & FLOWER_ATTR_IPV6_DST) {
		NLA_PUT_DATA(msg, TCA_FLOWER_KEY_IPV6_DST, f->cfl_key_ipv6_dst);
		NLA_PUT_DATA(msg, TCA_FLOWER_KEY_IPV6_DST_MASK, f->cfl_key_ipv6_dst_mask);
	}

	if (f->cfl_mask & FLOWER_ATTR_TCP_SRC) {
		NLA_PUT_U16(msg, TCA_FLOWER_KEY_TCP_SRC, f->cfl_key_tcp_src);
	}

	if (f->cfl_mask & FLOWER_ATTR_TCP_DST) {
		NLA_PUT_U16(msg, TCA_FLOWER_KEY_TCP_DST, f->cfl_key_tcp_dst);
	}

	if (f->cfl_mask & FLOWER_ATTR_UDP_SRC) {
		NLA_PUT_U16(msg, TCA_FLOWER_KEY_UDP_SRC, f->cfl_key_udp_src);
	}

	if (f->cfl_mask & FLOWER_ATTR_UDP_DST) {
		NLA_PUT_U16(msg, TCA_FLOWER_KEY_UDP_DST, f->cfl_key_udp_dst);
	}

	return 0;

nla_put_failure:
	return -NLE_NOMEM;
}

static void flower_dump_line(struct rtnl_tc *tc, void *data,
			  struct nl_dump_params *p)
{
	printf("DBG: 'flower_dump_line' called\n");
	// TODO
}

static void flower_dump_details(struct rtnl_tc *tc, void *data,
			     struct nl_dump_params *p)
{
	printf("DBG: 'flower_dump_details' called\n");
	// TODO
}

static void flower_dump_stats(struct rtnl_tc *tc, void *data,
			   struct nl_dump_params *p)
{
	printf("DBG: 'flower_dump_stats' called\n");
	// TODO
}

/** @} */

static struct rtnl_tc_ops flower_ops = {
	.to_kind		= "flower",
	.to_type		= RTNL_TC_TYPE_CLS,
	.to_size		= sizeof(struct rtnl_flower),
	.to_msg_parser		= flower_msg_parser,
	.to_free_data		= flower_free_data,
	.to_clone		= flower_clone,
	.to_msg_fill		= flower_msg_fill,
	.to_dump = {
	    [NL_DUMP_LINE]	= flower_dump_line,
	    [NL_DUMP_DETAILS]	= flower_dump_details,
	    [NL_DUMP_STATS]	= flower_dump_stats,
	},
};

static void __init flower_init(void)
{
	rtnl_tc_register(&flower_ops);
}

static void __exit flower_exit(void)
{
	rtnl_tc_unregister(&flower_ops);
}

/** @} */

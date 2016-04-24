#include <netlink-private/netlink.h>
#include <netlink-private/tc.h>
#include <netlink-private/route/tc-api.h>

#include <netlink/route/cls/flower.h>

#define FLOWER_ATTR_SRC_MAC 0x001

int rtnl_flower_set_src_mac(struct rtnl_cls *cls, char* addr)
{
    struct rtnl_flower *u;
    // int err;

	if (!(u = rtnl_tc_data(TC_CAST(cls))))
		return -NLE_NOMEM;

    // alloc nl_data and fill mac address
	u->cf_src_mac = nl_data_alloc(addr, 6);

    // set mask
    u->cf_mask = FLOWER_ATTR_SRC_MAC;
    return 0;
}


static int flower_msg_parser(struct rtnl_tc *tc, void *data)
{
    printf("DBG: 'flower_msg_parser' called\n");
    return 0;
    // TODO
}

static void flower_free_data(struct rtnl_tc *tc, void *data)
{
    printf("DBG: 'flower_free_data' called\n");
    // TODO
}

static int flower_clone(void *_dst, void *_src)
{
    printf("DBG: 'flower_clone' called\n");
    return 0;
    // TODO
}

static int flower_msg_fill(struct rtnl_tc *tc, void *data, struct nl_msg *msg)
{
    printf("DBG: 'flower_msg_fill' called\n");
    return 0;
    // TODO
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

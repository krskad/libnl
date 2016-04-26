#ifndef NETLINK_FLOWER_H_
#define NETLINK_FLOWER_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/classifier.h>
#include <netlink/route/action.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int rtnl_flower_get_classid(struct rtnl_cls *, uint32_t *);

extern int rtnl_flower_set_classid(struct rtnl_cls *, uint32_t);

extern int rtnl_flower_set_indev(struct rtnl_cls *, const char *);

extern int rtnl_flower_add_action(struct rtnl_cls *, struct rtnl_act *);

extern int rtnl_flower_del_action(struct rtnl_cls *, struct rtnl_act *);

extern int rtnl_flower_set_src_mac(struct rtnl_cls *, char*, char*);

extern int rtnl_flower_set_dst_mac(struct rtnl_cls *, char*, char*);

extern int rtnl_flower_set_eth_type(struct rtnl_cls *, uint16_t);

extern int rtnl_flower_set_ip_proto(struct rtnl_cls *, uint8_t);

extern int rtnl_flower_set_ipv4_src(struct rtnl_cls *, uint32_t, uint32_t);

extern int rtnl_flower_set_ipv4_dst(struct rtnl_cls *, uint32_t, uint32_t);

// ipv6_src

// ipv6_dst

extern int rtnl_flower_set_tcp_src(struct rtnl_cls *, uint16_t);

extern int rtnl_flower_set_tcp_dst(struct rtnl_cls *, uint16_t);

extern int rtnl_flower_set_udp_src(struct rtnl_cls *, uint16_t);

extern int rtnl_flower_set_udp_dst(struct rtnl_cls *, uint16_t);


#ifdef __cplusplus
}
#endif

#endif

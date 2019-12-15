#include "../../nft_json_api.h"

int main(void) {

    addr_ctx sa_ctx = {};
    sa_ctx.addr = "127.0.0.1";
    sa_ctx.mask_len = 32;
    sa_ctx.addr_type = NFT_SRC_ADDR;
    sa_ctx.family = "ip";
    char saddr[256];
    sprint_addr_ctx(saddr, &sa_ctx);

    ports_ctx sport_ctx = {};
    sport_ctx.port_type = NFT_SRC_PORT;
    sport_ctx.protocol = 6;
    sport_ctx.port_begin = 80;
    sport_ctx.port_end = 90;
    char sports[256];
    sprint_ports_ctx(sports, &sport_ctx);

    addr_ctx da_ctx = {};
    da_ctx.addr = "127.0.1.1";
    da_ctx.mask_len = 32;
    da_ctx.addr_type = NFT_DST_ADDR;
    da_ctx.family = "ip";
    char daddr[256];
    sprint_addr_ctx(daddr, &da_ctx);

    ports_ctx dport_ctx = {};
    dport_ctx.port_type = NFT_DST_PORT;
    dport_ctx.protocol = 6;
    dport_ctx.port_begin = 80;
    dport_ctx.port_end = 90;
    char dports[256];
    sprint_ports_ctx(dports, &dport_ctx);

    policy_ctx pol_ctx = {};

    pol_ctx.policy = "accept";
    pol_ctx.iifname = "eth0";
    pol_ctx.saddr_ctx = sa_ctx;
    pol_ctx.daddr_ctx = da_ctx;
    pol_ctx.sport_ctx = sport_ctx;
    pol_ctx.dport_ctx = dport_ctx;

    char pol[1024];
    sprint_policy_ctx(pol, &pol_ctx);
    printf("policy_ctx %s", pol);

    return 0;
}

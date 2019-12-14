#include "../../nft_json_api.h"

void error(const char *err_msg)
{
    printf("error: %s\n", err_msg);
    exit(-1);
}

int main(int argc, char const *argv[])
{
    rule_ctx *r_ctx = malloc(sizeof(rule_ctx));

    r_ctx->ch_ctx.family = "ip";
    r_ctx->ch_ctx.table = "t1";
    const char *ifname = "enp6s0";
    r_ctx->ch_ctx.chain = "POSTROUTING";
    r_ctx->handle = 1;

    switch (argc)
    {
    case 2:
        ifname = argv[1];
        break;
    case 4:
        r_ctx->ch_ctx.table = argv[1];
        r_ctx->ch_ctx.chain = argv[2];
        ifname = argv[3];
        break;
    case 5:
        if (strcmp(argv[1], "ip") && strcmp(argv[1], "ip6"))
            error("family: ip or ip6");
        else
            r_ctx->ch_ctx.family = argv[1];
        r_ctx->ch_ctx.table = argv[2];
        r_ctx->ch_ctx.chain = argv[3];
        ifname = argv[4];
        break;

    default:
        error("Need arguments: family table chain ifname\n");
    }

    printf("Add rule masq %s %s %s %s\n", r_ctx->ch_ctx.family,
           r_ctx->ch_ctx.table, r_ctx->ch_ctx.chain, ifname);

    json_error_t err;
    json_t *nft_cmd = json_object();
    json_t *nft_array = json_array();
    nft_cmd =
        nft_json_add_table(r_ctx->ch_ctx.family, r_ctx->ch_ctx.table, &err);
    if (json_array_append(nft_array, nft_cmd))
        error("cannot append add table in nftables array");

    r_ctx->ch_ctx.type = "nat";
    r_ctx->ch_ctx.hook = "postrouting";
    r_ctx->ch_ctx.priority = 0;
    r_ctx->ch_ctx.policy = "accept";

    nft_cmd = nft_json_add_chain(&r_ctx->ch_ctx, &err);
    if (json_array_append(nft_array, nft_cmd))
        error("cannot append add chain in nftables array");

    json_t *nft_expr = nft_json_build_expr_msq(ifname, 1, &err);
    if (!nft_expr)
        error("cannot build expression masquerade\n");

    nft_cmd = nft_json_build_rule(r_ctx, nft_expr, &err);
    if (json_array_append(nft_array, nft_cmd))
        error("cannot append rule in nftables array");

    if (nft_json_run_cmd(nft_array))
        error("cannot run nft json command");

    return 0;
}

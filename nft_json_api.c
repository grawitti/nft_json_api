#include "nft_json_api.h"

json_t *pfail(const char *err_msg)
{
    printf("error: %s\n", err_msg);
    return NULL;
}

void perror(const char *err_msg)
{
    printf("error: %s\n", err_msg);
    exit(-1);
}

int nft_get_output(struct nft_ctx *nft)
{
    int rc = 0;
    const char *output = nft_ctx_get_output_buffer(nft);

    if (strlen(output))
    {
        printf("\nThis is the current ruleset:\n| ");
        const char *p;
        for (p = output; *(p + 1); p++)
        {
            if (*p == '\n')
                printf("\n| ");
            else
                putchar(*p);
        }
        putchar('\n');
        rc = 0;
    }
    else
    {
        printf("\nCurrent ruleset is empty.\n");
        rc - 1;
    }

    if (strlen(output))
    {
        fflush(stdout);
        memset((char *)output, 0, strlen(output));
    }

    return rc;
}

json_t *nft_json_add_table(const char *family, const char *table, json_error_t *err)
{
    return json_pack_ex(err, 0, "{s{s{ss,ss}}}",
                        "add", "table",
                        "family", family,
                        "name", table);
}

json_t *nft_json_add_chain(chain_ctx *ch_ctx, json_error_t *err)
{
    return json_pack_ex(err, 0,
                        "{s{s{ss,ss,ss,ss,ss,ss}}}",
                        "add", "chain",
                        "family", ch_ctx->family,
                        "table", ch_ctx->table,
                        "name", ch_ctx->chain,
                        "type", ch_ctx->type,
                        "hook", ch_ctx->hook,
                        "policy", ch_ctx->policy);
}

json_t *nft_json_build_st_oifname(const char *oifname, json_error_t *err)
{
    return json_pack_ex(err, 0, "{s{s{ss},ss}}",
                        "match", "left",
                        "meta", "oifname",
                        "right", oifname);
}

json_t *nft_json_build_st_iif(const char *iifname, json_error_t *err)
{
    return json_pack_ex(err, 0, "{s{s{ss},ss}}",
                        "match", "left",
                        "meta", "iif",
                        "right", iifname);
}

json_t *nft_json_build_st_addr(const addr_ctx *addr_ctx, json_error_t *err)
{
    const char *xaddr;
    switch (addr_ctx->addr_type)
    {
    case NFT_SRC_ADDR:
        xaddr = "saddr";
        break;
    case NFT_DST_ADDR:
        xaddr = "daddr";
        break;
    default:
        return pfail("unexpected addr_type.");
    }

    return json_pack_ex(err, 0, "{s{s{s{ss,ss}},s{s{ss,si}}}}",
                        "match",
                        "left",
                        "payload",
                        "name", addr_ctx->family,
                        "field", xaddr,
                        "right",
                        "prefix",
                        "addr", addr_ctx->addr,
                        "len", addr_ctx->mask_len);
}

json_t *nft_json_build_st_count()
{
    return json_pack("{sn}", "counter");
}

json_t *nft_json_build_st_policy(const char *policy)
{
    return json_pack("{sn}", policy);
}

json_t *nft_json_build_st_nat(uint8_t nat_type, const char *addr, json_error_t *err)
{
    switch (nat_type)
    {
    case NFT_SNAT:
        return json_pack_ex(err, 0, "{s{ss}}", "snat", "addr", addr);

    case NFT_DNAT:
        return json_pack_ex(err, 0, "{s{ss}}", "dnat", "addr", addr);

    case NFT_MASQ:
        return json_pack("{sn}", "masquerade");

    default:
        return pfail("Unexpected nat_type.");
    }
}

json_t *nft_json_build_ports_set(const int port_begin, const int port_end, json_error_t *err)
{
    if (port_begin < 1 || port_end < 1)
        pfail("ports values must be > 0.");

    if (port_begin > port_end)
        pfail("port_begin must be > port_end or 0.");

    if (port_begin == port_end)
        return json_pack_ex(err, 0, "i", (json_int_t)port_begin);

    if (port_begin < port_end)
        return json_pack_ex(err, 0, "{s[i,i]}", "range",
                            (json_int_t)port_begin, (json_int_t)port_end);
}

json_t *nft_json_build_st_ports(const ports_ctx *p_ctx, json_error_t *err)
{
    const char *xport;
    switch (p_ctx->port_type)
    {
    case NFT_SRC_PORT:
        xport = "sport";
        break;

    case NFT_DST_PORT:
        xport = "dport";
        break;

    default:
        return pfail("Unexpected port_type.");
    }

    json_t *ports_set = nft_json_build_ports_set(p_ctx->port_begin, p_ctx->port_end, err);

    return json_pack_ex(err, 0,
                        "{s{s{s{ss,ss}},so}}",
                        "match",
                        "left",
                        "payload",
                        "name", p_ctx->protocol,
                        "field", xport,
                        "right", ports_set);
}

json_t *nft_json_build_expr_msq(const char *oifname, const int count, json_error_t *err)
{
    json_t *nft_expr = json_array();

    if (json_array_append(nft_expr, nft_json_build_st_oifname(oifname, err)))
        return pfail("can't build statement match");

    if (count)
        if (json_array_append(nft_expr, nft_json_build_st_count()))
            return pfail("can't build statement count");

    if (json_array_append(nft_expr, nft_json_build_st_nat(NFT_MASQ, NULL, err)))
        return pfail("can't build statement nat");

    return nft_expr;
}

json_t *nft_json_build_expr_snat(const nat_ctx *nat_ctx, const int count, json_error_t *err)
{
    json_t *nft_expr = json_array();

    if (json_array_append(nft_expr, nft_json_build_st_addr(&nat_ctx->saddr_ctx, err)))
        return pfail("can't build statement saddr");

    if (json_array_append(nft_expr, nft_json_build_st_oifname(nat_ctx->oif, err)))
        return pfail("can't build statement oif");

    if (count)
        if (json_array_append(nft_expr, nft_json_build_st_count()))
            return pfail("can't build statement counters");

    if (json_array_append(nft_expr, nft_json_build_st_nat(nat_ctx->nat_type, nat_ctx->nat_addr, err)))
        return pfail("can't build statement NAT");

    return nft_expr;
}

json_t *nft_json_build_expr_dnat(const nat_ctx *nat_ctx, const ports_ctx *p_ctx,
                                 const int count, json_error_t *err)
{
    json_t *nft_expr = json_array();

    if (json_array_append(nft_expr, nft_json_build_st_iif(nat_ctx->iifname, err)))
        return pfail("can't build statement iif");

    if (json_array_append(nft_expr, nft_json_build_st_ports(p_ctx, err)))
        return pfail("can't build statement dport");

    if (count)
        if (json_array_append(nft_expr, nft_json_build_st_count()))
            return pfail("can't build statement counters");

    if (json_array_append(nft_expr, nft_json_build_st_nat(nat_ctx->nat_type, nat_ctx->nat_addr, err)))
        return pfail("can't build statement NAT");

    return nft_expr;
}

json_t *nft_json_build_expr_policy(policy_ctx *pol_ctx, const char *family,
                                   const uint8_t count, json_error_t *err)
{
    json_t *nft_expr = json_array();
    pol_ctx->saddr_ctx.family = pol_ctx->daddr_ctx.family = family;
    pol_ctx->saddr_ctx.addr_type = NFT_SRC_ADDR;
    pol_ctx->daddr_ctx.addr_type = NFT_DST_ADDR;
    pol_ctx->sport_ctx.port_type = NFT_SRC_PORT;
    pol_ctx->dport_ctx.port_type = NFT_DST_PORT;

    if (pol_ctx->iifname)
        if (json_array_append(nft_expr, nft_json_build_st_iif(pol_ctx->iifname, err)))
            return pfail("can't build statement iif");

    if (pol_ctx->saddr_ctx.addr)
        if (json_array_append(nft_expr, nft_json_build_st_addr(&pol_ctx->saddr_ctx, err)))
            return pfail("can't build statement saddr");

    if (pol_ctx->daddr_ctx.addr)
        if (json_array_append(nft_expr, nft_json_build_st_addr(&pol_ctx->daddr_ctx, err)))
            return pfail("can't build statement daddr");

    if (pol_ctx->sport_ctx.protocol && pol_ctx->sport_ctx.port_begin > 0 && pol_ctx->sport_ctx.port_end >> 0)
        if (json_array_append(nft_expr, nft_json_build_st_ports(&pol_ctx->sport_ctx, err)))
            return pfail("can't build statement sport");

    if (pol_ctx->dport_ctx.protocol && pol_ctx->dport_ctx.port_begin > 0 && pol_ctx->dport_ctx.port_end >> 0)
        if (json_array_append(nft_expr, nft_json_build_st_ports(&pol_ctx->dport_ctx, err)))
            return pfail("can't build statement dport");

    if (count)
        if (json_array_append(nft_expr, nft_json_build_st_count()))
            return pfail("can't build statement counters");

    if (json_array_append(nft_expr, nft_json_build_st_policy(pol_ctx->policy)))
        return pfail("can't build statement policy");

    return nft_expr;
}

json_t *nft_json_build_rule(const rule_ctx *rule_ctx, json_t *expr, json_error_t *err)
{
    const char *cmd_str;
    switch (rule_ctx->nft_cmd)
    {
    case NFT_CMD_ADD:
        cmd_str = "add";
        break;
    case NFT_CMD_REPLACE:
        cmd_str = "replace";
        break;
    case NFT_CMD_DELETE:
        cmd_str = "delete";
        expr = json_pack("{}");
        break;

    default:
        pfail("Unexpected nft command");
    }

    return json_pack_ex(err, 0,
                        "{s{s{ss,ss,ss,so,si}}}",
                        cmd_str, "rule",
                        "family", rule_ctx->ch_ctx.family,
                        "table", rule_ctx->ch_ctx.table,
                        "chain", rule_ctx->ch_ctx.chain,
                        "expr", expr,
                        "handle", rule_ctx->handle);
}

json_t *nft_json_build_flush()
{
    return json_pack("{s{sn}}", "flush", "ruleset");
}

char *nft_json_get_cmd_string(json_t *nft_array)
{
    json_t *root = json_object();
    json_object_set(root, "nftables", nft_array);
#ifdef DEBUG
    json_dump_file(root, "json/input.json", JSON_INDENT(4));
#endif // DEBUG
    char *list_cmd = json_dumps(root, 0);
}

int nft_json_fprint_ruleset(struct nft_ctx *nft)
{
    if (!nft){
        pfail("nft_ctx is NULL");
        return -1;
    }

    char *list_cmd = "list chain nat POSTROUTING";
    const char *out_file = "json/output.json";

    nft_ctx_output_set_json(nft, 1);
    if (nft_ctx_buffer_output(nft) || nft_run_cmd_from_buffer(nft, list_cmd, sizeof(list_cmd)))
        return -1;

    const char *output = nft_ctx_get_output_buffer(nft);
    if(strlen(output))
    {
        json_error_t err;
        json_t *root = json_loads(output, 0, &err);
        if(!root){
            printf(err.text);
            return -1;
        }

        if(json_dump_file(root, out_file, JSON_INDENT(4))){
            printf("cannot write out_file");
            return -1;
        }
    }
    else {
        printf("output is NULL");
        return -1;
    }
    return 0;
}
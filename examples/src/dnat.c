#include "../../nft_json_api.h"

void perror(const char *err_msg)
{
    printf("error: %s\n", err_msg);
    exit(-1);
}

int main(int argc, char const **argv) {
	rule_ctx r_ctx;
	memset(&r_ctx, 0, sizeof(rule_ctx));
	nat_ctx n_ctx;
	memset(&n_ctx, 0, sizeof(nat_ctx));
	ports_ctx p_ctx;
	memset(&p_ctx, 0, sizeof(ports_ctx));

	n_ctx.nat_type = NFT_DNAT;
	r_ctx.ch_ctx.family = n_ctx.daddr_ctx.family = "ip";
	r_ctx.ch_ctx.table = "nat";
	r_ctx.ch_ctx.chain = "PREROUTING";

	n_ctx.iifname = "enp6s0";
	p_ctx.port_begin = 0;
	p_ctx.port_end = 0;
	p_ctx.port_type = NFT_DST_PORT;

	switch (argc) {
	case 5:
		p_ctx.protocol = argv[1];
		if (!(p_ctx.port_begin = atoi(argv[2])))
			return -1;
		if (!(p_ctx.port_end = atoi(argv[3])))
			return -1;
		n_ctx.nat_addr = argv[4];
		break;
	case 9:
		r_ctx.ch_ctx.family = argv[1];
		r_ctx.ch_ctx.table = argv[2];
		r_ctx.ch_ctx.chain = argv[3];
		n_ctx.iifname = argv[4];
		p_ctx.protocol = argv[5];
		if (!(p_ctx.port_begin = atoi(argv[6])))
			return -1;
		if (!(p_ctx.port_end = atoi(argv[7])))
			return -1;
		n_ctx.nat_addr = argv[8];
		break;

	default:
		printf("Need args: family table chain ifname protocol port_begin port_end "
		       "daddr | protocol port_begin port_end daddr\n");
		return -1;
	}

	json_error_t err;
	json_t *nft_cmd = json_object();

	nft_cmd = nft_json_add_table(r_ctx.ch_ctx.family, r_ctx.ch_ctx.table, &err);
	json_t *nft_array = json_array();
	if (json_array_append(nft_array, nft_cmd))
		perror("cannot append add table in nftables array");

	r_ctx.ch_ctx.type = "nat";
	r_ctx.ch_ctx.hook = "prerouting";
	r_ctx.ch_ctx.priority = 0;
	r_ctx.ch_ctx.policy = "accept";
	nft_cmd = nft_json_add_chain(&r_ctx.ch_ctx, &err);
	if (json_array_append(nft_array, nft_cmd))
		perror("cannot append add chain in nftables array");

	json_t *nft_expr = nft_json_build_expr_dnat(&n_ctx, &p_ctx, 0, &err);
	nft_cmd = nft_json_build_rule(&r_ctx, nft_expr, &err);
	if (json_array_append(nft_array, nft_cmd))
		perror("cannot append rule in nftables array");

	char *list_cmd = nft_json_get_cmd_string(nft_array);

	struct nft_ctx *nft;
	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	nft_ctx_output_set_json(nft, 1);
	int rc = 0;
	if (rc == 0) {
		if (nft_ctx_buffer_output(nft) || nft_run_cmd_from_buffer(nft, list_cmd, 0))
			return -1;

		if (rc != 1)
			nft_get_output(nft);
	}

	nft_ctx_unbuffer_output(nft);
	nft_ctx_free(nft);
	return 0;
}

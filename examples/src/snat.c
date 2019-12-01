#include "../../nft_json_api.h"

int main(int argc, char const **argv) {
	rule_ctx r_ctx;
	memset(&r_ctx, 0, sizeof(rule_ctx));
	nat_ctx n_ctx;
	memset(&n_ctx, 0, sizeof(nat_ctx));

	n_ctx.nat_type = NFT_SNAT;
	r_ctx.ch_ctx.family = n_ctx.saddr_ctx.family = "ip";

	switch (argc) {
	case 7:
		r_ctx.ch_ctx.table = argv[1];
		r_ctx.ch_ctx.chain = argv[2];
		n_ctx.oif = argv[3];
		n_ctx.saddr_ctx.addr = argv[4];
		n_ctx.saddr_ctx.addr_type = NFT_SRC_ADDR;
		if (!(n_ctx.saddr_ctx.mask_len = atoi(argv[5])))
			return -1;
		n_ctx.nat_addr = argv[6];
		break;

	case 8:
		r_ctx.ch_ctx.family = argv[1];
		r_ctx.ch_ctx.table = argv[2];
		r_ctx.ch_ctx.chain = argv[3];
		n_ctx.oif = argv[4];
		n_ctx.saddr_ctx.addr = argv[5];
		n_ctx.saddr_ctx.addr_type = NFT_SRC_ADDR;
		if (!(n_ctx.saddr_ctx.mask_len = atoi(argv[6])))
			return -1;
		n_ctx.nat_addr = argv[7];
		break;

	default:
		printf("Need args: family table chain ifname saddr sa_len snat_addr\n");
		return -1;
	}

	json_error_t err;
	json_t *nft_cmd = json_object();

	nft_cmd = nft_json_add_table(r_ctx.ch_ctx.family, r_ctx.ch_ctx.table, &err);
	json_t *nft_array = json_array();
	if (json_array_append(nft_array, nft_cmd))
		perror("cannot append add table in nftables array");

	r_ctx.ch_ctx.type = "nat";
	r_ctx.ch_ctx.hook = "postrouting";
	r_ctx.ch_ctx.priority = 100;
	r_ctx.ch_ctx.policy = "accept";
	nft_cmd = nft_json_add_chain(&r_ctx.ch_ctx, &err);
	if (json_array_append(nft_array, nft_cmd))
		perror("cannot append add chain in nftables array");

	json_t *nft_expr = nft_json_build_expr_snat(&n_ctx, 0, &err);
	if (!nft_expr)
		return -1;

	nft_cmd = nft_json_build_rule(&r_ctx, nft_expr, &err);

	if (json_array_append(nft_array, nft_cmd) != 0)
		perror("cannot append rule in nft array");

	char *list_cmd = nft_json_get_cmd_string(nft_array);

	struct nft_ctx *nft;
	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	nft_ctx_output_set_json(nft, 1);

#ifdef DEBUG
	nft_json_fprint_ruleset(nft);
#endif // DEBUG

	if (nft_ctx_buffer_output(nft) || nft_run_cmd_from_buffer(nft, list_cmd, 0))
		return -1;

	nft_get_output(nft);

	nft_ctx_unbuffer_output(nft);
	nft_ctx_free(nft);
	return 0;
}

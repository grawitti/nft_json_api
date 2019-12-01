#include "../nft_json_api.h"

int main(int argc, char const **argv) {
	rule_ctx r_ctx;
	memset(&r_ctx, 0, sizeof(rule_ctx));
	policy_ctx pol_ctx;
	memset(&pol_ctx, 0, sizeof(policy_ctx));

	r_ctx.ch_ctx.family = "ip";
	r_ctx.ch_ctx.table = "filter";
	r_ctx.ch_ctx.chain = "FORWARD";

	// PLEASE TEST SUPPORT IIFNAME!!!
	pol_ctx.iifname = "enp6s0";

	pol_ctx.policy = NFT_POLICY_ACCEPT;
	pol_ctx.dport_ctx.protocol = pol_ctx.sport_ctx.protocol = "tcp";

	switch (argc) {
	case 10:
		// if(strcmp(argv[1], "0")) {
		pol_ctx.saddr_ctx.addr = argv[1];
		if (!(pol_ctx.saddr_ctx.mask_len = atoi(argv[2])))
			return -1;
		// }
		pol_ctx.sport_ctx.port_begin = atoi(argv[3]);
		pol_ctx.sport_ctx.port_end = atoi(argv[4]);
		// if(strcmp(argv[5], "0")){
		pol_ctx.daddr_ctx.addr = argv[5];
		if (!(pol_ctx.daddr_ctx.mask_len = atoi(argv[6])))
			return -1;
		// }
		pol_ctx.dport_ctx.port_begin = atoi(argv[7]);
		pol_ctx.dport_ctx.port_end = atoi(argv[8]);
		pol_ctx.policy = argv[9];
		break;

	case 15:
		r_ctx.ch_ctx.family = argv[1];
		r_ctx.ch_ctx.table = argv[2];
		r_ctx.ch_ctx.chain = argv[3];
		pol_ctx.dport_ctx.protocol = pol_ctx.sport_ctx.protocol = argv[5];

		if (strcmp(argv[1], "0")) {
			pol_ctx.saddr_ctx.addr = argv[6];
			if (!(pol_ctx.saddr_ctx.mask_len = atoi(argv[7])))
				return -1;
		}
		pol_ctx.sport_ctx.port_begin = atoi(argv[8]);
		pol_ctx.sport_ctx.port_end = atoi(argv[9]);
		if (strcmp(argv[5], "0")) {
			pol_ctx.daddr_ctx.addr = argv[10];
			if (!(pol_ctx.daddr_ctx.mask_len = atoi(argv[11])))
				return -1;
		}
		pol_ctx.dport_ctx.port_begin = atoi(argv[12]);
		pol_ctx.dport_ctx.port_end = atoi(argv[13]);
		pol_ctx.policy = argv[14];
		break;

	default:
		printf("Need args: family table chain ifname protocol saddr sa_len "
		       "sport_begin sport end daddr_addr da_len dport_begin dport_end "
		       "policy\n");
		return -1;
	}

	struct nft_ctx *nft;
	int rc = 0;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	nft_ctx_output_set_json(nft, 1);

	json_error_t err;
	json_t *jt_nft_array = json_array();
	json_t *jt_nft_elem = json_object();

	json_t *nft_expr =
	        nft_json_build_expr_policy(&pol_ctx, r_ctx.ch_ctx.family, 0, &err);
	if (!nft_expr)
		return -1;

	jt_nft_elem = nft_json_build_rule(&r_ctx, nft_expr, &err);

	if (json_array_append(jt_nft_array, jt_nft_elem) != 0)
		perror("cannot append rule in nftables array");

	char *list_cmd = nft_json_get_cmd_string(jt_nft_array);

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

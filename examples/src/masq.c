#include "../../nft_json_api.h"

void perror(const char *err_msg)
{
    printf("error: %s\n", err_msg);
    exit(-1);
}

int main(int argc, char const *argv[]) {
	rule_ctx *r_ctx = malloc(sizeof(rule_ctx));

	r_ctx->ch_ctx.family = "ip";
	r_ctx->ch_ctx.table = "t1";
	const char *ifname = "enp6s0";
	r_ctx->ch_ctx.chain = "POSTROUTING";
	r_ctx->handle = 1;
    r_ctx->comment = "h9m5";
    int rc = 0;

    switch (argc) {
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
			rc = -1;
		else
			r_ctx->ch_ctx.family = argv[1];
		r_ctx->ch_ctx.table = argv[2];
		r_ctx->ch_ctx.chain = argv[3];
		ifname = argv[4];
		break;

	default:
		printf("Need arguments: family table chain ifname\n");
		rc = -1;
	}

	if (!rc) {
		printf("Add rule masq %s %s %s %s\n", r_ctx->ch_ctx.family,
		       r_ctx->ch_ctx.table, r_ctx->ch_ctx.chain, ifname);

		json_error_t err;
		json_t *nft_cmd = json_object();
		json_t *nft_array = json_array();
		nft_cmd =
		        nft_json_add_table(r_ctx->ch_ctx.family, r_ctx->ch_ctx.table, &err);
		if (json_array_append(nft_array, nft_cmd))
			perror("cannot append add table in nftables array");

		r_ctx->ch_ctx.type = "nat";
		r_ctx->ch_ctx.hook = "postrouting";
		r_ctx->ch_ctx.priority = 0;
		r_ctx->ch_ctx.policy = "accept";
		nft_cmd = nft_json_add_chain(&r_ctx->ch_ctx, &err);
		if (json_array_append(nft_array, nft_cmd))
			perror("cannot append add chain in nftables array");

		json_t *nft_expr = nft_json_build_expr_msq(ifname, 1, &err);
		if (!nft_expr)
			return -1;

		nft_cmd = nft_json_build_rule(r_ctx, nft_expr, &err);
		if (json_array_append(nft_array, nft_cmd))
			perror("cannot append rule in nftables array");

		char *list_cmd = nft_json_get_cmd_string(nft_array);
		struct nft_ctx *nft;
		nft = nft_ctx_new(NFT_CTX_DEFAULT);
		if (!nft)
			return -1;

		nft_ctx_output_set_json(nft, 1);

#ifdef DEBUG
		nft_json_fprint_ruleset(nft, "../json/output.json");
#endif // DEBUG

		if (rc == 0) {
			if (nft_ctx_buffer_output(nft)
			    || nft_run_cmd_from_buffer(nft, list_cmd, 0))
				return -1;

			if (rc != 1)
				nft_get_output(nft);
		}
		free(r_ctx);

		nft_ctx_unbuffer_output(nft);
		nft_ctx_free(nft);
	}
	return 0;
}

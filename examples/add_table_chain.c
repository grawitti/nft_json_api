#include "../nft_json_api.h"

int main(int argc, char const *argv[]) {
	chain_ctx *ch_ctx = malloc(sizeof(chain_ctx));
	if (!ch_ctx)
		return -1;

	ch_ctx->family = "ip";
	ch_ctx->priority = 0;
	ch_ctx->policy = "accept";

	switch (argc) {
	case 5:
		ch_ctx->table = argv[1];
		ch_ctx->chain = argv[2];
		ch_ctx->type = argv[3];
		ch_ctx->hook = argv[4];
		break;
	case 8:
		ch_ctx->family = argv[1];
		ch_ctx->table = argv[2];
		ch_ctx->chain = argv[3];
		ch_ctx->type = argv[4];
		ch_ctx->hook = argv[5];
		ch_ctx->priority = atoi(argv[6]);
		ch_ctx->policy = argv[7];
		break;

	default:
		printf("Need arguments: table chain type hook \
        | family table chain type hook priority policy\n");
		return -1;
	}

	json_error_t err;
	json_t *nft_cmd = json_object();
	nft_cmd = nft_json_add_table(ch_ctx->family, ch_ctx->table, &err);
	json_t *nft_array = json_array();
	if (json_array_append(nft_array, nft_cmd))
		pfail("cannot append nftables array");

	nft_cmd = nft_json_add_chain(ch_ctx, &err);
	if (json_array_append(nft_array, nft_cmd))
		pfail("cannot append nftables array");

	char *list_cmd = nft_json_get_cmd_string(nft_array);
	if (!list_cmd)
		pfail("cannot get list nft commands");

	struct nft_ctx *nft;
	int rc = 0;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	nft_ctx_output_set_json(nft, 1);
	if (rc == 0) {
		if (nft_ctx_buffer_output(nft) || nft_run_cmd_from_buffer(nft, list_cmd, 0))
			return -1;

		if (rc != 1)
			nft_get_output(nft);
	}

	free(ch_ctx);
	nft_ctx_unbuffer_output(nft);
	nft_ctx_free(nft);
	return 0;
}

#include "../../nft_json_api.h"

int main(int argc, char const *argv[]) {
	chain_ctx *ch_ctx = malloc(sizeof(chain_ctx));
	if (!ch_ctx)
		return 0;
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
	case 7:
		ch_ctx->family = argv[1];
		ch_ctx->table = argv[2];
		ch_ctx->chain = argv[3];
		ch_ctx->type = argv[4];
		ch_ctx->hook = argv[5];
		ch_ctx->priority = atoi(argv[6]);
		break;

	default:
		printf("Need arguments: table chain type hook | family table chain type "
		       "hook priority policy\n");
		return -1;
	}

	json_error_t err;
	struct nft_ctx *nft;
	int rc = 0;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	nft_ctx_output_set_json(nft, 1);

	json_t *jt_nft_array = json_array();
	json_t *jt_nft_elem = json_object();

	jt_nft_elem = nft_json_add_chain(ch_ctx, &err);

	if (json_array_append(jt_nft_array, jt_nft_elem) != 0) {
		fprintf(stderr, "JSON error: %s\n", err.text);
		rc = -1;
	}

	json_t *root = json_object();
	json_object_set(root, "nftables", jt_nft_array);

	json_dump_file(root, "json/input.json", JSON_INDENT(4));

	char *list_cmd = json_dumps(root, 0);

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

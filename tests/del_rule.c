#include "../nft_json_api.h"

int main(int argc, char const *argv[]) {
	int rc = 0;
	rule_ctx r_ctx;
	memset(&r_ctx, 0, sizeof(rule_ctx));

	r_ctx.ch_ctx.family = "ip";
	r_ctx.nft_cmd = NFT_CMD_DELETE;
	r_ctx.handle = 4;

	switch (argc) {
	case 4:
		r_ctx.ch_ctx.table = argv[1];
		r_ctx.ch_ctx.chain = argv[2];
		r_ctx.handle = atoi(argv[3]);
		if (!r_ctx.handle) {
			printf("not supported handle value: %s\n", argv[3]);
			rc = -1;
			break;
		}
		break;
	case 5:
		r_ctx.ch_ctx.family = argv[1];
		r_ctx.ch_ctx.table = argv[2];
		r_ctx.ch_ctx.chain = argv[3];
		r_ctx.handle = atoi(argv[4]);
		if (!r_ctx.handle) {
			printf("not supported handle value: %s\n", argv[4]);
			rc = -1;
			break;
		}
		break;
	default:
		printf("Need arguments: family table chain handle\n");
		rc = -1;
		break;
	}

	json_error_t err;
	struct nft_ctx *nft;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	nft_ctx_output_set_json(nft, 1);

	json_t *jt_nft_array = json_array();
	json_t *jt_nft_elem = json_object();

	jt_nft_elem = nft_json_build_rule(&r_ctx, NULL, &err);

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

	nft_ctx_unbuffer_output(nft);
	nft_ctx_free(nft);
	return 0;
}

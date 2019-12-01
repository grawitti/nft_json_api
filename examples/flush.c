#include "../nft_json_api.h"

int main() {
	json_error_t err;
	struct nft_ctx *nft;
	int rc = 0;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	nft_ctx_output_set_json(nft, 1);

	json_t *jt_nft_array = json_array();
	json_t *jt_nft_elem = json_object();

	jt_nft_elem = nft_json_build_flush();

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

	printf("nftable ruleset flushed\n");

	nft_ctx_unbuffer_output(nft);
	nft_ctx_free(nft);
	return 0;
}

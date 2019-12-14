#include "../../nft_json_api.h"

int main(int argc, char const *argv[]) {
    chain_ctx ch_ctx = {};
    ch_ctx.family = "ip";

	switch (argc) {
	case 3:
		ch_ctx.table = argv[1];
		ch_ctx.chain = argv[2];
		break;

	case 4:
		ch_ctx.family = argv[1];
		ch_ctx.table = argv[2];
		ch_ctx.chain = argv[3];
		break;

	default:
		printf("Arguments: table chain | family table chaind\n");
		return -1;
	}

	json_t *nft_array = json_array();
	json_t *nft_cmd = json_object();

    json_error_t err;
	nft_cmd = nft_json_build_flush_chain(&ch_ctx, &err);

    if (json_array_append(nft_array, nft_cmd)){
        printf("error: cannot append command flush chain in nftables array\n");
        return -1;
    }

    if (nft_json_run_cmd(nft_array)){
        printf("error: cannot run nft json command\n");
        return -1;
    }

    return 0;
}

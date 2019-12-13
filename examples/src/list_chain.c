#include "../../nft_json_api.h"

int main(int argc, char const *argv[])
{
    chain_ctx ch_ctx = {};

    ch_ctx.family = "ip";

    switch (argc)
    {
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
        printf("Arguments: table chain | family table chain\n");
        return -1;
    }

    int max_len = 40;
    char list_cmd[max_len];
    memset(list_cmd, 0, max_len);
    nft_json_build_list_chain(list_cmd, max_len, &ch_ctx);
    if(!strlen(list_cmd)){
        printf("cannot bbuild list_cmd\n");
        return -1;
    }

    struct nft_ctx *nft;
    nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft){
        printf("Error: create nft\n");
        return -1;
    }

    nft_ctx_output_set_json(nft, 1);

    json_error_t err;
    int handle = nft_json_get_rule_handle(nft, &ch_ctx, "m2", &err);
    if (handle < 0)
    {
        printf("cannot get rule handle\n");
        return -1;
    }
    else
        printf("handle: %i\n", handle);

    nft_json_free(nft);

    return 0;
}

#include "../nft_json_api.h"

int main(int argc, char const *argv[])
{   
    const char *family = "ip";
    const char *table;
    
    switch (argc)
    {
    case 2:
        table = argv[1];
        break;
    case 3:
        family = argv[1];
        table = argv[2];
        break;
    
    default:
        printf("Need arguments: family table | table\n");
        return -1;
    }

    struct nft_ctx *nft;
    int rc = 0;

    nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft)
        return -1;

    json_error_t err;
    json_t *nft_cmd = json_object();
    nft_cmd = nft_json_add_table(family, table, &err);

    json_t *nft_array = json_array();
    json_array_append(nft_array, nft_cmd);

    char *list_cmd = nft_json_get_cmd_string(nft_array);

    nft_ctx_output_set_json(nft, 1);
    if (rc == 0)
    {
        if (nft_ctx_buffer_output(nft) || nft_run_cmd_from_buffer(nft, list_cmd, 0))
            return -1;

        if (rc != 1)
            nft_get_output(nft);
    }

    nft_ctx_unbuffer_output(nft);
    nft_ctx_free(nft);
    return 0;
}
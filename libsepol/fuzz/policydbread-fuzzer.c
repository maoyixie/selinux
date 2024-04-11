#include <sepol/debug.h>
#include <sepol/kernel_to_cil.h>
#include <sepol/kernel_to_conf.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/hierarchy.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/policydb.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    policydb_t policydb;
    struct policy_file pf;
    int rc;

    if (Size < sizeof(uint32_t))
    {
        return 0;
    }

    policydb_init(&policydb);
    policy_file_init(&pf);

    pf.type = PF_USE_MEMORY;
    pf.data = (void *)Data;
    pf.len = Size;

    rc = policydb_read(&policydb, &pf, 0);

    if (rc == 0)
    {
        policydb_destroy(&policydb);
    }

    return 0;
}
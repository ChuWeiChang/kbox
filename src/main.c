/* SPDX-License-Identifier: MIT */

/* kbox entry point.
 *
 * Parses CLI arguments and dispatches to the appropriate mode handler.
 */

#include <stdio.h>
#include <stdlib.h>

#include "kbox/cli.h"
#include "kbox/image.h"

int main(int argc, char *argv[])
{
    struct kbox_args args;
    int ret;

    if (kbox_parse_args(argc, argv, &args) < 0)
        return 1;

    switch (args.mode) {
    case KBOX_MODE_IMAGE:
        ret = kbox_run_image(&args.image);
        break;
    default:
        fprintf(stderr, "unsupported mode\n");
        return 1;
    }

    return ret < 0 ? 1 : 0;
}

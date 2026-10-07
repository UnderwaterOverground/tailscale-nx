// MagicDNS for the whole console through Atmosphère's DNS MITM: tailnet
// names are kept in a managed block of the hosts file Atmosphère is using,
// and Atmosphère is asked to reload it. Apps resolve names via sfdnsres,
// which never reaches the engine, so this is the hook that works for all.
//
// Atmosphère's own rules are never weakened. It checks later entries first
// (each is inserted at the front), so our block, last in the file, is
// consulted first; but our entries are exact tailnet names (no wildcards,
// nothing containing "nintendo"), which only ever match themselves.
#pragma once

extern "C" {
#include "tsnx.h"
}

namespace ams::hosts {

    // Rewrites the managed block from the engine's current peers (call with
    // the runtime lock held). Never creates a hosts file, never touches
    // lines outside the block, and skips writing if anything looks off.
    void Update(TsnxEngine *engine);

}

/** @file
  kAFL fuzzing agent implementation

**/

#include "KaflAgentLibInternal.h"
#include <Library/BaseMemoryLib.h>    // CompareMem
#include <Library/BaseLib.h>          // AsciiStrnCmp



// local agent state
agent_state_t agent_state = {
  .agent_initialized = FALSE,
  .fuzz_enabled = FALSE,
  .ve_buf = NULL,
  .ve_num = 0,
  .ve_pos = 0,
  .ve_mis = 0,
};


UINTN
EFIAPI
kafl_fuzz_buffer (
  IN  VOID                    *fuzz_buf,
  IN  CONST VOID              *orig_buf,
  IN  CONST UINTN             *addr,
  IN  CONST UINTN             num_bytes,
  IN  CONST enum tdx_fuzz_loc type
  )
{
  UINTN RequestedBytes = 0;

  debug_print("kAFL %a\n", __FUNCTION__);

  update_local_state();
  RequestedBytes = internal_fuzz_buffer(fuzz_buf, orig_buf, addr, num_bytes, type, &agent_state);
  update_global_state();
  return RequestedBytes;
}

VOID
EFIAPI
kafl_fuzz_event (
  IN  enum kafl_event  e
  )
{
  debug_print("kAFL %a\n", __FUNCTION__);

  update_local_state();
  internal_fuzz_event(e, &agent_state);
  update_global_state();
}

STATIC
VOID
EFIAPI
show_local_state (
  VOID
  )
{
  UINTN as_size = sizeof(agent_state);
  debug_print("kAFL global agent state address at 0x%p, pointing to agent state at 0x%p\n", gKaflAgentStatePtrAddr, *(agent_state_t**)gKaflAgentStatePtrAddr);
  debug_print("kAFL local agent state at 0x%p, size %d (0x%x):\n", &agent_state, as_size, as_size);
  debug_print("  agent_initialized: %d\n", agent_state.agent_initialized);
  debug_print("  fuzz_enabled: %d\n", agent_state.fuzz_enabled);
  debug_print("  ve_buf: 0x%p\n", agent_state.ve_buf);
  debug_print("  ve_num: %d\n", agent_state.ve_num);
  debug_print("  ve_pos: %d\n", agent_state.ve_pos);
  debug_print("  ve_mis: %d\n", agent_state.ve_mis);
}

/**
  Copy an agent state by copying each member individually.

  Pointer dereferenciation (*DstState = *SrcState) may work as well, but assumes
  that members in both structs have the same order. This may not be the case here
  since we copy structs across compilation units (modules) and hence the compiler
  might decide to reorder struct members differently in different modules.

  @param DstState   The state into which data will be copied.
  @param SrcState   The state from which data will be copied.
**/
STATIC
VOID
EFIAPI
copy_state (
  IN  agent_state_t   *DstState,
  IN  agent_state_t   *SrcState
)
{
  if (!DstState || !SrcState)
  {
    kafl_habort("cannot copy agent state; pointer to Source or Destination state are NULL.\n");
  }

  DstState->agent_initialized = SrcState->agent_initialized;
  DstState->fuzz_enabled = SrcState->fuzz_enabled;
  DstState->ve_buf = SrcState->ve_buf;
  DstState->ve_num = SrcState->ve_num;
  DstState->ve_pos = SrcState->ve_pos;
  DstState->ve_mis = SrcState->ve_mis;
}

VOID
EFIAPI
update_global_state (
  VOID
  )
{
  debug_print("update global state\n");

  if (!gKaflAgentStatePtrAddr)
  {
    kafl_habort("Invalid agent state pointer address.\n");
  }

  *(agent_state_t**)gKaflAgentStatePtrAddr = &agent_state;

  // verify that agent state pointer was written correctly
  agent_state_t *gAS = *(agent_state_t**)gKaflAgentStatePtrAddr;
  if (gAS != &agent_state)
  {
    kafl_habort("global & local agent state pointers are not equal after copy!\n");
  }

  show_local_state();
}

VOID
EFIAPI
update_local_state (
  VOID
  )
{
  debug_print("update local state\n");

  if (!gKaflAgentStatePtrAddr)
  {
    kafl_habort("Invalid agent state pointer address.\n");
  }

  agent_state_t *gAS = *(agent_state_t**)gKaflAgentStatePtrAddr;
  if (gAS)
  {
    // only update local state if global agent state pointer is not NULL
    copy_state(&agent_state, gAS);
    show_local_state();
  }
}
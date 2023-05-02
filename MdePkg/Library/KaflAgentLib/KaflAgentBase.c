/** @file
  kAFL fuzzing agent implementation

**/

#include "KaflAgentLibInternal.h"
#include <Library/BaseMemoryLib.h>    // CompareMem
#include <Library/BaseLib.h>          // AsciiStrnCmp



// local agent state
STATIC agent_state_t agent_state = {
  .id_string = AGENT_STATE_ID,
  .agent_initialized = FALSE,
  .fuzz_enabled = FALSE,
  .agent_config = { 0 },
  .host_config = { 0 },
  .payload_buffer_size = KAFL_AGENT_PAYLOAD_MAX_SIZE,
  .payload_buffer = (UINT8*) KAFL_AGENT_PAYLOAD_BUF_ADDR,
  .ve_buf = NULL,
  .ve_num = 0,
  .ve_pos = 0,
  .ve_mis = 0,
  .agent_state_address = (UINT8*) KAFL_AGENT_STATE_STRUCT_ADDR
};

STATIC
VOID
EFIAPI
kafl_show_local_state (
  VOID
  )
{
  UINTN as_size = sizeof(agent_state);
  debug_print("kAFL global agent state address at 0x%p, pointing to agent state at 0x%p\n", gKaflAgentStatePtrAddr, *(agent_state_t**)gKaflAgentStatePtrAddr);
  debug_print("kAFL local agent state at 0x%p, size %d (0x%x):\n", &agent_state, as_size, as_size);
  debug_print("  id_string: %a\n", agent_state.id_string);
  debug_print("  agent_initialized: %d\n", agent_state.agent_initialized);
  debug_print("  fuzz_enabled: %d\n", agent_state.fuzz_enabled);
  debug_print("  agent_config: 0x%p\n", agent_state.agent_config);
  debug_print("  host_config: 0x%p\n", agent_state.host_config);
  debug_print("  payload_buffer_size: %d\n", agent_state.payload_buffer_size);
  debug_print("  payload_buffer: 0x%p\n", agent_state.payload_buffer);
  debug_print("  ve_buf: 0x%p\n", agent_state.ve_buf);
  debug_print("  ve_num: %d\n", agent_state.ve_num);
  debug_print("  ve_pos: %d\n", agent_state.ve_pos);
  debug_print("  ve_mis: %d\n", agent_state.ve_mis);
  debug_print("  agent_state_address: 0x%p\n", agent_state.agent_state_address);
}

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

  kafl_show_local_state();
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
    agent_state = *gAS;
    kafl_show_local_state();
  }
}
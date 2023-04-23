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
kafl_show_state (
  VOID
  )
{
  UINTN as_size = sizeof agent_state;
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

/**
  Compare two agent state structs for equality.

  @param ThisState    Pointer to the first agent state struct.
  @param OtherState   Pointer to the second agent state struct.

  @retval TRUE    If both agent states are equal and not NULL
  @retval FALSE   Otherwise
**/
STATIC
BOOLEAN
EFIAPI
state_is_equal (
  agent_state_t *ThisState,
  agent_state_t *OtherState
)
{
  if (ThisState == NULL || OtherState == NULL)
  {
    return FALSE;
  }
  return 0 == CompareMem(ThisState, OtherState, KAFL_AGENT_STATE_STRUCT_SIZE);
}

VOID
EFIAPI
update_global_state (
  VOID
  )
{
  debug_print("update global state\n");

  if (!gKaflAgentStateStructAddr)
  {
    kafl_habort("Invalid agent state struct address.\n");
  }

  //? maybe use copymem instead?
  // CopyMem(gKaflAgentStateStructAddr, &agent_state, KAFL_AGENT_STATE_STRUCT_SIZE);
  *(agent_state_t*)gKaflAgentStateStructAddr = agent_state;

  // verify that data was written correctly
  agent_state_t *gAS = (agent_state_t*)gKaflAgentStateStructAddr;
  if (!state_is_equal(gAS, &agent_state))
  {
    kafl_habort("global & local agent state are not equal after copy!\n");
  }

  debug_print("New kAFL global state:");
  kafl_show_state();
}

VOID
EFIAPI
update_local_state (
  VOID
  )
{
  debug_print("update local state\n");

  if (!gKaflAgentStateStructAddr)
  {
    kafl_habort("Invalid agent state struct address.\n");
  }

  agent_state_t *gAS = (agent_state_t*)gKaflAgentStateStructAddr;
  if ((gAS->id_string == NULL) || (gAS->agent_state_address == 0))
  {
    // global agent state contains only null data -> no need to update local state
    return;
  }

  // check if agent state struct markers are valid
  if (AsciiStrnCmp(gAS->id_string, AGENT_STATE_ID, AGENT_STATE_ID_SIZE) == 0 &&
      gAS->agent_state_address == gKaflAgentStateStructAddr)
  {
    // global agent state was already initialized -> prefer it over file-local state struct
    //? maybe use copymem instead?
    // CopyMem(&agent_state, gAS, KAFL_AGENT_STATE_STRUCT_SIZE);
    agent_state = *gAS;
  }

  debug_print("New kAFL local state:");
  kafl_show_state();
}
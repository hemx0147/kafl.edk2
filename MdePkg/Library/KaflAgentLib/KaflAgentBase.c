/** @file
  kAFL fuzzing agent implementation

**/

#include "KaflAgentLibInternal.h"
#include <Library/BaseMemoryLib.h>    // CompareMem
#include <Library/BaseLib.h>          // AsciiStrnCmp


STATIC UINTN gKaflAgentPayloadMaxBufSize __attribute__((used)) = 0;
STATIC UINT8 *gKaflAgentPayloadBufAddr __attribute__((used)) = NULL;
STATIC UINT8 *gKaflAgentStateStructAddr __attribute__((used)) = NULL;

// local agent state
STATIC agent_state_t g_agent_state = {
  .id_string = AGENT_STATE_ID,
  .agent_initialized = FALSE,
  .fuzz_enabled = FALSE,
  .agent_config = { 0 },
  .host_config = { 0 },
  .payload_buffer_size = 0,
  .payload_buffer = NULL,
  .ve_buf = NULL,
  .ve_num = 0,
  .ve_pos = 0,
  .ve_mis = 0,
  .agent_state_address = NULL
};


VOID
EFIAPI
kafl_show_state (
  VOID
  )
{
  debug_print("kAFL %a\n", __FUNCTION__);
  update_local_state();
  internal_show_state(&g_agent_state);
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

  debug_print("kAFL old state:");
  internal_show_state(&g_agent_state);

  RequestedBytes = internal_fuzz_buffer(fuzz_buf, orig_buf, addr, num_bytes, type, &g_agent_state);
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
  internal_show_state(&g_agent_state);
  internal_fuzz_event(e, &g_agent_state);
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

  // try memcmp for now. If this doesn't work, fall back to member comparison
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
    kafl_habort("Invalid agent state struct address.\n", &g_agent_state);
  }

  CopyMem(gKaflAgentStateStructAddr, &g_agent_state, KAFL_AGENT_STATE_STRUCT_SIZE);

  // verify that data was written correctly
  agent_state_t *gAS = (agent_state_t*)gKaflAgentStateStructAddr;
  if (!state_is_equal(gAS, &g_agent_state))
  {
    kafl_habort("global & local agent state are not equal after copy!\n", &g_agent_state);
  }

  debug_print("kAFL new state:");
  internal_show_state(&g_agent_state);
}

VOID
EFIAPI
update_local_state (
  VOID
  )
{
  debug_print("update local state\n");

  debug_print("kAFL: global state struct addr at 0x%p\n", gKaflAgentStateStructAddr);
  if (!gKaflAgentStateStructAddr)
  {
    kafl_habort("Invalid agent state struct address.\n", &g_agent_state);
  }

  debug_print("kAFL: global state struct addr second time at 0x%p\n", gKaflAgentStateStructAddr);
  agent_state_t *gAS = (agent_state_t*)gKaflAgentStateStructAddr;

  // check if global agent state contains any data except 0
  if ((gAS->id_string == NULL) || (gAS->agent_state_address == 0))
  {
    return;
  }

  // check if agent state struct markers are valid
  if (AsciiStrnCmp(gAS->id_string, AGENT_STATE_ID, AGENT_STATE_ID_SIZE) == 0 &&
      gAS->agent_state_address == gKaflAgentStateStructAddr)
  {
    // global agent state was already initialized -> prefer it over file-local state struct
    CopyMem(&g_agent_state, gAS, KAFL_AGENT_STATE_STRUCT_SIZE);
  }
}

VOID
EFIAPI
kafl_submit_agent_state_addr (
  IN  UINT8   *StateAddr
)
{
  if (!StateAddr)
  {
    kafl_habort("agent state buf is NULL\n", &g_agent_state);
  }

  gKaflAgentStateStructAddr = StateAddr;
  g_agent_state.agent_state_address = StateAddr;
}

VOID
EFIAPI
kafl_submit_payload_buf_addr (
  IN  UINT8   *BufAddr,
  IN  UINTN   MaxBufSize
)
{
  if (!BufAddr) {
    kafl_habort("agent payload buffer space address is NULL\n", &g_agent_state);
  }
  if (MaxBufSize <= 0 || MaxBufSize > KAFL_AGENT_PAYLOAD_MAX_SIZE) {
    kafl_habort("invalid buffer size\n", &g_agent_state);
  }

  gKaflAgentPayloadBufAddr = BufAddr;
  gKaflAgentPayloadMaxBufSize = MaxBufSize;
  g_agent_state.payload_buffer = BufAddr;
  g_agent_state.payload_buffer_size = MaxBufSize;
}
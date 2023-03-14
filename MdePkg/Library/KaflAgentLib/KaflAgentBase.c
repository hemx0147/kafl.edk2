/** @file
  kAFL fuzzing agent implementation

**/

#include "KaflAgentLibInternal.h"


STATIC agent_state_t g_agent_state = { 0 };


VOID
EFIAPI
kafl_agent_done (
  VOID
  )
{
  internal_agent_done(&g_agent_state);
}

VOID
EFIAPI
kafl_show_state (
  VOID
  )
{
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
  return internal_fuzz_buffer(fuzz_buf, orig_buf, addr, num_bytes, type, &g_agent_state);
}


VOID
EFIAPI
kafl_fuzz_event (
  IN  enum kafl_event  e
  )
{
  internal_fuzz_event(e, &g_agent_state);
}
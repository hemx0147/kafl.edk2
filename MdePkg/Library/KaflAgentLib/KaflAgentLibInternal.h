/** @file
  kAFL fuzzing agent definitions

**/

#ifndef _KAFL_AGENT_LIB_INTERNAL_H_
#define _KAFL_AGENT_LIB_INTERNAL_H_

#include <Library/KaflAgentLib.h>
#include <NyxHypercalls.h>


// store agent state as struct in UEFI var to make it available accross compilation units in DXE phase
// Note: keep struct members fixed-length to be able to use copy-assignment operator
typedef struct agent_state_s {
  BOOLEAN agent_initialized;
  BOOLEAN fuzz_enabled;
  UINT8 *ve_buf;
  UINT32 ve_num;
  UINT32 ve_pos;
  UINT32 ve_mis;
} agent_state_t;


VOID
EFIAPI
kafl_raise_panic (
  VOID
);

VOID
EFIAPI
kafl_raise_kasan (
  VOID
);

VOID
EFIAPI
kafl_habort (
  IN  CHAR8   *Msg
);

VOID
EFIAPI
kafl_agent_done (
  IN  agent_state_t   *agent_state
);

VOID
EFIAPI
internal_show_state (
  IN  agent_state_t   *agent_state
);

UINTN
EFIAPI
internal_fuzz_buffer (
  IN  VOID                    *fuzz_buf,
  IN  CONST VOID              *orig_buf,
  IN  CONST UINTN             *addr,
  IN  CONST UINTN             num_bytes,
  IN  CONST enum tdx_fuzz_loc type,
  IN  OUT  agent_state_t      *agent_state
);

VOID
EFIAPI
internal_fuzz_event (
  IN  enum kafl_event  e,
  IN  OUT  agent_state_t *agent_state
);

/**
  Check whether global agent state struct was already initialized and, if yes,
  copy its contents to the local agent state struct.

  If the global agent state was not yet initialized, then the local state
  remains unmodified.
**/
VOID
EFIAPI
update_local_state (
  VOID
);

/**
  Copy the contents of the local agent state to the global agent state.
**/
VOID
EFIAPI
update_global_state (
  VOID
);

/**
  Separate print function for debug prints.
  This way we can disable all prints in kAFL agent, without disabling all debug prints for TDVF.
*/
VOID
EFIAPI
debug_print (
  IN  CONST CHAR8   *Format,
  ...
);
#endif
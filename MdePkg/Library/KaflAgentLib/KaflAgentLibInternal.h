/** @file
  kAFL fuzzing agent definitions

**/

#ifndef _KAFL_AGENT_LIB_INTERNAL_H_
#define _KAFL_AGENT_LIB_INTERNAL_H_

#include <Library/KaflAgentLib.h>
#include <NyxHypercalls.h>


#define ASSUME_ALLOC

// dedicated assert for raising kAFL/harness level issues
#define KAFL_ASSERT(Exp) \
  do { \
    if (!(Exp)) { \
      kafl_hprintf("kAFL ASSERT at %s:%d, %s\n", __FILE__, __LINE__, #Exp); \
      kafl_habort("assertion fail (see hprintf logs)"); \
    } \
  } while (0)


// TODO: check kernel agent implementation for correct definition
typedef struct agent_flags {
  BOOLEAN dump_observed;
  BOOLEAN dump_stats;
  BOOLEAN dump_callers;
} agent_flags;

// store agent state as struct in UEFI var to make it available accross compilation units in DXE phase
// Note: keep struct members fixed-length to be able to use copy-assignment operator
#define AGENT_STATE_ID "KAFLSTATE"
#define AGENT_STATE_ID_SIZE 10     // length of kafl state id string
typedef struct agent_state_s {
  CHAR8 id_string[AGENT_STATE_ID_SIZE];
  BOOLEAN agent_initialized;
  BOOLEAN fuzz_enabled;
  BOOLEAN exit_at_eof;
  agent_flags agent_flags;
  agent_config_t agent_config;
  host_config_t host_config;
  kafl_dump_file_t dump_file;
  UINT8 *payload_buffer;
  UINT8 *observed_buffer;
  UINT8 *ve_buf;
  UINT8 *ob_buf;
  UINTN payload_buffer_size;
  UINTN observed_buffer_size;
  UINT32 ve_num;
  UINT32 ve_pos;
  UINT32 ve_mis;
  UINT32 ob_num;
  UINT32 ob_pos;
  UINT8 *agent_state_address;
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
  CHAR8   *Msg
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

#endif
/** @file
  kAFL fuzzing agent implementation

**/

#include <Library/UefiRuntimeServicesTableLib.h>  // GetVariable, SetVariable
#include <Guid/KaflAgent.h>               // agent state variable GUID & name
#include <KaflAgentLibInternal.h>


STATIC agent_state_t g_agent_state = { 0 };

/**
  Write all current state values to state struct and store it in UEFI variable
  Triggers abort if an error occured while writing the variable.
**/
STATIC
VOID
EFIAPI
kafl_store_agent_state (
  VOID
  )
{
  // TODO: maybe better pass agent state struct explicitly?
  EFI_STATUS Status;

  Status = gRT->SetVariable (
    KAFL_AGENT_STATE_VARIABLE_NAME,
    &gKaflAgentStateVariableGuid,
    EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
    sizeof(agent_state_t),
    &g_agent_state
  );
  if (EFI_ERROR (Status))
  {
    kafl_hprintf("kAFL: write agent state to UEFI variable failed with status %d\n", Status);
    kafl_habort("aborting session\n");
  }
}

/**
  Obtain the kAFL agent state from UEFI variable.

  @retval EFI_SUCCESS if agent state could be read from UEFI variable
  @retval EFI_ABORTED otherwise
**/
STATIC
EFI_STATUS
EFIAPI
kafl_get_agent_state (
  VOID
  )
{
  // TODO: maybe better pass agent state struct explicitly?
  EFI_STATUS Status = EFI_ABORTED;
  UINTN StructSize = sizeof(agent_state_t);

  Status = gRT->GetVariable (
    KAFL_AGENT_STATE_VARIABLE_NAME,
    &gKaflAgentStateVariableGuid,
    NULL,
    &StructSize,
    &g_agent_state
  );

  // either agent was initialized, state can be retrieved from UEFI var and GetVariable succeeds,
  // or agent was not yet initialized, UEFI var does exist and GetVariable returns NOT FOUND.
  // all other cases indicate issues while accessing the variable.
  if ( !( (Status == EFI_SUCCESS) || (Status == EFI_NOT_FOUND)) )
  {
    kafl_hprintf("accessing agent state UEFI variable failed with status %d\n", Status);
    kafl_habort("aborting session\n");
  }
  return Status;
}

VOID
EFIAPI
kafl_agent_done (
  VOID
  )
{
  kafl_get_agent_state();

  if (!g_agent_state.agent_initialized)
  {
    kafl_habort("Attempt to finish kAFL run but never initialized\n");
  }
  internal_agent_done(&g_agent_state);
}

VOID
EFIAPI
kafl_show_state (
  VOID
  )
{
  kafl_get_agent_state();
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
  UINTN NumFuzzed;

  kafl_get_agent_state();
  NumFuzzed = internal_fuzz_buffer(fuzz_buf, orig_buf, addr, num_bytes, type, &g_agent_state);
  kafl_store_agent_state();
  return NumFuzzed;
}


VOID
EFIAPI
kafl_fuzz_event (
  IN  enum kafl_event  e
  )
{
  kafl_get_agent_state();
  internal_fuzz_event(e, &g_agent_state);
  kafl_store_agent_state();
}
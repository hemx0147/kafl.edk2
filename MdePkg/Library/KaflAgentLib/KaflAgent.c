#include <Library/KaflAgentLib.h>

VOID
EFIAPI
kafl_hprintf(
  IN  CONST CHAR8 *Msg
  )
{
  kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (UINTN)Msg);
}
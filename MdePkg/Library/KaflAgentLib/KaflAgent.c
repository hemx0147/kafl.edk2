/** @file
  kAFL fuzzing agent definitions

**/

#include <Library/DebugLib.h>
#include <Library/PrintLib.h>       // AsciiVSPrint, AsciiVBPrint
#include <Uefi/UefiBaseType.h>      // EFI_PAGE_MASK
#include <Library/KaflAgentLib.h>
#include "NyxHypercalls.h"

#define pr_fmt(fmt) "kAFL: " fmt
#define pr_warn(fmt, ...) \
  DEBUG ((DEBUG_WARN, pr_fmt(fmt), ##__VA_ARGS__))

//
// Define the maximum debug and assert message length that this library supports
//
#define MAX_DEBUG_MESSAGE_LENGTH  0x100

BOOLEAN AgentInitialized = FALSE;
BOOLEAN FuzzEnabled = FALSE;

CONST CHAR8 *KaflEventName[KAFL_EVENT_MAX] = {
  "KAFL_ENABLE",
  "KAFL_START",
  "KAFL_ABORT",
  "KAFL_SETCR3",
  "KAFL_DONE",
  "KAFL_PANIC",
  "KAFL_KASAN",
  "KAFL_UBSAN",
  "KAFL_HALT",
  "KAFL_REBOOT",
  "KAFL_SAFE_HALT",
  "KAFL_TIMEOUT",
  "KAFL_ERROR",
  "KAFL_PAUSE",
  "KAFL_RESUME",
  "KAFL_TRACE",
};

STATIC
VOID
EFIAPI
kafl_raise_panic (
  VOID
  )
{
  kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
}

STATIC
VOID
EFIAPI
kafl_raise_kasan (
  VOID
  )
{
  kAFL_hypercall(HYPERCALL_KAFL_KASAN, 0);
}

STATIC
VOID
EFIAPI
kafl_agent_setrange (
  UINTN   Id,
  VOID    *Start,
  VOID    *End
  )  __attribute__ ((unused));

STATIC
VOID
EFIAPI
kafl_agent_setrange (
  UINTN   Id,
  VOID    *Start,
  VOID    *End
  )
{
  // TODO: use correct type for uintptr_t (maybe not UINTN?)
  UINTN   Range[3];

  Range[0] = (UINTN)Start & (UINTN)EFI_PAGE_MASK;
  Range[1] = ((UINTN)End + (UINTN)EFI_PAGE_SIZE - 1) & (UINTN)EFI_PAGE_MASK;
  Range[2] = Id;

  kafl_hprintf("Setting range %lu: %lx-%lx\n", Range[2], Range[0], Range[1]);
  kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (UINTN)Range);
}

STATIC
VOID
EFIAPI
kafl_habort (
  CHAR8   *Msg
  )
{
  kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, (UINTN)Msg);
}

// dedicated assert for raising kAFL/harness level issues
#define KAFL_ASSERT(Exp) \
  do { \
    if (!(Exp)) { \
      kafl_hprintf("kAFL ASSERT at %s:%d, %s\n", __FILE__, __LINE__, #Exp); \
      kafl_habort("assertion fail (see hprintf logs)"); \
    } \
  } while (0)

STATIC
VOID
hprintf_marker (
  IN  CONST CHAR8   *Format,
  IN  VA_LIST       VaListMarker,
  IN  BASE_LIST     BaseListMarker
  )
{
  CHAR8   Buffer[MAX_DEBUG_MESSAGE_LENGTH];

  //
  // If Format is NULL, then ASSERT().
  //
  if (Format == NULL)
  {
    kafl_habort("hprintf format is NULL\n");
  }

  //
  // Convert the hprintf() message to an ASCII String
  //
  if (BaseListMarker == NULL) {
    AsciiVSPrint (Buffer, sizeof (Buffer), Format, VaListMarker);
  } else {
    AsciiBSPrint (Buffer, sizeof (Buffer), Format, BaseListMarker);
  }

  //
  // Print string with kAFL hprintf
  //
  kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (UINTN)Buffer);
}

VOID
EFIAPI
kafl_hprintf (
  IN  CONST CHAR8   *Format,
  ...
  )
{
  VA_LIST   Marker;

  VA_START (Marker, Format);
  hprintf_marker (Format, Marker, NULL);
  VA_END (Marker);
}

STATIC
VOID
EFIAPI
kafl_agent_init (
  VOID
  )
{
  // TODO: implement me
  return;
}

STATIC
VOID
EFIAPI
kafl_agent_done (
  VOID
  )
{
  // TODO: implement me
  return;
}

VOID
EFIAPI
kafl_fuzz_event (
  IN  enum KaflEvent  E
  )
{
  // pre-init actions
  switch(E)
  {
    case KAFL_START:
      pr_warn("[*] Agent start!\n");
      kafl_agent_init();
      FuzzEnabled = TRUE;
      return;
    case KAFL_ENABLE:
      pr_warn("[*] Agent enable!\n");
      /* fallthrough */
    case KAFL_RESUME:
      FuzzEnabled = TRUE;
      return;
    case KAFL_DONE:
      return kafl_agent_done();
    case KAFL_ABORT:
      return kafl_habort("kAFL got ABORT event.\n");
    default:
      break;
  }

  if (!AgentInitialized)
  {
    pr_warn("Got event %s but not initialized?!\n", KaflEventName[E]);
    return;
  }

  // post-init actions - abort if we see these before FuzzInitialized=TRUE
  // Use this table to selectively raise error conditions
  switch(E)
  {
    case KAFL_KASAN:
    case KAFL_UBSAN:
      return kafl_raise_kasan();
    case KAFL_PANIC:
    case KAFL_ERROR:
    case KAFL_HALT:
    case KAFL_REBOOT:
      return kafl_raise_panic();
    case KAFL_TIMEOUT:
      return kafl_habort("TODO: add a timeout handler?!\n");
    default:
      return kafl_habort("Unrecognized fuzz event.\n");
  }
}
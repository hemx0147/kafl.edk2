/** @file
  kAFL fuzzing agent definitions

**/

#ifndef _KAFL_AGENT_LIB_H_
#define _KAFL_AGENT_LIB_H_

#include <Base.h>
#include <Library/DebugLib.h>
#include <Uefi/UefiBaseType.h>  // EFI_PAGE_MASK
#include <Library/PrintLib.h>   // AsciiVSPrint, AsciiVBPrint
#include "NyxHypercalls.h"

enum KaflEvent {
	KAFL_ENABLE,
	KAFL_START,
	KAFL_ABORT,
	KAFL_SETCR3,
	KAFL_DONE,
	KAFL_PANIC,
	KAFL_KASAN,
	KAFL_UBSAN,
	KAFL_HALT,
	KAFL_REBOOT,
	KAFL_SAFE_HALT,
	KAFL_TIMEOUT,
	KAFL_ERROR,
	KAFL_PAUSE,
	KAFL_RESUME,
	KAFL_TRACE,
	KAFL_EVENT_MAX
};

VOID
EFIAPI
kafl_fuzz_event(
  IN  enum KaflEvent E
);

VOID
EFIAPI
kafl_hprintf(
  IN  CONST CHAR8   *Format,
  ...
);

#endif
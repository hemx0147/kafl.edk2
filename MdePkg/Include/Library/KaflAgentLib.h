/** @file
  kAFL fuzzing agent definitions

**/

#ifndef _KAFL_AGENT_LIB_H_
#define _KAFL_AGENT_LIB_H_

#include <Base.h>   // UEFI definitions

enum kafl_event {
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

enum tdx_fuzz_loc {
  TDX_FUZZ_MSR_READ,
  TDX_FUZZ_MMIO_READ,
  TDX_FUZZ_PORT_IN,
  TDX_FUZZ_CPUID1,
  TDX_FUZZ_CPUID2,
  TDX_FUZZ_CPUID3,
  TDX_FUZZ_CPUID4,
  TDX_FUZZ_MSR_READ_ERR,
  TDX_FUZZ_MSR_WRITE_ERR,
  TDX_FUZZ_MAP_ERR,
  TDX_FUZZ_PORT_IN_ERR,
  TDX_FUZZ_VIRTIO,
  TDX_FUZZ_RANDOM,  /* kAFL */
  TDX_FUZZ_DEBUGFS, /* kAFL */
  TDX_FUZZ_MAX
};

VOID
EFIAPI
kafl_fuzz_event (
  IN  enum kafl_event  e
);

VOID
EFIAPI
kafl_hprintf (
  IN  CONST CHAR8   *Format,
  ...
);

#endif
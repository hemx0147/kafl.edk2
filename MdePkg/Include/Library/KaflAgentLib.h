/** @file
  kAFL fuzzing agent definitions

**/

#ifndef _KAFL_AGENT_LIB_H_
#define _KAFL_AGENT_LIB_H_

#include <Uefi/UefiBaseType.h>   // UEFI definitions


/** KAFL HARNESS CONFIGURATION START **/
// #define CONFIG_KAFL_FUZZ_BOOT_LOADER
// #define CONFIG_KAFL_FUZZ_VIRTIO_READ
#define CONFIG_KAFL_FUZZ_BLK_DEV_INIT
/** KAFL HARNESS CONFIGURATION END **/

//! keep consistent with sizeof(agent_state_t)
#define KAFL_AGENT_STATE_STRUCT_SIZE 128
//! keep consistent with real address of agent state struct in SecMain
#define KAFL_AGENT_STATE_STRUCT_ADDR 0xFFFDEFF4
STATIC UINT8 *gKaflAgentStateStructAddr __attribute__((used)) = (UINT8*) KAFL_AGENT_STATE_STRUCT_ADDR;

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
  TDX_FUZZ_VIRTIO,
  TDX_FUZZ_BOOT_LOADER,
  TDX_FUZZ_BLK_DEV_INIT,
  TDX_FUZZ_MAX
};

VOID
EFIAPI
kafl_fuzz_event (
  IN  enum kafl_event  e
);

UINTN
EFIAPI
kafl_fuzz_buffer (
  IN  OUT   VOID                *fuzz_buf,
  IN  CONST VOID                *orig_buf,
  IN  CONST UINTN               *addr,
  IN  CONST UINTN               num_bytes,
  IN  CONST enum tdx_fuzz_loc   type
);

VOID
EFIAPI
kafl_hprintf (
  IN  CONST CHAR8   *Format,
  ...
);

VOID
EFIAPI
kafl_dump_buffer (
  IN  UINT8   *Buf,
  IN  UINTN   BufSize
);

VOID
EFIAPI
kafl_show_state (
  VOID
);

#endif
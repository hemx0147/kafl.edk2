/** @file
  kAFL fuzzing agent definitions

**/

#ifndef _KAFL_AGENT_LIB_H_
#define _KAFL_AGENT_LIB_H_

#include <Uefi/UefiBaseType.h>   // UEFI definitions


/** KAFL HARNESS CONFIGURATION START **/
/** KAFL HARNESS CONFIGURATION END **/

// fuzzing harnesses that target early boot components can set this flag to use stack memory instead of heap allocations
#ifndef KAFL_EARLY_BOOT_FUZZING
// memory allocation functions can be used only for targets that run later in boot process (triggers assertion for early targets e.g. in TdxStartup.c)
# define KAFL_ASSUME_ALLOC
#endif

#define KAFL_DEBUG_PRINT_ACTIVE
// allocate only few pages for buffer (larger values (e.g. default value of 32) may cause errors)
#define KAFL_AGENT_PAYLOAD_MAX_SIZE (16 * EFI_PAGE_SIZE)


//! keep consistent with real addresses of agent state struct and payload buffer in SecMain.c
#define KAFL_AGENT_PAYLOAD_BUF_ADDR 0x80F000
#define KAFL_AGENT_STATE_STRUCT_ADDR 0x80ECA0
STATIC UINT8 *gKaflAgentPayloadBufAddr __attribute__((used)) = (UINT8*) KAFL_AGENT_PAYLOAD_BUF_ADDR;
STATIC VOID **gKaflAgentStatePtrAddr __attribute__((used)) = (VOID**) KAFL_AGENT_STATE_STRUCT_ADDR;

enum kafl_event {
  KAFL_ENABLE,
  KAFL_START,
  KAFL_DONE,
  KAFL_PANIC,
  KAFL_ABORT,
  KAFL_EVENT_MAX
};

VOID
EFIAPI
kafl_fuzz_event (
  IN  enum kafl_event  event
);

UINTN
EFIAPI
kafl_fuzz_buffer (
  IN OUT  VOID          *fuzz_buf,
  IN      CONST UINTN   num_bytes
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

#endif
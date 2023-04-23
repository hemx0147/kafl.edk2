/** @file
  kAFL fuzzing agent definitions

**/

#ifndef _KAFL_AGENT_LIB_H_
#define _KAFL_AGENT_LIB_H_

#include <Uefi/UefiBaseType.h>   // UEFI definitions


// Note: CONFIG_KAFL_FUZZ_BLK_DEV_MEDIA_SMALL excludes CONFIG_KAFL_FUZZ_BLK_DEV_MEDIA_LARGE

/** KAFL HARNESS CONFIGURATION START **/
// #define CONFIG_KAFL_FUZZ_BOOT_LOADER
// #define CONFIG_KAFL_FUZZ_VIRTIO_READ
// #define CONFIG_KAFL_FUZZ_BLK_DEV_INIT
// #define CONFIG_KAFL_FUZZ_BLK_DEV_MEDIA_SMALL
// #define CONFIG_KAFL_FUZZ_BLK_DEV_MEDIA_LARGE
#define CONFIG_KAFL_FUZZ_TDHOB
/** KAFL HARNESS CONFIGURATION END **/

// assume that we can use memory allocation functions only for targets that run later in boot process
// trying to use allocation functions in TdHob harness (i.e. in TdxStartup.c) results in triggered assertion
#ifndef CONFIG_KAFL_FUZZ_TDHOB
# define KAFL_ASSUME_ALLOC
#else
// size of the fuzzing payload to be injected as TdHob (730 is same size as MAGIC_TDHOB)
# define KAFL_AGENT_TDHOB_FUZZ_SIZE 730
#endif

#define KAFL_DEBUG_PRINT_ACTIVE
// allocate only few pages for buffer (larger values (e.g. default value of 32) may cause errors)
#define KAFL_AGENT_PAYLOAD_MAX_SIZE (16 * EFI_PAGE_SIZE)


//! keep consistent with sizeof(agent_state_t)
#define KAFL_AGENT_STATE_STRUCT_SIZE 128
//! keep consistent with real addresses of agent state struct and payload buffer in SecMain.c
#define KAFL_AGENT_PAYLOAD_BUF_ADDR 0x80F000
#define KAFL_AGENT_STATE_STRUCT_ADDR 0x80ED50
STATIC UINT8 *gKaflAgentPayloadBufAddr __attribute__((used)) = (UINT8*) KAFL_AGENT_PAYLOAD_BUF_ADDR;
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
  TDX_FUZZ_VIRTIO_PCI_IO,
  TDX_FUZZ_BLK_DEV_MEDIA,
  TDX_FUZZ_TDHOB,
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

#endif
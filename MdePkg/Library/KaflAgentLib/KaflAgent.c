/** @file
  kAFL fuzzing agent definitions

**/

#include <Library/DebugLib.h>
#include <Library/PrintLib.h>       // AsciiVSPrint, AsciiVBPrint
#include <Uefi/UefiBaseType.h>      // EFI_PAGE_MASK
#include <Library/KaflAgentLib.h>
#include <Library/BaseMemoryLib.h>  // ZeroMem
#include <Library/MemoryAllocationLib.h>  // AllocateAlignedPages
#include "NyxHypercalls.h"

#define pr_fmt(fmt) "kAFL: " fmt
#define pr_warn(fmt, ...) \
  DEBUG ((DEBUG_WARN, pr_fmt(fmt), ##__VA_ARGS__))

//
// Define the maximum debug and assert message length that this library supports
//
#define MAX_DEBUG_MESSAGE_LENGTH  0x100

BOOLEAN agent_initialized = FALSE;
BOOLEAN fuzz_enabled = FALSE;

agent_config_t agent_config = { 0 };
host_config_t host_config = { 0 };

// AllocatePool/AllocatePages might not be available at early boot
#define KAFL_ASSUME_ALLOC
#ifdef KAFL_ASSUME_ALLOC
UINTN payload_buffer_size = 0;
UINTN observed_buffer_size = 0;
UINT8 *payload_buffer = NULL;
UINT8 *observed_buffer = NULL;
#else
UINTN payload_buffer_size = PAYLOAD_MAX_SIZE;
UINT8 payload_buffer[PAYLOAD_MAX_SIZE] __attribute__((aligned(EFI_PAGE_SIZE)));
#endif


UINT8 *ve_buf;
UINT32 ve_num;
UINT32 ve_pos;
UINT32 ve_mis;

UINT8 *ob_buf;
UINT32 ob_num;
UINT32 ob_pos;

CONST CHAR8 *kafl_event_name[KAFL_EVENT_MAX] = {
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
  kAFL_payload *payload = NULL;
#ifdef KAFL_ASSUME_ALLOC
  UINTN payload_buf_pages;
  UINTN observed_buf_pages;
#endif

  if (agent_initialized)
  {
    kafl_habort("Warning: Agent was already initialized!\n");
  }

  kafl_hprintf("[*] Initialize kAFL Agent\n");

  //
  // initial fuzzer handshake
  //
  kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

  //? do we need kafl user submit mode?

  //
  // acquire host configuration
  //
  kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (UINTN)&host_config);
  kafl_hprintf("[host_config] bitmap sizes = <0x%x,0x%x>\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
  kafl_hprintf("[host_config] payload size = %dKB\n", host_config.payload_buffer_size/1024);
  kafl_hprintf("[host_config] worker id = %02u\n", host_config.worker_id);

  //
  // check if host config is valid
  //
  if (host_config.host_magic != NYX_HOST_MAGIC ||
      host_config.host_version != NYX_HOST_VERSION) {
    kafl_hprintf("host_config magic/version mismatch!\n");
    kafl_habort("GET_HOST_CNOFIG magic/version mismatch!\n");
  }

  //
  // allocate payload/observed buffer if AllocateAlignedPages is available
  //
#ifdef KAFL_ASSUME_ALLOC
  pr_warn("kAFL %a: Using page allocation functions for payload buffer\n", __FUNCTION__);
  payload_buffer_size = host_config.payload_buffer_size;
  observed_buffer_size = 2*host_config.payload_buffer_size;
  payload_buf_pages = (payload_buffer_size % EFI_PAGE_SIZE) == 0 ? payload_buffer_size / EFI_PAGE_SIZE : ((UINTN)(payload_buffer_size / EFI_PAGE_SIZE)) + 1;
  observed_buf_pages = (observed_buffer_size % EFI_PAGE_SIZE) == 0 ? observed_buffer_size / EFI_PAGE_SIZE : ((UINTN)(observed_buffer_size / EFI_PAGE_SIZE)) + 1;
  payload_buffer = (UINT8 *)AllocateAlignedPages(payload_buf_pages, EFI_PAGE_SIZE);
  observed_buffer = (UINT8 *)AllocateAlignedPages(observed_buf_pages, EFI_PAGE_SIZE);

  if (!payload_buffer)
  {
    kafl_habort("Failed to allocate host payload buffer!\n");
  }
#else
  pr_warn("Page allocation functions unavailable, using stack for payload buffer instead\n");
  if (host_config.payload_buffer_size > PAYLOAD_MAX_SIZE)
  {
    kafl_habort("Insufficient payload buffer size!\n");
  }
#endif  // KAFL_ASSUME_ALLOC

  //
  // ensure payload is paged in
  //
  SetMem(payload_buffer, payload_buffer_size, 0xff);
  SetMem(observed_buffer, observed_buffer_size, 0xff);

  //
  // submit payload buffer address to HV
  //
  kafl_hprintf("kAFL %a: Submitting payload buffer address to hypervisor (0x%lx)\n", __FUNCTION__, (UINTN)payload_buffer);
  kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINTN)payload_buffer);

  //
  // submit agent config
  //
  //? add other values from kafl.linux kafl-agent.c as well?
  agent_config.agent_magic = NYX_AGENT_MAGIC;
  agent_config.agent_version = NYX_AGENT_VERSION;
  agent_config.agent_tracing = 0; // trace by host!
  agent_config.agent_ijon_tracing = 0; // no IJON
  agent_config.agent_non_reload_mode = 1; // allow persistent
  agent_config.coverage_bitmap_size = host_config.bitmap_size;
  kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (UINTN)&agent_config);

  //? set IntelPt range based on exported linker map symbols?

  //
  // fetch fuzz input for later #VE injection
  //
  kafl_hprintf("Starting kAFL loop...\n");
  kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

  payload = (kAFL_payload *)payload_buffer;
  ve_buf = payload->data;
  ve_num = payload->size;
  ve_pos = 0;
  ve_mis = 0;

  // TODO: add kafl stats clear

  agent_initialized = TRUE;

  //
  // start coverage tracing
  //
  kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
}

STATIC
VOID
EFIAPI
kafl_agent_done (
  VOID
  )
{
  if (!agent_initialized)
  {
    kafl_habort("kAFL: Attempt to finish kAFL run but never initialized\n");
  }


  //
  // Stop tracing and restore the snapshot for next round
  // Non-zero argument triggers stream_expand mutation in kAFL
  //
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, ve_mis*sizeof(ve_buf[0]));
}

VOID
EFIAPI
kafl_fuzz_event (
  IN  enum kafl_event  e
  )
{
  // pre-init actions
  switch(e)
  {
    case KAFL_START:
      pr_warn("[*] Agent start!\n");
      kafl_agent_init();
      fuzz_enabled = TRUE;
      return;
    case KAFL_ENABLE:
      pr_warn("[*] Agent enable!\n");
      /* fallthrough */
    case KAFL_RESUME:
      fuzz_enabled = TRUE;
      return;
    case KAFL_DONE:
      return kafl_agent_done();
    case KAFL_ABORT:
      return kafl_habort("kAFL got ABORT event.\n");
    default:
      break;
  }

  if (!agent_initialized)
  {
    pr_warn("Got event %s but not initialized?!\n", kafl_event_name[e]);
    return;
  }

  // post-init actions - abort if we see these before FuzzInitialized=TRUE
  // Use this table to selectively raise error conditions
  switch(e)
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
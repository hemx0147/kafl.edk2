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

BOOLEAN AgentInitialized = FALSE;
BOOLEAN FuzzEnabled = FALSE;

agent_config_t AgentConfig = { 0 };
host_config_t HostConfig = { 0 };

// AllocatePool/AllocatePages might not be available at early boot
#define KAFL_ASSUME_ALLOC
#ifdef KAFL_ASSUME_ALLOC
UINTN PayloadBufferSize = 0;
UINTN ObservedBufferSize = 0;
UINT8 *PayloadBuffer = NULL;
UINT8 *ObservedBuffer = NULL;
#else
UINTN PayloadBufferSize = PAYLOAD_MAX_SIZE;
UINTN ObservedBufferSize = 2 * PAYLOAD_MAX_SIZE;
UINT8 PayloadBuffer[PAYLOAD_MAX_SIZE] __attribute__((aligned(EFI_PAGE_SIZE)));
UINT8 *ObservedBuffer[2 * PAYLOAD_MAX_SIZE] __attribute__((aligned(EFI_PAGE_SIZE)));
#endif

UINT8 *VeBuf;
UINT32 VeNum;
UINT32 VePos;
UINT32 VeMis;

UINT8 *ObBuf;
UINT32 *ObNum;
UINT32 *ObPos;

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
  kAFL_payload *Payload = NULL;
  UINTN PayloadBufferNumPages;
  UINTN ObservedBufferNumPages;

  if (AgentInitialized)
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
  kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (UINTN)&HostConfig);
  kafl_hprintf("[HostConfig] bitmap sizes = <0x%x,0x%x>\n", HostConfig.bitmap_size, HostConfig.ijon_bitmap_size);
  kafl_hprintf("[HostConfig] payload size = %dKB\n", HostConfig.payload_buffer_size/1024);
  kafl_hprintf("[HostConfig] worker id = %02u\n", HostConfig.worker_id);

  //
  // check if host config is valid
  //
  if (HostConfig.host_magic != NYX_HOST_MAGIC ||
      HostConfig.host_version != NYX_HOST_VERSION) {
    hprintf("HostConfig magic/version mismatch!\n");
    habort("GET_HOST_CNOFIG magic/version mismatch!\n");
  }

  //
  // allocate payload/observed buffer if AllocateAlignedPages is available
  //
#ifdef KAFL_ASSUME_ALLOC
  pr_warn("Using page allocation functions for payload buffer\n");
  PayloadBufferSize = HostConfig.payload_buffer_size;
  ObservedBufferSize = 2 * HostConfig.payload_buffer_size;
  PayloadBufferNumPages = (PayloadBufferSize % EFI_PAGE_SIZE) == 0 ? PayloadBufferSize / EFI_PAGE_SIZE : (UINTN)(PayloadBufferSize / EFI_PAGE_SIZE) + 1;
  ObservedBufferNumPages = (ObservedBufferSize % EFI_PAGE_SIZE) == 0 ? ObservedBufferSize / EFI_PAGE_SIZE : (UINTN)(ObservedBufferSize / EFI_PAGE_SIZE) + 1;
  PayloadBuffer = (UINT8 *)AllocateAlignedPages(PayloadBufferNumPages, EFI_PAGE_SIZE);
  ObservedBuffer = (UINT8 *)AllocateAlignedPages(ObservedBufferNumPages, EFI_PAGE_SIZE);

  if (!PayloadBuffer || !ObservedBuffer)
  {
    kafl_habort("Failed to allocate host payload buffer!\n");
  }
#else
  pr_warn("Page allocation functions unavailable, using stack for payload buffer instead\n");
  if (HostConfig.payload_buffer_size > PAYLOAD_MAX_SIZE)
  {
    kafl_habort("Insufficient payload buffer size!\n");
  }
#endif  // KAFL_ASSUME_ALLOC

  //
  // ensure payload is paged in
  //
  // TODO: verify that payload buffer was written with correct value
  SetMem(PayloadBuffer, PayloadBufferSize, 0xff);
  SetMem(ObservedBuffer, ObservedBufferSize, 0xff);

  //
  // submit payload buffer address to HV
  //
  kafl_hprintf("Submitting payload buffer address to hypervisor (%lx)\n", (UINTN)PayloadBuffer);
  kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINTN)PayloadBuffer);

  //
  // submit agent config
  //
  //? add other values from kafl.linux kafl-agent.c as well?
  AgentConfig.agent_magic = NYX_AGENT_MAGIC;
  AgentConfig.agent_version = NYX_AGENT_VERSION;
  AgentConfig.agent_tracing = 0; // trace by host!
  AgentConfig.agent_ijon_tracing = 0; // no IJON
  AgentConfig.agent_non_reload_mode = 1; // allow persistent
  AgentConfig.coverage_bitmap_size = HostConfig.bitmap_size;
  kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (UINTN)&AgentConfig);

  //? set IntelPt range based on exported linker map symbols?

  //
  // fetch fuzz input for later #VE injection
  //
  kafl_hprintf("Starting kAFL loop...\n");
  kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

  Payload = (kAFL_payload *)PayloadBuffer;
  VeBuf = Payload->data;
  VeNum = Payload->size;
  VePos = 0;
  VeMis = 0;

  //? what about kafl vanilla payload?

  // TODO: add kafl stats clear

  AgentInitialized = TRUE;

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
  if (!AgentInitialized)
  {
    kafl_habort("Attempt to finish kAFL run but never initialized\n");
  }

  // TODO: add kafl agent stats

  //
  // Stop tracing and restore the snapshot for next round
  // Non-zero argument triggers stream_expand mutation in kAFL
  //
  kafl_hprintf("Exiting kAFL loop...\n");
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, VeMis*sizeof(VeBuf[0]));
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
/** @file
  kAFL fuzzing agent implementation

**/

#include <Library/BaseLib.h>              // AsciiStrnCpyS
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>             // AsciiVSPrint, AsciiVBPrint
#include <Uefi/UefiBaseType.h>            // EFI_PAGE_MASK, EFI_SIZE_TO_PAGES
#include <Library/BaseMemoryLib.h>        // SetMem, CopyMem
#include <Library/MemoryAllocationLib.h>  // AllocateAlignedPages

#include <KaflAgentLibInternal.h>


#define pr_fmt(fmt) "kAFL: " fmt
#define pr_warn(fmt, ...) \
  DEBUG ((DEBUG_WARN, pr_fmt(fmt), ##__VA_ARGS__))

//
// Define the maximum debug and assert message length that this library supports
//
#define MAX_DEBUG_MESSAGE_LENGTH  0x100

// abort at end of payload - otherwise we keep feeding unmodified input
// which means we see coverage that is not represented in the payload
// agent_state.exit_at_eof = TRUE;


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

VOID
EFIAPI
kafl_raise_panic (
  VOID
  )
{
  kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
}

VOID
EFIAPI
kafl_raise_kasan (
  VOID
  )
{
  kAFL_hypercall(HYPERCALL_KAFL_KASAN, 0);
}

VOID
EFIAPI
kafl_habort (
  CHAR8   *Msg
  )
{
  kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, (UINTN)Msg);
}

VOID
EFIAPI
kafl_dump_buffer (
  IN  UINT8   *Buf,
  IN  UINTN   BufSize
  )
{
  UINTN Pos;

  kafl_hprintf("DumpBuffer 0x%p (%d (0x%x) bytes): [", Buf, BufSize, BufSize);

  for (Pos = 0; Pos < BufSize; Pos++)
  {
    if (Pos != 0)
    {
      kafl_hprintf(" ");
    }
    kafl_hprintf("%02x", Buf[Pos]);
  }
  kafl_hprintf("]\n");
}

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

VOID
EFIAPI
internal_agent_done (
  IN  agent_state_t   *agent_state
  )
{
  UINT64 ReleaseNum;

  // TODO: add agent stats / file dumping of agent stats

  //
  // Stop tracing and restore the snapshot for next round
  // Non-zero argument triggers stream_expand mutation in kAFL
  //
  kafl_hprintf("kAFL %a: Exiting kAFL loop\n", __FUNCTION__);
  ReleaseNum = agent_state->ve_mis * sizeof((agent_state->ve_buf)[0]);
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, ReleaseNum);
}

VOID
EFIAPI
internal_show_state (
  agent_state_t *agent_state
  )
{
  kafl_hprintf("kAFL: print current fuzzer state\n");
  kafl_hprintf("  agent_init: %d\n", agent_state->agent_initialized);
  kafl_hprintf("  fuzz_enabled: %d\n", agent_state->fuzz_enabled);
}

// TODO: create fns for setting variable init values, set-/copy-/allocate memory
STATIC
VOID
EFIAPI
kafl_agent_init (
  IN  OUT agent_state_t   *agent_state
  )
{
  UINTN payload_buffer_size;
  UINTN observed_buffer_size;
  UINT8 *payload_buffer;
  UINT8 *observed_buffer;
  UINT8 *ve_buf;
  UINT32 ve_num;
  UINT32 ve_pos;
  UINT32 ve_mis;
  UINT8 *ob_buf;
  UINT32 ob_num;
  UINT32 ob_pos;
  kAFL_payload *payload;
  host_config_t host_config = {0};
  agent_config_t agent_config = {0};
  agent_flags agent_flags = {0};

  if (agent_state->agent_initialized)
  {
    kafl_habort("Warning: Agent was already initialized!\n");
  }

  kafl_hprintf("[*] Initialize kAFL Agent\n");

  //
  // initial fuzzer handshake
  //
  kafl_hprintf("kAFL: initial fuzzer handshake\n");
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
  // allocate page-aligned payload/observed buffer
  //
  payload_buffer_size = host_config.payload_buffer_size;
  observed_buffer_size = 2*host_config.payload_buffer_size;
  payload_buffer = (UINT8*)AllocateAlignedPages(EFI_SIZE_TO_PAGES(payload_buffer_size), EFI_PAGE_SIZE);
  observed_buffer = (UINT8*)AllocateAlignedPages(EFI_SIZE_TO_PAGES(observed_buffer_size), EFI_PAGE_SIZE);
  kafl_hprintf("kAFL %a: allocated %d bytes for payload at 0x%p\n", __FUNCTION__, payload_buffer_size, payload_buffer);
  kafl_hprintf("kAFL %a: allocated %d bytes for observed at 0x%p\n", __FUNCTION__, observed_buffer_size, observed_buffer);

  if (!payload_buffer)
  {
    kafl_habort("kAFL: Failed to allocate host payload buffer!\n");
  }

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
  kafl_hprintf("kAFL %a: submit agent config\n", __FUNCTION__);
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
  kafl_hprintf("kAFL %a: Starting kAFL loop...\n", __FUNCTION__);
  kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

  payload = (kAFL_payload *)payload_buffer;
  ve_buf = payload->data;
  ve_num = payload->size;
  ve_pos = 0;
  ve_mis = 0;
  kafl_hprintf("kAFL %a: set payload to 0x%p, ve_buf: 0x%p, ve_num: %d\n", __FUNCTION__, payload, ve_buf, ve_num);

  if (payload->flags.raw_data != 0)
  {
    kafl_hprintf("Runtime payload->flags=0x%04x\n", payload->flags.raw_data);
    kafl_hprintf("\t dump_observed = %u\n",         payload->flags.dump_observed);
    kafl_hprintf("\t dump_stats = %u\n",            payload->flags.dump_stats);
    kafl_hprintf("\t dump_callers = %u\n",          payload->flags.dump_callers);

    // debugfs cannot handle the bitfield..
    agent_flags.dump_observed = payload->flags.dump_observed;
    agent_flags.dump_stats    = payload->flags.dump_stats;
    agent_flags.dump_callers  = payload->flags.dump_callers;

    // dump modes are exclusive - sharing the observed_* and ob_* buffers
    KAFL_ASSERT(!(agent_flags.dump_observed && agent_flags.dump_callers));
    KAFL_ASSERT(!(agent_flags.dump_observed && agent_flags.dump_stats));
    KAFL_ASSERT(!(agent_flags.dump_callers  && agent_flags.dump_stats));
  }

  if (agent_flags.dump_observed) {
    ob_buf = observed_buffer;
    ob_num = sizeof(observed_buffer);
    ob_pos = 0;
  }
  kafl_hprintf("kAFL %a: set observed buf: 0x%p, ob_num: %d\n", __FUNCTION__, ob_buf, ob_num);

  // TODO: add kafl stats clear

  // TODO: add all other agent state changes

  //
  // initialize agent state
  //
  kafl_hprintf("kAFL %a: initialize agent state\n", __FUNCTION__);
  agent_state->agent_initialized = TRUE;
  agent_state->payload_buffer = payload_buffer;
  agent_state->payload_buffer_size = payload_buffer_size;
  agent_state->observed_buffer = observed_buffer;
  agent_state->observed_buffer_size = observed_buffer_size;
  agent_state->agent_flags = agent_flags;
  agent_state->host_config = host_config;
  agent_state->agent_config = agent_config;
  agent_state->ve_buf = ve_buf;
  agent_state->ve_num = ve_num;
  agent_state->ve_pos = ve_pos;
  agent_state->ve_mis = ve_mis;
  agent_state->ob_buf = ob_buf;
  agent_state->ob_num = ob_num;
  agent_state->ob_pos = ob_pos;

  //
  // start coverage tracing
  //
  kafl_hprintf("kAFL %a: start coverage tracking\n", __FUNCTION__);
  kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
}

STATIC
UINTN
EFIAPI
_internal_fuzz_buffer (
  IN      VOID          *buf,
  IN OUT  CONST UINTN   num_bytes,
  IN OUT  agent_state_t *agent_state
  )
{
  UINT8 *ve_buf = agent_state->ve_buf;
  UINT32 ve_pos = agent_state->ve_pos;
  UINT32 ve_num = agent_state->ve_num;
  UINT32 ve_mis = agent_state->ve_mis;

  // TODO: fuzzer kickstart value must be at least num_bytes larger, otherwise fuzzer won't work
  kafl_hprintf("kAFL %a: Fuzz buf 0x%p Size %d (0x%x)\n", __FUNCTION__, buf, num_bytes, num_bytes);
  kafl_hprintf("kAFL %a: ve_pos: %d, num_bytes: %d, ve_pos + num_bytes: %d, ve_num: %d\n", __FUNCTION__, ve_pos, num_bytes, ve_pos + num_bytes, ve_num);
  if (ve_pos + num_bytes <= ve_num)
  {
    kafl_hprintf("kAFL %a: CopyMem ve_pos + ve_buf: %d, num_bytes: %d\n", __FUNCTION__, ve_pos + ve_buf, num_bytes);
    CopyMem(buf, ve_buf + ve_pos, num_bytes);
    ve_pos += num_bytes;
    agent_state->ve_pos = ve_pos;
    kafl_hprintf("kAFL %a: new ve_pos: %d\n", __FUNCTION__, ve_pos);
    return num_bytes;
  }

  //
  // insufficient fuzz buffer
  //
  ve_mis += num_bytes;
  agent_state->ve_mis = ve_mis;
  kafl_hprintf("kAFL %a: insufficient FuzBuf. ve_mis: %d\n", __FUNCTION__, ve_mis);
  if (agent_state->exit_at_eof && !agent_state->agent_flags.dump_observed)
  {
    kafl_hprintf("kAFL %a: end here without return\n", __FUNCTION__);
    /* no return */
    internal_agent_done(agent_state);
  }
  return 0;
}

UINTN
EFIAPI
internal_fuzz_buffer (
  IN  VOID                    *fuzz_buf,
  IN  CONST VOID              *orig_buf,
  IN  CONST UINTN             *addr,
  IN  CONST UINTN             num_bytes,
  IN  CONST enum tdx_fuzz_loc type,
  IN  OUT  agent_state_t *agent_state
  )
{
  UINTN num_fuzzed = 0;
  UINT8 *ob_buf = agent_state->ob_buf;
  UINT32 ob_num = agent_state->ob_num;
  UINT32 ob_pos = agent_state->ob_pos;

  // TODO: add fuzz filter

  // TODO: add trace tdx fuzz?

  if (!agent_state->fuzz_enabled)
  {
    return 0;
  }

  if (!agent_state->agent_initialized)
  {
    kafl_agent_init(agent_state);
  }

  // TODO: add agent flags dump callers

  kafl_hprintf("kAFL %a: Buffer 0x%p, Size %d (0x%x) before injection:\n", __FUNCTION__, fuzz_buf, num_bytes, num_bytes);
  kafl_dump_buffer(fuzz_buf, num_bytes < 32 ? num_bytes : 32);
  num_fuzzed = _internal_fuzz_buffer(fuzz_buf, num_bytes, agent_state);
  kafl_hprintf("kAFL %a: Buffer 0x%p, Size %d (0x%x) after injection:\n", __FUNCTION__, fuzz_buf, num_bytes, num_bytes);
  kafl_dump_buffer(fuzz_buf, num_bytes < 32 ? num_bytes : 32);
  kafl_hprintf("kAFL %a: num_fuzzed: %d (0x%x)\n", __FUNCTION__, num_fuzzed, num_fuzzed);

  if (agent_state->agent_flags.dump_observed)
  {
    if (ob_pos + num_bytes > ob_num)
    {
      pr_warn("Warning: insufficient space in dump_payload\n");
      internal_agent_done(agent_state);
    }

    CopyMem(ob_buf + ob_pos, fuzz_buf, num_fuzzed);
    ob_pos += num_fuzzed;
    CopyMem(ob_buf + ob_pos, orig_buf, num_bytes - num_fuzzed);
    ob_pos += (num_bytes - num_fuzzed);

    agent_state->ob_pos = ob_pos;
  }

  return num_fuzzed;
}

VOID
EFIAPI
internal_fuzz_event (
  IN  enum kafl_event  e,
  IN  OUT  agent_state_t *agent_state
  )
{
  switch(e)
  {
    case KAFL_START:
      pr_warn("[*] Agent start!\n");
      kafl_agent_init(agent_state);
      agent_state->fuzz_enabled = TRUE;
      return;
    case KAFL_ENABLE:
      pr_warn("[*] Agent enable!\n");
      /* fallthrough */
    case KAFL_RESUME:
      agent_state->fuzz_enabled = TRUE;
      return;
    case KAFL_DONE:
      return internal_agent_done(agent_state);
    case KAFL_ABORT:
      return kafl_habort("kAFL got ABORT event.\n");
    default:
      break;
  }

  if (!agent_state->agent_initialized)
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
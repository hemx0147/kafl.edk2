/** @file

  Copyright (c) 2006 - 2015, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/QemuLoadImageLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/UefiLib.h>


EFI_STATUS
TryRunningQemuKernel (
  VOID
  )
{
  EFI_STATUS                Status;
  EFI_HANDLE                KernelImageHandle;

  DEBUG ((DEBUG_INFO, "%a:%d: %a is called\n", __FILE__, __LINE__, __FUNCTION__));

  DEBUG ((DEBUG_INFO, "%a:%d:%a load kernel image\n", __FILE__, __LINE__, __FUNCTION__));
  Status = QemuLoadKernelImage (&KernelImageHandle);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Signal the EVT_SIGNAL_READY_TO_BOOT event
  //
  DEBUG ((DEBUG_INFO, "%a:%d:%a signal event ReadyToBoot\n", __FILE__, __LINE__, __FUNCTION__));
  EfiSignalEventReadyToBoot();

  REPORT_STATUS_CODE (EFI_PROGRESS_CODE,
    (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_DXE_BS_PC_READY_TO_BOOT_EVENT));

  //
  // Start the image.
  //
  DEBUG ((DEBUG_INFO, "%a:%d:%a kAFL: prevent kernel image from being started for TDVF fuzzing\n", __FILE__, __LINE__, __FUNCTION__));

  //
  // kAFL: abort execution here as we do not need to start the linux kernel for TDVF fuzzing
  //
  // Status = QemuStartKernelImage (&KernelImageHandle);
  Status = EFI_ABORTED;

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: QemuStartKernelImage(): %r\n", __FUNCTION__,
      Status));
  }

  DEBUG ((DEBUG_INFO, "%a:%d:%a unload kernel image after start failed\n", __FILE__, __LINE__, __FUNCTION__));
  QemuUnloadKernelImage (KernelImageHandle);

  return Status;
}

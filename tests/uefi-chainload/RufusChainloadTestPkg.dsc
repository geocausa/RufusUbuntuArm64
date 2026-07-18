## @file
# Deterministic ARM64 EFI application used only for runtime-integrity QEMU qualification.
# SPDX-License-Identifier: MIT
##

[Defines]
  PLATFORM_NAME                  = RufusChainloadTestPkg
  PLATFORM_GUID                  = 34EFA554-86DC-4F04-A830-10CC0AD97EF5
  PLATFORM_VERSION               = 1.0
  DSC_SPECIFICATION              = 0x00010005
  SUPPORTED_ARCHITECTURES        = AARCH64
  OUTPUT_DIRECTORY               = Build/RufusChainloadTest
  BUILD_TARGETS                  = RELEASE
  SKUID_IDENTIFIER               = DEFAULT

[BuildOptions]
  RELEASE_*_*_CC_FLAGS           = -DMDEPKG_NDEBUG
  *_*_*_CC_FLAGS                 = -DDISABLE_NEW_DEPRECATED_INTERFACES

!include MdePkg/MdeLibs.dsc.inc

[LibraryClasses]
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLibBase.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  NULL|MdePkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf

[Components]
  RufusChainloadTestPkg/RufusChainloadTest.inf

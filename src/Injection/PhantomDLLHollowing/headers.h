#pragma once

#include <windows.h>

#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x20007
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON 0x0000100000000000
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#define STATUS_SUCCESS 0x00000000

typedef struct PROC_THREAD_ATTRIBUTE_ENTRY
{
    DWORD_PTR   Attribute;
    SIZE_T      cbSize;
    PVOID       lpValue;
} PROC_THREAD_ATTRIBUTE_ENTRY, *LPPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST
{
    DWORD                          dwFlags;
    ULONG                          Size;
    ULONG                          Count;
    ULONG                          Reserved;
    PULONG                         Unknown;
    PROC_THREAD_ATTRIBUTE_ENTRY    Entries[ANYSIZE_ARRAY];
} PROC_THREAD_ATTRIBUTE_LIST, *LPPROC_THREAD_ATTRIBUTE_LIST;

typedef struct STARTUPINFOEXA {
    STARTUPINFOA StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA,*LPSTARTUPINFOEXA;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
IN PVOID ApcContext,
IN PIO_STATUS_BLOCK IoStatusBlock,
IN ULONG Reserved
);

typedef enum _SECTION_INHERIT {
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

#define OBJ_CASE_INSENSITIVE 0x00000040

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // s: KAFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation,
    ProcessAllowedCpuSetsInformation,
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // 80
    ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage,
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    MaxProcessInfoClass
} PROCESSINFOCLASS;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60
#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];
typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
#ifndef FLS_MAXIMUM_AVAILABLE
#define FLS_MAXIMUM_AVAILABLE 128
#endif

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{
     BOOLEAN InheritedAddressSpace;
     BOOLEAN ReadImageFileExecOptions;
     BOOLEAN BeingDebugged;
     union
     {
         BOOLEAN BitField;
         struct
         {
             BOOLEAN ImageUsesLargePages : 1;
             BOOLEAN IsProtectedProcess : 1;
             BOOLEAN IsImageDynamicallyRelocated : 1;
             BOOLEAN SkipPatchingUser32Forwarders : 1;
             BOOLEAN IsPackagedProcess : 1;
             BOOLEAN IsAppContainer : 1;
             BOOLEAN IsProtectedProcessLight : 1;
             BOOLEAN SpareBits : 1;
         };
     };
     HANDLE Mutant;

     PVOID ImageBaseAddress;
     PPEB_LDR_DATA Ldr;
     PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
     PVOID SubSystemData;
     PVOID ProcessHeap;
     PRTL_CRITICAL_SECTION FastPebLock;
     PVOID AtlThunkSListPtr;
     PVOID IFEOKey;
     union
     {
         ULONG CrossProcessFlags;
         struct
         {
             ULONG ProcessInJob : 1;
             ULONG ProcessInitializing : 1;
             ULONG ProcessUsingVEH : 1;
             ULONG ProcessUsingVCH : 1;
             ULONG ProcessUsingFTH : 1;
             ULONG ReservedBits0 : 27;
         };
         ULONG EnvironmentUpdateCount;
     };
     union
     {
         PVOID KernelCallbackTable;
         PVOID UserSharedInfoPtr;
     };
     ULONG SystemReserved[1];
     ULONG AtlThunkSListPtr32;
     PVOID ApiSetMap;
     ULONG TlsExpansionCounter;
     PVOID TlsBitmap;
     ULONG TlsBitmapBits[2];
     PVOID ReadOnlySharedMemoryBase;
     PVOID HotpatchInformation;
     PVOID *ReadOnlyStaticServerData;
     PVOID AnsiCodePageData;
     PVOID OemCodePageData;
     PVOID UnicodeCaseTableData;

     ULONG NumberOfProcessors;
     ULONG NtGlobalFlag;

     LARGE_INTEGER CriticalSectionTimeout;
     SIZE_T HeapSegmentReserve;
     SIZE_T HeapSegmentCommit;
     SIZE_T HeapDeCommitTotalFreeThreshold;
     SIZE_T HeapDeCommitFreeBlockThreshold;

     ULONG NumberOfHeaps;
     ULONG MaximumNumberOfHeaps;
     PVOID *ProcessHeaps;

     PVOID GdiSharedHandleTable;
     PVOID ProcessStarterHelper;
     ULONG GdiDCAttributeList;

     PRTL_CRITICAL_SECTION LoaderLock;

     ULONG OSMajorVersion;
     ULONG OSMinorVersion;
     USHORT OSBuildNumber;
     USHORT OSCSDVersion;
     ULONG OSPlatformId;
     ULONG ImageSubsystem;
     ULONG ImageSubsystemMajorVersion;
     ULONG ImageSubsystemMinorVersion;
     ULONG_PTR ImageProcessAffinityMask;
     GDI_HANDLE_BUFFER GdiHandleBuffer;
     PVOID PostProcessInitRoutine;

     PVOID TlsExpansionBitmap;
     ULONG TlsExpansionBitmapBits[32];

     ULONG SessionId;

     ULARGE_INTEGER AppCompatFlags;
     ULARGE_INTEGER AppCompatFlagsUser;
     PVOID pShimData;
     PVOID AppCompatInfo;

     UNICODE_STRING CSDVersion;

     PVOID ActivationContextData;
     PVOID ProcessAssemblyStorageMap;
     PVOID SystemDefaultActivationContextData;
     PVOID SystemAssemblyStorageMap;

     SIZE_T MinimumStackCommit;

     PVOID *FlsCallback;
     LIST_ENTRY FlsListHead;
     PVOID FlsBitmap;
     ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
     ULONG FlsHighIndex;

    PVOID WerRegistrationData;
     PVOID WerShipAssertPtr;
     PVOID pContextData;
     PVOID pImageHeaderHash;
     union
     {
         ULONG TracingFlags;
         struct
         {
             ULONG HeapTracingEnabled : 1;
             ULONG CritSecTracingEnabled : 1;
             ULONG LibLoaderTracingEnabled : 1;
             ULONG SpareTracingBits : 29;
         };
     };
     ULONGLONG CsrServerReadOnlySharedMemoryBase;
} PEB, *PPEB;

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
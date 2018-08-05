// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements DdiMon functions.

#include "ddi_mon.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#include <array>
#include "shadow_hook.h"
#include <ntstrsafe.h>
#include <unordered_set>

struct ip_port {
	unsigned int ip;
	unsigned short port;
};



struct MyCompare {
public:
	bool operator()(const ip_port&Connection1, const ip_port&Connection2) const {
		return	(Connection1.ip == Connection2.ip && Connection1.port == Connection2.port);
	}


};

struct Myhash{
		size_t operator() (const ip_port&Connection) const {
			return (std::hash<unsigned int>()(Connection.ip),std::hash<short>()(Connection.port));
		}
	};


std::unordered_set<ip_port,Myhash,MyCompare> activeIPs;

// Registering dummy protocol handler function definitions

NDIS_STATUS PtSetOptions(
	IN  NDIS_HANDLE,
	IN  NDIS_HANDLE             
) 
{  
	return NDIS_STATUS_SUCCESS;}


VOID PtReceiveNBL(
	IN NDIS_HANDLE,
	IN PNET_BUFFER_LIST,
	IN NDIS_PORT_NUMBER,
	IN ULONG,
	IN ULONG             
) {
	return;}


VOID PtOpenAdapterComplete(
	IN  NDIS_HANDLE,
	IN  NDIS_STATUS            
) {
	return;}


VOID PtCloseAdapterComplete(
	IN NDIS_HANDLE
) {
	return;}


VOID
PtRequestComplete(
	IN  NDIS_HANDLE                 ,
	IN  PNDIS_OID_REQUEST           ,
	IN  NDIS_STATUS                 
) {
	return;}

VOID
PtStatus(
	IN  NDIS_HANDLE                 ,
	IN  PNDIS_STATUS_INDICATION     
) {
	return;}

NDIS_STATUS
PtBindAdapter(
	IN  NDIS_HANDLE             ,
	IN  NDIS_HANDLE             ,
	IN  PNDIS_BIND_PARAMETERS   
) {
	return NDIS_STATUS_UNSUPPORTED_MEDIA;}

NDIS_STATUS
PtUnbindAdapter(
	IN  NDIS_HANDLE             ,
	IN  NDIS_HANDLE             
) {
	return NDIS_STATUS_SUCCESS;}


NDIS_STATUS
PtPNPHandler(
	IN NDIS_HANDLE                 ,
	IN PNET_PNP_EVENT_NOTIFICATION 
) {
	return NDIS_STATUS_SUCCESS;}




VOID
PtSendNBLComplete(
	IN NDIS_HANDLE      ,
	IN PNET_BUFFER_LIST ,
	IN ULONG            
) {
	return;}


// Global variable holding tcpip base address
UCHAR* tcpipBase;


// A helper type for parsing a PoolTag value
union PoolTag {
	ULONG value;
	UCHAR chars[4];
};

// A callback type for EnumExportedSymbols()
using EnumExportedSymbolsCallbackType = bool(*)(
	ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory,
	ULONG_PTR directory_base, ULONG_PTR directory_end, void* context);

// For SystemProcessInformation
enum SystemInformationClass {
	kSystemProcessInformation = 5,
};

// For NtQuerySystemInformation
struct SystemProcessInformation {
	ULONG next_entry_offset;
	ULONG number_of_threads;
	LARGE_INTEGER working_set_private_size;
	ULONG hard_fault_count;
	ULONG number_of_threads_high_watermark;
	ULONG64 cycle_time;
	LARGE_INTEGER create_time;
	LARGE_INTEGER user_time;
	LARGE_INTEGER kernel_time;
	UNICODE_STRING image_name;
	// omitted. see ole32!_SYSTEM_PROCESS_INFORMATION
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//


_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static void DdimonpFreeAllocatedTrampolineRegions();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C static NTSTATUS
DdimonpEnumExportedSymbols(_In_ ULONG_PTR base_address,
	_In_ EnumExportedSymbolsCallbackType callback,
	_In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
static bool DdimonpEnumExportedSymbolsCallback(
	_In_ ULONG index, _In_ ULONG_PTR base_address,
	_In_ PIMAGE_EXPORT_DIRECTORY directory, _In_ ULONG_PTR directory_base,
	_In_ ULONG_PTR directory_end, _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C static NTSTATUS
InstallHookAtAddress_Index_0(_In_ void * address,
	_In_opt_ void* context);


template <typename T>
static T DdimonpFindOrignal(_In_ T handler);


#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DdimonInitialization)
#pragma alloc_text(INIT, DdimonpEnumExportedSymbols)
#pragma alloc_text(INIT, DdimonpEnumExportedSymbolsCallback)
#pragma alloc_text(PAGE, DdimonTermination)
#pragma alloc_text(PAGE, DdimonpFreeAllocatedTrampolineRegions)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// Defines where to install shadow hooks and their handlers
//
// Because of simplified implementation of DdiMon, DdiMon is unable to handle any
// of following exports properly:
//  - already unmapped exports (eg, ones on the INIT section) because it no
//    longer exists on memory
//  - exported data because setting 0xcc does not make any sense in this case
//  - functions does not comply x64 calling conventions, for example Zw*
//    functions. Because contents of stack do not hold expected values leading
//    handlers to failure of parameter analysis that may result in bug check.
//
// Also the following care should be taken:
//  - Function parameters may be an user-address space pointer and not
//    trusted. Even a kernel-address space pointer should not be trusted for
//    production level security. Verity and capture all contents from user
//    supplied address to VMM, then use them.
static ShadowHookTarget g_ddimonp_hook_targets[] = {
	{
		RTL_CONSTANT_STRING(L"NdisSendNetBufferLists"),
		HandleSendNetBufferLists,nullptr,
	},
};

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//




static UCHAR* DdimonpGetModuleBaseAddress(char * moduleName) {

	NTSTATUS status;
	ULONG i;
	PRTL_PROCESS_MODULES ModuleInfo;
	UNICODE_STRING	ZwQuerySystemInformation_;
	UCHAR* baseAddress = NULL;

	RtlInitUnicodeString(&ZwQuerySystemInformation_, L"ZwQuerySystemInformation");

	ModuleInfo = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, 102 * 1024, 'cba');


	if (!ModuleInfo)
	{
		HYPERPLATFORM_LOG_INFO_SAFE("\n Error: Unable to allocate memory for ZWQUERY");
		return NULL;
	}

	typedef NTSTATUS(*ZwQuerySystemInformationProc)(ULONG, PVOID, ULONG, PULONG);

	ZwQuerySystemInformationProc ZwQuerySystemInformation = (ZwQuerySystemInformationProc)MmGetSystemRoutineAddress(&ZwQuerySystemInformation_);

	status = ZwQuerySystemInformation(11, ModuleInfo, 1024 * 1024, NULL); // 11 = SystemModuleInformation

	if (status < 0) {

		HYPERPLATFORM_LOG_INFO_SAFE("Error: Unable to query module list (%#x)", status);

		return NULL;
	}


	for (i = 0; i < ModuleInfo->NumberOfModules; i++)
	{


		if (!_stricmp((char *)ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName, (char *)moduleName)) {

			baseAddress = (UCHAR*) ModuleInfo->Modules[i].ImageBase;


			HYPERPLATFORM_LOG_INFO_SAFE("\nImage name: %s\n", ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName);

			ExFreePoolWithTag(ModuleInfo, 'cba');
			return baseAddress;

		}

	}

	ExFreePoolWithTag(ModuleInfo, 'cba');

	return baseAddress;

}



bool CheckTcpipConnection(IN_ADDR* dstIP,USHORT port) {
	RTL_DYNAMIC_HASH_TABLE_ENUMERATOR enumerator;
	KLOCK_QUEUE_HANDLE LockHandle;
	bool found = false;

	//__debugbreak();

	// Get addresses of global variable in tcpip.sys based on fixed offsets
	UCHAR ** partitionTablePtr = (UCHAR **)(tcpipBase + PARTITION_TABLE_PTR_OFFSET); 
	ULONG * partitionCount = (ULONG*)(tcpipBase + PARTITION_COUNT_OFFSET); 

	TCPIP_PARTITION_TABLE * partitionTable;

	// Iterate through partitions
	for (unsigned int i = 0; i < *partitionCount; i++) {

		if (found) break;

		partitionTable = (TCPIP_PARTITION_TABLE*)(((*partitionTablePtr) + NEXT_PARTITION_OFFSET*i)); 
		KeAcquireInStackQueuedSpinLock(partitionTable->SpinLock, &LockHandle);	
		RtlInitWeakEnumerationHashTable(partitionTable->hashTable, &enumerator);

		

		// Enumerate entries in hash table
		while (1) {

			UCHAR* hEntry = (UCHAR*)RtlWeaklyEnumerateEntryHashTable(partitionTable->hashTable, &enumerator);
			if (!hEntry) break;

			TABLE_ENTRY* tableEntry = (TABLE_ENTRY*)(hEntry - HASH_TABLE_ENTRY_OFFSET); 
			IN_ADDR ip = *tableEntry->ipAddrStruct->ipAddr;

			// Check entry match IP and port
			if (ip.S_un.S_addr == dstIP->S_un.S_addr && tableEntry->remotePort == port) {
				found = true;
				break;
			}

		}

		RtlEndWeakEnumerationHashTable(partitionTable->hashTable, &enumerator);
		KeReleaseInStackQueuedSpinLock(&LockHandle);

	}
	return found;
}


// Initializes DdiMon
_Use_decl_annotations_ EXTERN_C NTSTATUS
DdimonInitialization(SharedShadowHookData* shared_sh_data) {

	// Get a base address of ntoskrnl
	auto nt_base = UtilPcToFileHeader(KdDebuggerEnabled);
	if (!nt_base) {
		return STATUS_UNSUCCESSFUL;
	}


	 // Install hooks by enumerating exports of ntoskrnl, but not activate them yet
	auto status = DdimonpEnumExportedSymbols(reinterpret_cast<ULONG_PTR>(nt_base),
		DdimonpEnumExportedSymbolsCallback,
		shared_sh_data);



	tcpipBase = DdimonpGetModuleBaseAddress("tcpip.sys");

	HYPERPLATFORM_LOG_INFO_SAFE("\nImage base: %llx\n", tcpipBase);


	// GetFunction to be hooked
	PVOID sendHandler = GetLowLevelFunctionToHook();
	HYPERPLATFORM_LOG_INFO("Low level network function to  hook 0x%x", sendHandler);

	if (sendHandler) {

		// Install hook at Intel Network adapter
		InstallHookAtAddress_Index_0(sendHandler, shared_sh_data);

	}

	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Activate installed hooks
	status = ShEnableHooks();
	if (!NT_SUCCESS(status)) {
		DdimonpFreeAllocatedTrampolineRegions();
		return status;
	}

	HYPERPLATFORM_LOG_INFO("DdiMon has been initialized.");


	return status;
}

// Terminates DdiMon
_Use_decl_annotations_ EXTERN_C void DdimonTermination() {
	PAGED_CODE();

	ShDisableHooks();
	UtilSleep(1000);
	DdimonpFreeAllocatedTrampolineRegions();
	HYPERPLATFORM_LOG_INFO("DdiMon has been terminated.");
}


// Installs Hook at specified address
_Use_decl_annotations_ EXTERN_C static NTSTATUS InstallHookAtAddress_Index_0(void * address, void* context) {


	// This is bad, we are using fixed index !!!
	auto& target = g_ddimonp_hook_targets[0];

	// Yes, install a hook at the address
	if (!ShInstallHook(reinterpret_cast<SharedShadowHookData*>(context),
		(address), &target)) {
		// This is an error which should not happen
		DdimonpFreeAllocatedTrampolineRegions();
		return STATUS_UNSUCCESSFUL;
	}
	HYPERPLATFORM_LOG_INFO("Hook has been installed at %p.", address);

	return STATUS_SUCCESS;

}




// Frees trampoline code allocated and stored in g_ddimonp_hook_targets by
// DdimonpEnumExportedSymbolsCallback()
_Use_decl_annotations_ EXTERN_C static void
DdimonpFreeAllocatedTrampolineRegions() {
	PAGED_CODE();

	for (auto& target : g_ddimonp_hook_targets) {
		if (target.original_call) {
			ExFreePoolWithTag(target.original_call, kHyperPlatformCommonPoolTag);
			target.original_call = nullptr;
		}
	}
}

// Enumerates all exports in a module specified by base_address.
_Use_decl_annotations_ EXTERN_C static NTSTATUS DdimonpEnumExportedSymbols(
	ULONG_PTR base_address, EnumExportedSymbolsCallbackType callback,
	void* context) {
	PAGED_CODE();


	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
	auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(
		&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	if (!dir->Size || !dir->VirtualAddress) {
		return STATUS_SUCCESS;
	}

	auto dir_base = base_address + dir->VirtualAddress;
	auto dir_end = base_address + dir->VirtualAddress + dir->Size - 1;
	auto exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address +
		dir->VirtualAddress);
	for (auto i = 0ul; i < exp_dir->NumberOfNames; i++) {
		if (!callback(i, base_address, exp_dir, dir_base, dir_end, context)) {
			return STATUS_SUCCESS;
		}
	}
	return STATUS_SUCCESS;
}

// Checks if the export is listed as a hook target, and if so install a hook.
_Use_decl_annotations_ EXTERN_C static bool DdimonpEnumExportedSymbolsCallback(
	ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory,
	ULONG_PTR directory_base, ULONG_PTR directory_end, void* context) {
	PAGED_CODE();


	if (!context) {
		return false;
	}

	auto functions =
		reinterpret_cast<ULONG*>(base_address + directory->AddressOfFunctions);
	auto ordinals = reinterpret_cast<USHORT*>(base_address +
		directory->AddressOfNameOrdinals);
	auto names =
		reinterpret_cast<ULONG*>(base_address + directory->AddressOfNames);

	auto ord = ordinals[index];
	auto export_address = base_address + functions[ord];
	auto export_name = reinterpret_cast<const char*>(base_address + names[index]);

	// Check if an export is forwarded one? If so, ignore it.
	if (UtilIsInBounds(export_address, directory_base, directory_end)) {
		return true;
	}

	// convert the name to UNICODE_STRING
	wchar_t name[100];
	auto status =
		RtlStringCchPrintfW(name, RTL_NUMBER_OF(name), L"%S", export_name);
	if (!NT_SUCCESS(status)) {
		return true;
	}
	UNICODE_STRING name_u = {};
	RtlInitUnicodeString(&name_u, name);

	for (auto& target : g_ddimonp_hook_targets) {
		// Is this export listed as a target
		if (!FsRtlIsNameInExpression(&target.target_name, &name_u, TRUE, nullptr)) {
			continue;
		}

		// Yes, install a hook to the export
		if (!ShInstallHook(reinterpret_cast<SharedShadowHookData*>(context),
			reinterpret_cast<void*>(export_address), &target)) {
			// This is an error which should not happen
			DdimonpFreeAllocatedTrampolineRegions();
			return false;
		}
		HYPERPLATFORM_LOG_INFO("Hook has been installed at %p %s.", export_address,
			export_name);
	}
	return true;
}


// Finds a handler to call an original function
template <typename T>
static T DdimonpFindOrignal(T handler) {
	for (const auto& target : g_ddimonp_hook_targets) {
		if (target.handler == handler) {
			NT_ASSERT(target.original_call);
			return reinterpret_cast<T>(target.original_call);
		}
	}
	NT_ASSERT(false);
	return nullptr;
}


static bool CheckRegistryKeyGateway(PUNICODE_STRING key, PUNICODE_STRING subKey, PSTR gateway) {


	USHORT len = subKey->Length + key->Length + 2;
	UNICODE_STRING fullRegistryPath;
	UNICODE_STRING valueName;
	OBJECT_ATTRIBUTES  ObjectAttributes;
	HANDLE handleRegKey = NULL;
	NTSTATUS status;
	ULONG valueLength = 0;
	wchar_t wcharIP[40];
	PVOID ipBuffer;
	size_t bufSize;

	RtlZeroMemory(&fullRegistryPath, sizeof(UNICODE_STRING));


	// Alloc memory for strings concatenation
	PWCH buffer =(PWCH) ExAllocatePool(NonPagedPool, len);
	

	if (buffer != NULL) {

		RtlZeroMemory(buffer, len);
		RtlInitEmptyUnicodeString(&fullRegistryPath, buffer, len);
		RtlCopyUnicodeString(&fullRegistryPath, key); 
		RtlAppendUnicodeToString(&fullRegistryPath, L"\\");
		RtlUnicodeStringCat(&fullRegistryPath, subKey);

		InitializeObjectAttributes(&ObjectAttributes, &fullRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		// Open registry key for enummeration
		status = ZwOpenKey(&handleRegKey, KEY_READ, &ObjectAttributes);

		if (NT_SUCCESS(status)) {

			RtlInitUnicodeString(&valueName, L"DhcpDefaultGateway");
			status = ZwQueryValueKey(handleRegKey,&valueName, KeyValuePartialInformation, NULL, 0, &valueLength);

			if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) {

				PKEY_VALUE_PARTIAL_INFORMATION valueDataBuffer =(PKEY_VALUE_PARTIAL_INFORMATION) ExAllocatePool(NonPagedPool, valueLength);

				if (valueDataBuffer != NULL) {
					status = ZwQueryValueKey(handleRegKey, &valueName, KeyValuePartialInformation, valueDataBuffer, valueLength, &valueLength);

					if (NT_SUCCESS(status)) {
						
						ipBuffer = ExAllocatePool(NonPagedPool, valueDataBuffer->DataLength);
						RtlZeroMemory(ipBuffer, valueDataBuffer->DataLength);
						RtlCopyMemory(ipBuffer, valueDataBuffer->Data, valueDataBuffer->DataLength);

						
						bufSize=strlen(gateway)*2+2;
						bufSize = bufSize < 40 ? bufSize : 40;
						mbstowcs(wcharIP, gateway, bufSize);

						if(!wcscmp(wcharIP, (const wchar_t *)ipBuffer)) return true;


					}

				}
		

			}

	
		}


	}


	return false;

}


// Returns address of low level network function send handler
static PVOID NdisStructHelper(PUNICODE_STRING adapterName) {

	NDIS_STATUS status;
	NDIS_PROTOCOL_DRIVER_CHARACTERISTICS characteristics;
	NDIS_HANDLE protocolHandle;
	NDIS_OPEN_PARAMETERS OpenParameters;
	NDIS_STRING name;
	UNICODE_STRING upperAdapterName;
	UNICODE_STRING upperFoundName;
	void* handler = nullptr;


	NdisZeroMemory(&characteristics, sizeof(NDIS_PROTOCOL_DRIVER_CHARACTERISTICS));
	NdisZeroMemory(&OpenParameters, sizeof(NDIS_OPEN_PARAMETERS));

	// Initialize required fields of structure.
	NdisInitUnicodeString(&name, L"KIWI");
	characteristics.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	characteristics.Header.Size = sizeof(NDIS_PROTOCOL_DRIVER_CHARACTERISTICS);
	characteristics.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_1;
	characteristics.MajorNdisVersion = 6;
	characteristics.MinorNdisVersion = 0;
	characteristics.MajorDriverVersion = 1;
	characteristics.MinorDriverVersion = 1;
	characteristics.Name = name;
	characteristics.BindAdapterHandlerEx = PtBindAdapter;
	characteristics.CloseAdapterCompleteHandlerEx = PtCloseAdapterComplete;
	characteristics.NetPnPEventHandler = PtPNPHandler;
	characteristics.OidRequestCompleteHandler = PtRequestComplete;
	characteristics.OpenAdapterCompleteHandlerEx = PtOpenAdapterComplete;
	characteristics.ReceiveNetBufferListsHandler = PtReceiveNBL;
	characteristics.SendNetBufferListsCompleteHandler = PtSendNBLComplete;
	characteristics.SetOptionsHandler = PtSetOptions;
	characteristics.StatusHandlerEx = PtStatus;
	characteristics.UnbindAdapterHandlerEx = PtUnbindAdapter;

	// Register protocol and get acces to list of protocol and miniport driver structures
	status = NdisRegisterProtocolDriver(NULL, &characteristics, &protocolHandle);


if (status == NDIS_STATUS_SUCCESS) {

	HYPERPLATFORM_LOG_ERROR("Protocol Registered");

	_NDIS_PROTOCOL_BLOCK* pProtocolHandle = (_NDIS_PROTOCOL_BLOCK *)protocolHandle;
	UNICODE_STRING tcpipString;
	WCHAR upperFoundTerminated[150];
	WCHAR upperAdapterTerminated[150];
	WCHAR buffer[10];
	bool found = false;
	tcpipString.Buffer = buffer;

	RtlInitUnicodeString(&tcpipString, L"TCPIP");
	
	// Find TCPIP protocol
	// By registering our custom protocol, we get access to chain of installed protocols
	while (pProtocolHandle != NULL) {
		
		if (RtlCompareUnicodeString(&tcpipString,&pProtocolHandle->Name,true) == 0) {
			found = true;
			break;
		}
		pProtocolHandle = pProtocolHandle->NextProtocol;
	}
	

	if (found) {

		_NDIS_OPEN_BLOCK* openBlock = pProtocolHandle->OpenQueue;

		found = false;
		
		RtlUpcaseUnicodeString(&upperAdapterName, adapterName, true);

		// Null terminate for wcsstr
		RtlZeroMemory(upperAdapterTerminated, sizeof(upperAdapterTerminated));
		memcpy(upperAdapterTerminated, upperAdapterName.Buffer, upperAdapterName.Length);


		/* Iterate through Open block structures belonging to miniport adapter drivers and choose one with matching name.*/
		while (openBlock != NULL) {
		
		RtlUpcaseUnicodeString(&upperFoundName, openBlock->BindDeviceName, true);

		// Null terminate for wcsstr
		RtlZeroMemory(upperFoundTerminated, sizeof(upperFoundTerminated));
		memcpy(upperFoundTerminated, upperFoundName.Buffer, upperFoundName.Length);

			if (wcsstr(upperFoundTerminated, upperAdapterTerminated) != NULL) {
				found = true;
				break;
			}

			openBlock = openBlock->NextGlobalOpen;
		
		}

		RtlFreeUnicodeString(&upperAdapterName);
		RtlFreeUnicodeString(&upperFoundName);


		if (found) {

			_NDIS_MINIPORT_BLOCK* miniportBlock =(_NDIS_MINIPORT_BLOCK*) openBlock->MiniportHandle;
			 handler = miniportBlock->DriverHandle->MiniportDriverCharacteristics.SendNetBufferListsHandler;

		}

		// Uninstall custom protocol
		NdisDeregisterProtocolDriver(protocolHandle);

	}

	else { 	HYPERPLATFORM_LOG_ERROR("OpenBlock Not Found"); }


	}


	else {
		HYPERPLATFORM_LOG_ERROR("Register Protocol Error 0x%x",status);
	}



	return handler;

}


static PVOID GetLowLevelFunctionToHook() {

	NTSTATUS status;
	HANDLE handleRegKey = NULL;
	void* handler = NULL;

	// Get Default gateway
	PSTR ipv4Gateway = GetBestInterface();

	if (ipv4Gateway) {

		UNICODE_STRING     RegistryKeyName;
		OBJECT_ATTRIBUTES  ObjectAttributes;
		RtlInitUnicodeString(&RegistryKeyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces");
		InitializeObjectAttributes(&ObjectAttributes,&RegistryKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		// Open registry key for enummeration
		status = ZwOpenKey(&handleRegKey, KEY_READ, &ObjectAttributes);

		if (NT_SUCCESS(status)) {

			KEY_FULL_INFORMATION keyInfo;
			KEY_NODE_INFORMATION * keyNodeInfo = NULL;
			ULONG len;

			status = ZwQueryKey(handleRegKey, KeyFullInformation, &keyInfo, sizeof(keyInfo), &len);

			if (NT_SUCCESS(status)) {

				ULONG maxNameLen = keyInfo.MaxNameLen+2;
				PVOID str = ExAllocatePool(NonPagedPool, maxNameLen);
				UNICODE_STRING subKey;

				if(str) {

				// Enumerate network interfaces and Choose one with Gateway Set
				for (ULONG i = 0; i < keyInfo.SubKeys; i++) {

					keyNodeInfo = (KEY_NODE_INFORMATION *)ExAllocatePool(NonPagedPool, sizeof(KEY_NODE_INFORMATION));

					if (keyNodeInfo) {

						status = ZwEnumerateKey(handleRegKey, i, KeyNodeInformation, keyNodeInfo, sizeof(KEY_NODE_INFORMATION), &len);
						
						// If buffer small, free previous memory and allocate more.
						if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {

							ExFreePool(keyNodeInfo);
							keyNodeInfo = (KEY_NODE_INFORMATION *)ExAllocatePool(NonPagedPool, len);

						}

							if (keyNodeInfo) {

								RtlZeroMemory(keyNodeInfo, len);
								status = ZwEnumerateKey(handleRegKey, i, KeyNodeInformation, keyNodeInfo, len, &len);
							}

							if (NT_SUCCESS(status)) {

								RtlZeroMemory(&subKey, sizeof(UNICODE_STRING));
								RtlZeroMemory(str, maxNameLen);
								
								memcpy(str, keyNodeInfo->Name, keyNodeInfo->NameLength);
								
								subKey.Buffer = (PWCH) str;
								subKey.Length = (ULONG) keyNodeInfo->NameLength;
								subKey.MaximumLength = (ULONG) maxNameLen;


								if (CheckRegistryKeyGateway(&RegistryKeyName, &subKey, ipv4Gateway)) {

									// Get SendHandler
									handler = NdisStructHelper(&subKey);

								}
	
			

							}



						}

						ExFreePool(keyNodeInfo);

					}

							 

				}

				ExFreePool(str);
			}
						

			}  


	}
	else {

		HYPERPLATFORM_LOG_ERROR("No IPV4");

	}


	return handler;

}


// Finds low level Driver Function to be hooked
static PSTR GetBestInterface() {

	MIB_IPFORWARD_TABLE2 *table = NULL;
	MIB_IPFORWARD_ROW2 *BestGatewayRow = NULL;
	ULONG BestGatewayMetric = ULONG_MAX;
	NETIO_STATUS status;
	PSTR ipv4Gateway = NULL;

	status = GetIpForwardTable2(AF_INET, &table);

	if (!NETIO_SUCCESS(status)) { 
		HYPERPLATFORM_LOG_ERROR("Error IP Forward table");
		return NULL; }

	for (ULONG i = 0; i < table->NumEntries; i++) {

		MIB_IPFORWARD_ROW2 *row = table->Table + i;
		IP_ADDRESS_PREFIX *prefix = &row->DestinationPrefix;
		SOCKADDR_INET *destAddr = &prefix->Prefix;

		// Take Default route
		if (destAddr->Ipv4.sin_addr.S_un.S_addr == 0 && prefix->PrefixLength == 0) {


			MIB_IPINTERFACE_ROW interfaceRow;
			memset(&interfaceRow, 0, sizeof(MIB_IPINTERFACE_ROW));
			interfaceRow.InterfaceLuid = row->InterfaceLuid;
			interfaceRow.Family = AF_INET;

			// Get Interface IPINTERFACE_ROW structure to obtain Cost of interface
			status = GetIpInterfaceEntry(&interfaceRow);

			if (NETIO_SUCCESS(status)) {

				// Found better Route
				if (interfaceRow.Metric + row->Metric < BestGatewayMetric) {

					BestGatewayRow = row;
				}

			}
			else {

				HYPERPLATFORM_LOG_ERROR("Error IP Interface Entry");

			}

		}

	}


	if (BestGatewayRow) {

		 ipv4Gateway = (PSTR)ExAllocatePool(NonPagedPool, 20);

		if (ipv4Gateway) {

			RtlIpv4AddressToString(&BestGatewayRow->NextHop.Ipv4.sin_addr, ipv4Gateway);
			FreeMibTable(table);
			return ipv4Gateway;
		}

	}


	return ipv4Gateway;

}


// Allocates memory for Ethernet Frame and copies there data from all MDLs
static PVOID GetFrameData(PNET_BUFFER pNetBuffer, ULONG * size) {
	if (pNetBuffer == nullptr || size == nullptr) goto Err;

	ULONG frameSize = NET_BUFFER_DATA_LENGTH(pNetBuffer);
	PMDL pMdl = NET_BUFFER_CURRENT_MDL(pNetBuffer);
	PVOID data = NULL;
	*(size) = frameSize;

	if (frameSize > 0 && pMdl)	{

		ULONG remainingData = frameSize;
		ULONG offset = 0;
		data = ExAllocatePoolWithTag(NonPagedPool, frameSize, 'data');
		if (data == nullptr) goto Err;

		// This is first MDL, handle it specially
		PVOID pMdlData = (PVOID)(static_cast<char *>(MmGetMdlVirtualAddress(pMdl)) + NET_BUFFER_CURRENT_MDL_OFFSET(pNetBuffer));
		ULONG mdlDataSize = min(remainingData, MmGetMdlByteCount(pMdl) - NET_BUFFER_CURRENT_MDL_OFFSET(pNetBuffer));

		// Iterate over MDLs
		while (remainingData > 0) {

			memcpy((void *)(static_cast<char *>(data) + offset), pMdlData, mdlDataSize);
			offset += mdlDataSize;
			remainingData -= mdlDataSize;
			pMdl = pMdl->Next;
			if (!pMdl) break;
			pMdlData = MmGetMdlVirtualAddress(pMdl);
			mdlDataSize = min(remainingData, MmGetMdlByteCount(pMdl));

		}

		return data;

	}


Err: return nullptr;
}


static VOID HandleSendNetBufferLists(
	NDIS_HANDLE NdisBindingHandle, PNET_BUFFER_LIST NetBufferLists,
	NDIS_PORT_NUMBER PortNumber, ULONG SendFlags) {
	PNET_BUFFER pFirstNetBuffer = NetBufferLists->FirstNetBuffer;
	ULONG frameSize;



	// During experiments, following pointers were always NULL, but we add this code to test it.
	if (NetBufferLists->Next != NULL) HYPERPLATFORM_LOG_ERROR("Error processing NEXT list");
	if (pFirstNetBuffer->Next != NULL) HYPERPLATFORM_LOG_ERROR("Error processing NEXT packet");
	


	if (NetBufferLists && pFirstNetBuffer) {


		MDL * pMdl = NET_BUFFER_CURRENT_MDL(pFirstNetBuffer);
		frameSize = NET_BUFFER_DATA_LENGTH(pFirstNetBuffer);
		PETHERNET_FRAME frame = nullptr;



		if (pMdl && frameSize > 0) {


			frame = (PETHERNET_FRAME)(static_cast<char *>(MmGetMdlVirtualAddress(pMdl)) + NET_BUFFER_CURRENT_MDL_OFFSET(pFirstNetBuffer));
			ULONG MdlDataSize = MmGetMdlByteCount(pMdl) - NET_BUFFER_CURRENT_MDL_OFFSET(pFirstNetBuffer);

			// Check if all necessary data (Ethernet header, ip Header) in First (current) MDL
			if (MdlDataSize >= 34) {

				if (RtlUshortByteSwap(frame->type) == 0x86DD) {
					//HYPERPLATFORM_LOG_ERROR("IPV6");
				}

				// IPV4
				if (RtlUshortByteSwap(frame->type) == 0x800) {

					PIP_PACKET ipPacket = (PIP_PACKET)frame->data;

					// UDP
					if (ipPacket->protocol == UDP_PROTOCOL) {

						// Here we rather copy all data to one buffer
						frame = (PETHERNET_FRAME)GetFrameData(pFirstNetBuffer, &frameSize);

						// These are new data
						ipPacket = (PIP_PACKET)frame->data;
						PUDP pUdpDatagram = (PUDP)ipPacket->data;
						PDNS pDnsDatagram = (PDNS)pUdpDatagram->data;

						USHORT index = 0;
						UCHAR labelLength;
						PVOID query = pDnsDatagram->query;

						// Change lengths of labels in DNS query to '.' as in Real DNS request
						while (((char *)query + index) < (char *)(frame + frameSize)) {
							labelLength = *((char *)query + index);
							*((char *)query + index) = '.';
							index += labelLength + 1;
							labelLength = *((char *)query + index);
							if (labelLength == 0) break;
						}


						//HYPERPLATFORM_LOG_ERROR("DNS QUERY FOR %s", pDnsDatagram->query);
						ExFreePoolWithTag(frame, 'data');

					}

					if (ipPacket->protocol == TCP_PROTOCOL) {

						PTCP tcpHeader = (PTCP) ipPacket->data;
						
						struct ip_port Connection;
						Connection.ip = ipPacket->dst_ip.S_un.S_addr;
						Connection.port = tcpHeader->destination_port;

						// Check if system knows about this connection
						if (!CheckTcpipConnection(&ipPacket->dst_ip, tcpHeader->destination_port)) {

							// If hypervisor has not seen this connection and system
							// does not have any information as well, this is hidden communication
							if (activeIPs.find(Connection) == activeIPs.end()) {

								UCHAR flags = tcpHeader->flags;

								// RST ACK  TCP Termination - Ignore these packets
								if (flags != 0x14) {

									HYPERPLATFORM_LOG_ERROR("Detected: DST IP Address: %d.%d.%d.%d:%d SRC IP Address: %d.%d.%d.%d:%d ", ipPacket->dst_ip.S_un.S_un_b.s_b1, ipPacket->dst_ip.S_un.S_un_b.s_b2, ipPacket->dst_ip.S_un.S_un_b.s_b3, ipPacket->dst_ip.S_un.S_un_b.s_b4, RtlUshortByteSwap(tcpHeader->destination_port), ipPacket->src_ip.S_un.S_un_b.s_b1, ipPacket->src_ip.S_un.S_un_b.s_b2, ipPacket->src_ip.S_un.S_un_b.s_b3, ipPacket->src_ip.S_un.S_un_b.s_b4, RtlUshortByteSwap(tcpHeader->source_port));
									HYPERPLATFORM_LOG_ERROR("SeqN:%u AckN:%u", RtlUlongByteSwap(tcpHeader->seq_num), RtlUlongByteSwap(tcpHeader->ack_num));


									if (flags & 0x1) HYPERPLATFORM_LOG_ERROR("FIN");
									flags >>= 1;
									if (flags & 0x1) HYPERPLATFORM_LOG_ERROR("SYN");
									flags >>= 1;
									if (flags & 0x1) HYPERPLATFORM_LOG_ERROR("RST");
									flags >>= 1;
									if (flags & 0x1) HYPERPLATFORM_LOG_ERROR("PSH");
									flags >>= 1;
									if (flags & 0x1) HYPERPLATFORM_LOG_ERROR("ACK");
									flags >>= 1;
									if (flags & 0x1) HYPERPLATFORM_LOG_ERROR("URG");
									flags >>= 1;
									if (flags & 0x1) HYPERPLATFORM_LOG_ERROR("ECE");
									flags >>= 1;
									if (flags & 0x1) HYPERPLATFORM_LOG_ERROR("CWR");
									flags >>= 1;

								}
						

							}
							else {

								activeIPs.erase(Connection);
							}

						}
						else {
						

							if (activeIPs.find(Connection)==activeIPs.end()) {
								activeIPs.insert(Connection);
								
							}


						}


					}


				}

			}
		}
		else { HYPERPLATFORM_LOG_ERROR("Small first MDL"); }

	}


	const auto original = DdimonpFindOrignal(HandleSendNetBufferLists);
	original(NdisBindingHandle, NetBufferLists, PortNumber, SendFlags);

	// Is inside image?
	auto return_addr = _ReturnAddress();
	if (UtilPcToFileHeader(return_addr)) {
		return;
	}

}















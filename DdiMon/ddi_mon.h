// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to DdiMon functions.

#ifndef DDIMON_DDI_MON_H_
#define DDIMON_DDI_MON_H_

#include <fltKernel.h>
#include <stdint.h>
#include <Inaddr.h>
#include <netioapi.h>
#include <Mstcpip.h>
#include <ndisStructs.h>


////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct SharedShadowHookData;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;


#pragma pack(push, 1)
typedef struct ether_frame_ {
	uint8_t destination_MAC[6];
	uint8_t source_MAC[6];
	uint16_t type;
	uint8_t data[1];
}ETHERNET_FRAME,*PETHERNET_FRAME;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct ip_packet_ {
	uint8_t ihl : 4;
	uint8_t version : 4;
	uint8_t tos;
	uint16_t length;
	uint16_t identification;
	uint16_t flag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t headr_checksum;
	struct in_addr src_ip;
	struct in_addr dst_ip;
	uint8_t data[1];
}IP_PACKET,*PIP_PACKET;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct tcp_ {
	uint16_t source_port;
	uint16_t destination_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t data_offset : 4;
	uint8_t reserved : 4;
	uint8_t flags;
	uint16_t windows;
	uint16_t checksum;
	uint16_t urgent_pointer;
	uint8_t data[1];
}TCP,*PTCP;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct udp_ {
	uint16_t source_port;
	uint16_t destination_port;
	uint16_t length;
	uint16_t checksum;
	uint8_t data[1];
}UDP, *PUDP;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct dns_ {
	uint16_t transaction_id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answer_rrs;
	uint16_t authority_rrs;
	uint16_t additional_rrs;
	uint8_t query[1];
}DNS,*PDNS;
#pragma pack(pop)

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


PROTOCOL_SET_OPTIONS PtSetOptions;
PROTOCOL_OPEN_ADAPTER_COMPLETE_EX PtOpenAdapterComplete;
PROTOCOL_CLOSE_ADAPTER_COMPLETE_EX PtCloseAdapterComplete;
PROTOCOL_OID_REQUEST_COMPLETE PtRequestComplete;
PROTOCOL_STATUS_EX PtStatus;
PROTOCOL_BIND_ADAPTER_EX PtBindAdapter;
PROTOCOL_UNBIND_ADAPTER_EX PtUnbindAdapter;
PROTOCOL_NET_PNP_EVENT PtPNPHandler;
PROTOCOL_RECEIVE_NET_BUFFER_LISTS PtReceiveNBL;
PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE PtSendNBLComplete;

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS
    DdimonInitialization(_In_ SharedShadowHookData* shared_sh_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C void DdimonTermination();

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//


_IRQL_requires_max_(PASSIVE_LEVEL) static bool CheckTcpipConnection(IN_ADDR* dstIP, USHORT port);


_IRQL_requires_max_(PASSIVE_LEVEL)  static UCHAR* DdimonpGetModuleBaseAddress(char * moduleName);

_IRQL_requires_max_(PASSIVE_LEVEL)  static PSTR GetBestInterface();

_IRQL_requires_max_(PASSIVE_LEVEL)  static PVOID GetLowLevelFunctionToHook();

_IRQL_requires_max_(PASSIVE_LEVEL)  static PVOID NdisStructHelper(PUNICODE_STRING adapterName);

_IRQL_requires_max_(PASSIVE_LEVEL)  static VOID HandleSendNetBufferLists(
	_In_ NDIS_HANDLE      NdisBindingHandle,
	_In_ PNET_BUFFER_LIST NetBufferLists,
	_In_ NDIS_PORT_NUMBER PortNumber,
	_In_ ULONG            SendFlags);


_IRQL_requires_max_(PASSIVE_LEVEL) static PVOID GetFrameData(
	_In_ PNET_BUFFER pNetBuffer, 
	_Out_ ULONG * size);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool CheckRegistryKeyGateway(
	_In_ PUNICODE_STRING key,
	_In_ PUNICODE_STRING subKey,
	_In_ PSTR gateway);

#endif  // DDIMON_DDI_MON_H_

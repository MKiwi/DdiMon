#pragma once
#include <Ndis.h>
#include <Ntddndis.h>


#define WIN7 1

#ifndef WIN7
#define WIN10 1
#endif


#if(_WIN64)
#define bufferStructSize1 656
#define bufferStructSize2 656
#define qcSize 40
#define reserved3Size 5
#else
#define qcSize 20
#define bufferStructSize1 608
#define bufferStructSize2 604
#define reserved3Size 1
#endif



// TCP structures offsets
#if(WIN7)
#if(_WIN64)

#define PARTITION_TABLE_PTR_OFFSET 0x190fd0
#define PARTITION_COUNT_OFFSET 0x190fda
#define NEXT_PARTITION_OFFSET 0x78
#define HASH_TABLE_ENTRY_OFFSET 0x28
#define IP_ADDR_PADDING 0x10
#define TABLE_ENTRY_PADDING0 0x20
#define TABLE_ENTRY_PADDING1 0x3c

#else 

#define PARTITION_TABLE_PTR_OFFSET 0xfa0c0
#define PARTITION_COUNT_OFFSET 0xfa0c6
#define NEXT_PARTITION_OFFSET 0x48
#define HASH_TABLE_ENTRY_OFFSET 0x18
#define IP_ADDR_PADDING 0x08
#define TABLE_ENTRY_PADDING0 0x10
#define TABLE_ENTRY_PADDING1 0x20

#endif
#else //---------------------- WIN10
#if(_WIN64)


#define PARTITION_TABLE_PTR_OFFSET 0x1d20f0
#define PARTITION_COUNT_OFFSET  0x1d20ec
#define NEXT_PARTITION_OFFSET 0x78
#define HASH_TABLE_ENTRY_OFFSET 0x28
#define IP_ADDR_PADDING 0x10
#define TABLE_ENTRY_PADDING0 0x20
#define TABLE_ENTRY_PADDING1 0x3c



#else


#endif
#endif

typedef struct _NDIS_PM_PARAMETERS
{
	//
	// Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	// Header.Revision = NDIS_PM_PARAMETERS_REVISION_2;
	// Header.Size = NDIS_SIZEOF_NDIS_PM_PARAMETERS_REVISION_2;
	//
	NDIS_OBJECT_HEADER      Header;

	ULONG                   EnabledWoLPacketPatterns; // NDIS_PM_WOL_XXX_ENABLED flags
	ULONG                   EnabledProtocolOffloads;  // NDIS_PM_PROTOCOL_OFFLOAD_XXX_ENABLED flags
	ULONG                   WakeUpFlags;              // NDIS_PM_WAKE_ON_XXX_ENABLED flags

#if (NDIS_SUPPORT_NDIS630)
	ULONG                   MediaSpecificWakeUpEvents; // NDIS_{WLAN|WWAN}_WAKE_ON_XXX_ENABLED flags
#endif // (NDIS_SUPPORT_NDIS630)

} NDIS_PM_PARAMETERS, *PNDIS_PM_PARAMETERS;


struct _REFERENCE_EX {
	void* SpinLock ;
	UINT16 ReferenceCount ;
	UCHAR Closing;
	UCHAR ZeroBased ;
	void* RefCountTracker;
};

#if(WIN7)

struct _NDIS_PROTOCOL_BLOCK {
	_NDIS_OBJECT_HEADER Header;
	void* ProtocolDriverContext;
	_NDIS_PROTOCOL_BLOCK* NextProtocol;
	_NDIS_OPEN_BLOCK* OpenQueue;
	_REFERENCE ref;
	UCHAR MajorNdisVersion;
	UCHAR MinorNdisVersion;
	UCHAR MajorDriverVersion;
	UCHAR MinorDriverVersion;
	UINT32 Reserved;
	UINT32 Flags;
	UNICODE_STRING Name;
	// Shortened, other Parts are not important
};


struct TCPIP_PARTITION_TABLE {
	PKSPIN_LOCK SpinLock;
	PRTL_DYNAMIC_HASH_TABLE hashTable;
};



struct IPADDR {
	CHAR padding[IP_ADDR_PADDING]; 
	IN_ADDR *ipAddr;
};

struct TABLE_ENTRY {
	UCHAR padding0[TABLE_ENTRY_PADDING0];   
	IPADDR *ipAddrStruct;
	PLIST_ENTRY ipInfoPtr;
	UCHAR padding1[TABLE_ENTRY_PADDING1];
	USHORT localPort;
	USHORT remotePort;
	UCHAR padding2[0x1ca];
	ULONG* eprocess;
};


#elif(WIN10)

struct _NDIS_PROTOCOL_BLOCK {
	_NDIS_OBJECT_HEADER Header;
	void* ProtocolDriverContext;
	_NDIS_PROTOCOL_BLOCK* NextProtocol;
	_NDIS_OPEN_BLOCK* OpenQueue;
	_REFERENCE_EX ref;
	UCHAR MajorNdisVersion;
	UCHAR MinorNdisVersion;
	UCHAR MajorDriverVersion;
	UCHAR MinorDriverVersion;
	UINT32 Reserved;
	UINT32 Flags;
	UNICODE_STRING Name;
	// Shortened, other Parts are not important
};


struct TCPIP_PARTITION_TABLE {
	PKSPIN_LOCK SpinLock;
	PRTL_DYNAMIC_HASH_TABLE hashTable;
};



struct IPADDR {
	CHAR padding[IP_ADDR_PADDING];
	IN_ADDR *ipAddr;
};

struct TABLE_ENTRY {
	UCHAR padding0[TABLE_ENTRY_PADDING0];
	IPADDR *ipAddrStruct;
	PLIST_ENTRY ipInfoPtr;
	UCHAR padding1[TABLE_ENTRY_PADDING1];
	USHORT localPort;
	USHORT remotePort;
	UCHAR padding2[0x1ca];
	ULONG* eprocess;
};

#endif


struct _NDIS_M_DRIVER_BLOCK {
	_NDIS_OBJECT_HEADER Header;
	_NDIS_M_DRIVER_BLOCK* NextDriver;
	_NDIS_MINIPORT_BLOCK* MiniportQueue;
	UCHAR MajorNdisVersion;
	UCHAR MinorNdisVersion;
	UINT16 Flags;
	_NDIS_WRAPPER_HANDLE* NdisDriverInfo;
	_DRIVER_OBJECT* DriverObject;
	_UNICODE_STRING ServiceRegPath;
	void* MiniportDriverContext;
	_NDIS_PROTOCOL_BLOCK* AssociatedProtocol;
	_LIST_ENTRY DeviceList;
	void* PendingDeviceList; // PendingDeviceList
	void* UnloadHandler;
	_NDIS_MINIPORT_DRIVER_CHARACTERISTICS MiniportDriverCharacteristics;
	// Shortened, other Parts are not important
};




typedef struct _NDIS_OPEN_BLOCK {
	_NDIS_OBJECT_HEADER Header;
	void* BindingHandle;
	_NDIS_MINIPORT_BLOCK* MiniportHandle;
	_NDIS_PROTOCOL_BLOCK* ProtocolHandle;
	void* ProtocolBindingContext;
	void* NextSendHandler;
	void* NextSendContext;
	void* MiniportAdapterContext;
	UCHAR Reserved1;
	UCHAR vCallingFromNdis6Protocol;
	UCHAR Reserved3;
	UCHAR Reserved4[reserved3Size];
	void* NextReturnNetBufferListsHandler;
	void* Reserved5;
	void* NextReturnNetBufferListsContext;
	void* SendHandler;
	void* TransferDataHandler;
	void* SendCompleteHandler;
	void* TransferDataCompleteHandler;
	void* ReceiveHandler;
	void* ReceiveCompleteHandler;
	void* WanReceiveHandler;
	void* RequestCompleteHandler;
	void* ReceivePacketHandler;
	void* SendPacketsHandler;
	void* ResetHandler;
	void* RequestHandler;
	void* OidRequestHandler;
	void* ResetCompleteHandler;
	void* StatusHandler;
	void* StatusCompleteHandler;
	UINT32 Flags;
	INT32 References;
	void* SpinLock;
	void* FilterHandle;
	UINT32 FrameTypeArraySize;
	UINT16 FrameTypeArray[4];
	UINT32 ProtocolOptions;
	void* CurrentLookahead;
	int* WSendHandler;
	int* WTransferDataHandler;
	void* WSendPacketsHandler;
	void* CancelSendPacketsHandler;
	UINT32 WakeUpEnable;
	_NDIS_PM_PARAMETERS PMCurrentParameters;
	_KEVENT* CloseCompleteEvent;
	 UCHAR Qc[qcSize];
	 void* AfReferences;
	 _NDIS_OPEN_BLOCK* NextGlobalOpen;
	 _NDIS_OPEN_BLOCK* MiniportNextOpen;
	 _NDIS_OPEN_BLOCK* ProtocolNextOpen;
	 _UNICODE_STRING* BindDeviceName;
	 _UNICODE_STRING* RootDeviceName;
	 _NDIS_OPEN_BLOCK* FilterNextOpen;
	// Shortened, other Parts are not important
}NDIS_OPEN_BLOCK, *PNDIS_OPEN_BLOCK;


//----------------------------------------------------------------------------

typedef enum _NDIS_WORK_ITEM_TYPE
{
	NdisWorkItemRequest,
	NdisWorkItemSend,
	NdisWorkItemReturnPackets,
	NdisWorkItemResetRequested,
	NdisWorkItemResetInProgress,
	NdisWorkItemReserved,
	NdisWorkItemMiniportCallback,
	NdisMaxWorkItems
} NDIS_WORK_ITEM_TYPE, *PNDIS_WORK_ITEM_TYPE;

typedef struct _NDIS_MINIPORT_WORK_ITEM
{
	//
	//  Link for the list of work items of this type.
	//
	SINGLE_LIST_ENTRY   Link;

	//
	//  type of work item and context information.
	//
	NDIS_WORK_ITEM_TYPE WorkItemType;
	PVOID               WorkItemContext;
} NDIS_MINIPORT_WORK_ITEM, *PNDIS_MINIPORT_WORK_ITEM;

typedef enum _NDIS_PNP_DEVICE_STATE {
	NdisPnPDeviceAdded,
	NdisPnPDeviceStarted,
	NdisPnPDeviceQueryStopped,
	NdisPnPDeviceStopped,
	NdisPnPDeviceQueryRemoved,
	NdisPnPDeviceRemoved,
	NdisPnPDeviceSurpriseRemoved
} NDIS_PNP_DEVICE_STATE;

enum _NDIS_MINIPORT_STATE {
	NdisMiniportUndefindState,
	NdisMiniportHalted,
	NdisMiniportInitializing,
	NdisMiniportRestarting,
	NdisMiniportRunning,
	NdisMiniportPausing,
	NdisMiniportPaused
};

struct _ULONG_REFERENCE {
	void* SpinLock;
	UINT32 ReferenceCount;
	UCHAR Closing;
};

struct _NDIS_MINIPORT_HANDLERS {
	void* RequestContext;
	void* CancelSendContext;
	void* IndicateNetBufferListsContext;
	void* IndicateNetBufferListsObject;
	void* SaveIndicateNetBufferListsContext;
	void* ReturnNetBufferListsContext;
	void* ReturnNetBufferListsObject;
	void* SendNetBufferListsContext;
	void* SendNetBufferListsObject;
	void* SendNetBufferListsCompleteContext;
	void* SendNetBufferListsCompleteObject;
	void* RequestHandle;
	void* StatusHandle;
	void* DevicePnPEventNotifyHandle;
	void* NetPnPEventHandle;
	void* CancelSendHandler;
	void* SendNetBufferListsCompleteHandler;
	void* IndicateNetBufferListsHandler;
	void* SaveIndicateNetBufferListsHandler;
	void* ReturnNetBufferListsHandler;
	void* SendNetBufferListsHandler;
	void* DirectRequestHandle;
};


typedef union _NDIS_PM_ADMIN_GONFIG
{
	struct tmp2{
		ULONG WakeOnPattern : 2;
		ULONG WakeOnMagicPacket : 2;
		ULONG DeviceSleepOnDisconnect : 2;
		ULONG PMARPOffload : 2;
		ULONG PMNSOffload : 2;
		ULONG PMWiFiRekeyOffload : 2;
	};
	ULONG Value;
}NDIS_PM_ADMIN_GONFIG, *PNDIS_PM_ADMIN_GONFIG;


typedef enum _NDIS_M_PERIODIC_RECEIVE_STATE
{
	PeriodicReceivesOff = 0x0,
	PeriodicReceivesOn = 0x1,
	PeriodicReceivesBlocked = 0x2
}NDIS_M_PERIODIC_RECEIVE_STATE, *PNDIS_M_PERIODIC_RECEIVE_STATE;


struct _NDIS_M_PERIODIC_RECEIVES {
	_NDIS_MINIPORT_BLOCK* NextMiniportBlock;
	_NDIS_M_PERIODIC_RECEIVE_STATE State;
	void* SpinLock;
	void* LockThread;
	UINT32 LockDbg;
	UINT32 NumMQueuedNbls;
	UINT32 NumNblsDequeued;
	_NET_BUFFER_LIST* QueuedHead;
	_NET_BUFFER_LIST* QueuedTail;
	UINT32 BoundToIP;
	UCHAR Paused;
	UINT32 NblsAllocated;
	UINT32 TrackingQueued;
	UINT32 TrackingDequeued;
	UINT32 TrackingResources;
	UINT32 TrackingPending;
	UINT32 TrackingIndicated;
	UINT32 TrackingEmptied;
	_WORK_QUEUE_ITEM WorkItem;
	UINT32 WorkItemQueued;

};


typedef struct {
	union tmp3 {
		struct tmp1 {
			ULONG BaseIndexRegister : 3;
			ULONG Reserved : 29;
		};
		ULONG  TableOffset;
	};
} PCIX_TABLE_POINTER, *PPCIX_TABLE_POINTER;


typedef struct {
	PCI_CAPABILITIES_HEADER         Header;
	struct _PCI_MSI_MESSAGE_CONTROL {
		USHORT MSIEnable : 1;
		USHORT MultipleMessageCapable : 3;
		USHORT MultipleMessageEnable : 3;
		USHORT CapableOf64Bits : 1;
		USHORT PerVectorMaskCapable : 1;
		USHORT Reserved : 7;
	} MessageControl;
	union {
		struct _PCI_MSI_MESSAGE_ADDRESS {
			ULONG Reserved : 2;
			ULONG Address : 30;
		} Register;
		ULONG                           Raw;
	} MessageAddressLower;
	union {
		struct {
			USHORT MessageData;
		} Option32Bit;
		struct {
			ULONG  MessageAddressUpper;
			USHORT MessageData;
			USHORT Reserved;
			ULONG  MaskBits;
			ULONG  PendingBits;
		} Option64Bit;
	};
} PCI_MSI_CAPABILITY, *PPCI_MSI_CAPABILITY;

#ifndef PCI_MSIX_CAPABILITY
typedef struct {
	PCI_CAPABILITIES_HEADER Header;
	struct {
		USHORT TableSize : 11;
		USHORT Reserved : 3;
		USHORT FunctionMask : 1;
		USHORT MSIXEnable : 1;
	} MessageControl;
	PCIX_TABLE_POINTER      MessageTable;
	PCIX_TABLE_POINTER      PBATable;
} PCI_MSIX_CAPABILITY, *PPCI_MSIX_CAPABILITY;
#endif


struct _NDIS_MINIPORT_OFFLOAD_REG {
	unsigned long  Value; /*  +0x0000  */
};





struct _NDIS_PM_CAPABILITIES {
	_NDIS_OBJECT_HEADER Header;
	UINT32 Flags;
	UINT32 SupportedWoLPacketPatterns;
	UINT32 NumTotalWoLPatterns;
	UINT32 MaxWoLPatternSize;
	UINT32 MaxWoLPatternOffset;
	UINT32 MaxWoLPacketSaveBuffer;
	UINT32 SupportedProtocolOffloads;
	UINT32 NumArpOffloadIPv4Addresses;
	UINT32 NumNSOffloadIPv6Addresses;
	_NDIS_DEVICE_POWER_STATE MinMagicPacketWakeUp;
	_NDIS_DEVICE_POWER_STATE MinPatternWakeUp;
	_NDIS_DEVICE_POWER_STATE MinLinkChangeWakeUp;
};







typedef struct _NDIS_RECEIVE_FILTER_CAPABILITIES
{
	_In_  NDIS_OBJECT_HEADER          Header;
	_In_  ULONG                       Flags;
	_In_  ULONG                       EnabledFilterTypes;
	_In_  ULONG                       EnabledQueueTypes;
	_In_  ULONG                       NumQueues;
	_In_  ULONG                       SupportedQueueProperties;
	_In_  ULONG                       SupportedFilterTests;
	_In_  ULONG                       SupportedHeaders;
	_In_  ULONG                       SupportedMacHeaderFields;
	_In_  ULONG                       MaxMacHeaderFilters;
	_In_  ULONG                       MaxQueueGroups;
	_In_  ULONG                       MaxQueuesPerQueueGroup;
	_In_  ULONG                       MinLookaheadSplitSize;
	_In_  ULONG                       MaxLookaheadSplitSize;
#if (NDIS_SUPPORT_NDIS630)
	_In_  ULONG                       SupportedARPHeaderFields;
	_In_  ULONG                       SupportedIPv4HeaderFields;
	_In_  ULONG                       SupportedIPv6HeaderFields;
	_In_  ULONG                       SupportedUdpHeaderFields;
	_In_  ULONG                       MaxFieldTestsPerPacketCoalescingFilter;
	_In_  ULONG                       MaxPacketCoalescingFilters;
	_In_  ULONG                       NdisReserved;
#endif // (NDIS_SUPPORT_NDIS630)
} NDIS_RECEIVE_FILTER_CAPABILITIES, *PNDIS_RECEIVE_FILTER_CAPABILITIES;


typedef struct _NDIS_NIC_SWITCH_CAPABILITIES
{
	_In_  NDIS_OBJECT_HEADER          Header;
	_In_  ULONG                       Flags;
	_In_  ULONG                       NdisReserved1;
	_In_  ULONG                       NumTotalMacAddresses;
	_In_  ULONG                       NumMacAddressesPerPort;
	_In_  ULONG                       NumVlansPerPort;
	_In_  ULONG                       NdisReserved2;
	_In_  ULONG                       NdisReserved3;
#if (NDIS_SUPPORT_NDIS630)
	_In_  ULONG                       NicSwitchCapabilities;
	_In_  ULONG                       MaxNumSwitches;
	_In_  ULONG                       MaxNumVPorts;
	_In_  ULONG                       NdisReserved4;
	_In_  ULONG                       MaxNumVFs;
	_In_  ULONG                       MaxNumQueuePairs;
	_In_  ULONG                       NdisReserved5;
	_In_  ULONG                       NdisReserved6;
	_In_  ULONG                       NdisReserved7;
	_In_  ULONG                       MaxNumQueuePairsPerNonDefaultVPort;
	_In_  ULONG                       NdisReserved8;
	_In_  ULONG                       NdisReserved9;
	_In_  ULONG                       NdisReserved10;
	_In_  ULONG                       NdisReserved11;
	_In_  ULONG                       NdisReserved12;
	_In_  ULONG                       MaxNumMacAddresses;
	_In_  ULONG                       NdisReserved13;
	_In_  ULONG                       NdisReserved14;
	_In_  ULONG                       NdisReserved15;
	_In_  ULONG                       NdisReserved16;
	_In_  ULONG                       NdisReserved17;
#endif // (NDIS_SUPPORT_NDIS630)
#if (NDIS_SUPPORT_NDIS660)
	_In_  ULONG                       MaxNumRssCapableNonDefaultPFVPorts;
	_In_  ULONG                       NumberOfIndirectionTableEntriesForDefaultVPort;
	_In_  ULONG                       NumberOfIndirectionTableEntriesPerNonDefaultPFVPort;
	_In_  ULONG                       MaxNumQueuePairsForDefaultVPort;
#endif // (NDIS_SUPPORT_NDIS660)
}NDIS_NIC_SWITCH_CAPABILITIES, *PNDIS_NIC_SWITCH_CAPABILITIES;


typedef struct MY_IO_REMOVE_LOCK {
	IO_REMOVE_LOCK_COMMON_BLOCK Common;
} MY_IO_REMOVE_LOCK, *MY_PIO_REMOVE_LOCK;



struct MY_NET_IF_MEDIA_DUPLEX_STATE{
#if (_WIN64)
	void* ptrSize;
#endif
	UINT32 ptrSize2;
};




#if (WIN10)

struct  _NDIS_MINIPORT_BLOCK {
	UCHAR padding[3816];
	_NDIS_M_DRIVER_BLOCK* DriverHandle; // at offset 0xee8

};

#elif(WIN7)

struct  _NDIS_MINIPORT_BLOCK {
	_NDIS_OBJECT_HEADER Header;
	_NDIS_MINIPORT_BLOCK* NextMiniport;
	_NDIS_MINIPORT_BLOCK* BaseMiniport;
	void* MiniportAdapterContext;
	UCHAR MajorNdisVersion;
	UCHAR MinorNdisVersion;
	void* PerProcCounters;
	void* pvoidEnabledPerformanceCounters;
	void* OpenQueue;
	_REFERENCE ShortRef;
	void* pvoidEnabledPerformanceCountersEx;
	UCHAR LinkStateIndicationFlags;
	UCHAR LockAcquired;
	UCHAR PmodeOpens;
	UCHAR Reserved23;
	void* Lock;
	void* MediaRequest; // _NDIS_REQUEST*
	void* Interrupt; //_NDIS_MINIPORT_INTERRUPT*
	UINT32 Flags;
	UINT32 PnPFlags;
	_LIST_ENTRY PacketList;
	void* FirstPendingPacket; //_NDIS_PACKET* 
	void* ReturnPacketsQueue; //_NDIS_PACKET*
	UINT32 RequestBuffer;
	void* SetMCastBuffer;
	_NDIS_MINIPORT_BLOCK* PrimaryMiniport;
	void* NextCancelSendNetBufferListsHandler;
	void* OidContext;
	void* SupportedOidListLength; //--------------------------------------- c8
	_CM_RESOURCE_LIST* Resources;
	_NDIS_TIMER WakeUpDpcTimer;
	_NET_IF_MEDIA_CONNECT_STATE MiniportMediaConnectState;
	_NET_IF_MEDIA_DUPLEX_STATE MiniportMediaDuplexState; // _NET_IF_MEDIA_DUPLEX_STATE   (4 on x86)
	_UNICODE_STRING SymbolicLinkName;
	UINT32 CheckForHangSeconds;
	UINT16 CFHangTicks;
	UINT16 CFHangCurrentTick;
	UINT32 ResetStatus;
	void* ResetOpen;
	_X_FILTER* EthDB; //-------------------------------------------------------------
	_X_FILTER* TrDB;
	void* YYYDB;
	void* XXXDB;
	void* PacketIndicateHandler;
	void* SendCompleteHandler;
	void* SendResourcesHandler;
	void* ResetCompleteHandler;
	_NDIS_MEDIUM MediaType;
	UINT32 AutoNegotiationFlags;
	_NDIS_INTERFACE_TYPE Reserved5;
	_NDIS_INTERFACE_TYPE AdapterType;
	_NET_IF_MEDIA_CONNECT_STATE MediaConnectState;
	MY_NET_IF_MEDIA_DUPLEX_STATE MediaDuplexState;// _NET_IF_MEDIA_DUPLEX_STATE  (4 on x86)
	void* SupportedOidList;
	void* MiniportSGDmaBlock; //NDIS_SG_DMA_BLOCK* 
	_NDIS_AF_LIST* CallMgrAfList;
	void* MiniportThread;
	void* SetInfoBuf;
	UINT16 SetInfoBufLen;
	UINT16 MaxSendPackets;
	UINT32 FakeStatus;
	void* GlobalTriageBlock;
	_NDIS_RECEIVE_SCALE_PARAMETERS* CombinedNdisRSSParameters;
	_NDIS_MINIPORT_TIMER* TimerQueue;
	UINT32 MacOptions;
	void* PendingRequest;//_NDIS_REQUEST*  
	UINT32 MaximumLongAddresses;
	UINT32 MaximumShortAddresses;
	UINT32 MiniportCurrentLookahead;
	UINT32 MiniportMaximumLookahead;
	_X_FILTER* NullMediaFilter;
	void* DisableInterruptHandler;
	void* EnableInterruptHandler;
	void* SendPacketsHandler;
	void* DeferredSendHandler;
	void* EthRxIndicateHandler;
	void* TrRxIndicateHandler;
	void* NextSendNetBufferListsHandler;
	void* EthRxCompleteHandler;
	void* TrRxCompleteHandler;
	void* SavedNextSendNetBufferListsHandler;
	void* StatusHandler;
	void* StatusCompleteHandler;
	void* TDCompleteHandler;
	void* QueryCompleteHandler;
	void* SetCompleteHandler;
	void* WanSendCompleteHandler;
	void* WanRcvHandler;
	void* WanRcvCompleteHandler;
	void* IndicateNetBufferListsHandler;
	void* IndicateNetBufferListsContext;
	void* SendNetBufferListsCompleteHandler;
	void* NextReturnNetBufferLists;
	void* NextReturnNetBufferListsContext;
	_KEVENT * PnPEventLockEvent;
	_NDIS_OBJECT_HEADER* MediaSpecificAttributes;
	_IRP* PendingQueryPowerIrp;
	void* UnalignedPerProcCounters;
	void* InterruptEx; // _NDIS_INTERRUPT_BLOCK
	UINT64 XmitLinkSpeed;
	UINT64 RcvLinkSpeed;
	_NDIS_SUPPORTED_PAUSE_FUNCTIONS PauseFunctions;
	_PROCESSOR_NUMBER AssignedProcessor;
	_NDIS_SUPPORTED_PAUSE_FUNCTIONS MiniportPauseFunctions;
	UINT32 MiniportAutoNegotiationFlags;
	_SINGLE_LIST_ENTRY WorkQueue[7];
	_SINGLE_LIST_ENTRY SingleWorkItems[6];
	UCHAR SendFlags;
	UCHAR TrResetRing;
	UCHAR MP6SupportPM;
	UCHAR XState;
	void* Log; // _NDIS_LOG*
	_CM_RESOURCE_LIST* AllocatedResources;
	_CM_RESOURCE_LIST* AllocatedResourcesTranslated;
	_SINGLE_LIST_ENTRY PatternList;
	_SINGLE_LIST_ENTRY WOLPatternList;
	_SINGLE_LIST_ENTRY PMProtocolOffloadList;
	_NDIS_PNP_CAPABILITIES PMCapabilities61;
	_NDIS_PM_CAPABILITIES PMHardwareCapabilities;
	_NDIS_PM_CAPABILITIES PMAdvertisedCapabilities;
	_NDIS_PM_PARAMETERS PMCurrentParameters;
	_DEVICE_CAPABILITIES DeviceCaps;
	UCHAR S0WakeupSupported;
	UINT32 CombinedWakeUpEnable;
	UINT32 WakeUpEnable;
	_IRP* pIrpWaitWake;
	_SYSTEM_POWER_STATE WaitWakeSystemState;
	_LARGE_INTEGER VcIndex;
	void* VcCountLock;
	_LIST_ENTRY WmiEnabledVcs;
	_NDIS_GUID* pNdisGuidMap;
	_NDIS_GUID* pCustomGuidMap;
	UINT16 VcCount;
	UINT16 cNdisGuidMap;
	UINT16 cCustomGuidMap;
	_NDIS_TIMER MediaDisconnectTimer;
	_NDIS_PNP_DEVICE_STATE PnPDeviceState;
	_NDIS_PNP_DEVICE_STATE OldPnPDeviceState;
	_KDPC DeferredDpc;
	_LARGE_INTEGER StartTicks;
	void* IndicatedPacket;
	_KEVENT* RemoveReadyEvent;
	_KEVENT* AllOpensClosedEvent;
	_KEVENT* AllRequestsCompletedEvent;
	UINT32 InitTimeMs;
	_NDIS_MINIPORT_WORK_ITEM WorkItemBuffer[6];
	void* OidList;
	UINT16 InternalResetCount;
	UINT16 MiniportResetCount;
	UINT16 MediaSenseConnectCount;
	UINT16 MediaSenseDisconnectCount;
	void* xPackets;
	UINT32 UserModeOpenReferences;
	void* SavedIndicateNetBufferListsHandler;
	void* SavedIndicateNetBufferListsContext;
	void* WSendPacketsHandler;
	UINT32 MiniportAttributes;
	UINT16 NumOpens;
	UINT16 CFHangXTicks;
	UINT16 RequestCount;
	UINT32 IndicatedPacketsCount;
	UINT32 PhysicalMediumType;
	_NDIS_MEDIUM MiniportMediaType;
	void* LastRequest;
	void* FakeMac;
	UINT32 LockDbg;
	UINT32 LockDbgX;
	void* LockThread;
	UINT32 InfoFlags;
	void* TimerQueueLock;
	_KEVENT* ResetCompletedEvent;
	_KEVENT* QueuedBindingCompletedEvent;
	void* SavedPacketIndicateHandler;
	UINT32 RegisteredInterrupts;
	UINT32 SetOid;
	_KEVENT* WakeUpTimerEvent;
	void* DeviceContext0;
	void* DeviceContext1; // Replacement for Device context which is 8 on x86 and 16 on x64 size bytes.
	UCHAR CombinedRSSParametersBuf[bufferStructSize1]; // 604 //656
	UCHAR RSSParametersBuf[bufferStructSize2];  // 604  //656
	UCHAR UsingMSIX;
	UCHAR Miniport5InNdis6Mode;
	UCHAR Miniport5HasNdis6Component;
	UCHAR RestoreStackNeeded;
	UCHAR MediaChangeFilters;
	UCHAR FilterPnPLockAcquired;
	UCHAR LWFilterAllLoaded;
	UCHAR CheckPacketFilters;
	void* ReceiveFilters; // Change !!!! It is in real pointer size
	void* FilterPnPLockThread;
	void* FilterPnPLockDbgX; // platform
	void* RecvLock;
	_NDIS_MINIPORT_STATE RecvState;
	UINT16 OutstandingReceives;
	void* MiniportRecvLockThread;
	void* RecvLockDbg; // platform  It is in real pointer size
	void* NextSendPacketsHandler;
	void* FinalSendPacketsHandler;
	void* LWFilterMutexOwnerThread;
	UINT32 LWFilterMutexOwner;
	UINT32 LWFilterMutexOwnerCount;
	void* LowestFilter; // _NDIS_FILTER_BLOCK
	void* HighestFilter; // _NDIS_FILTER_BLOCK
	void* ShutdownContext;
	void* ShutdownHandler;
	_KBUGCHECK_CALLBACK_RECORD BugcheckCallbackRecord;
	void* TopIndicateNetBufferListsHandler;
	void* TopIndicateLoopbackNetBufferListsHandler;
	void* Ndis5PacketIndicateHandler;
	void* MiniportReturnPacketHandler;
	void* MiniportReturnPacketContext;
	void* SynchronousReturnPacketHandler;
	void* SynchronousReturnPacketContext;
	void* NextRequestHandler;
	void* NextRequestContext;
	_LIST_ENTRY OidRequestList;
	_NDIS_OID_REQUEST* PendingOidRequest;
	void* NextCoOidRequestHandle;
	UINT32 Ndis6ProtocolsBound;
	UINT32 PmodeOpen6;
	_NDIS_MINIPORT_STATE State;
	_KEVENT* AsyncOpCompletionEvent;
	UINT32 AsyncOpCompletionStatus;
	_ULONG_REFERENCE Ref;
	UINT64 MaxXmitLinkSpeed;
	UINT64 MaxRcvLinkSpeed;
	UINT32 SupportedPacketFilters;
	_NDIS_MINIPORT_HANDLERS NoFilter;
	_NDIS_MINIPORT_HANDLERS Next;
	UINT32 NumOfPauseRestartRequests;
	UINT32 FilterPnPFlags;
	UINT32 SupportedStatistics;
	UINT32 cDpcSendCompletes;
	UINT32 cDpcRcvIndications;
	UINT32 cDpcRcvIndicationCalls;
	UINT32 cDpcNbSendCompletes;
	UINT32 cDpcNblSendCompletes;
	UINT32 cDpcNblIndications;
	UINT32 cDpcMaxPacketsIndicated;
	UINT32 cDpcTotalDpcCount;
	_NDIS_RECEIVE_SCALE_CAPABILITIES RecvScaleCapabilities;
	_NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES* GeneralAttributes;
	_LIST_ENTRY PortList;
	UCHAR * AllocatedPortIndices;
	UINT32 AllocatedPortIndicesLength;
	UINT32 NumberOfPorts;
	UINT32 NumberOfActivePorts;
	UINT64 MiniportXmitLinkSpeed;
	UINT64 MiniportRcvLinkSpeed;
	_KEVENT RestoreStackTimerEvent;
	_NDIS_TIMER RestoreStackTimer;
	_NDIS_WORK_ITEM RestoreStackWorkItem;
	UINT32 RestoreStackBindRefCount;
	UINT32 ProtocolsToBind;
	void* DpcTrackers; // DpcTrackers
	void* CurrentDpcTracker;
	UCHAR DpcTrackerIndex;
	UCHAR SupportedRss;
	UINT64 DpcWatchDogCycleCount;
	UINT32 DataBackFillSize;
	UINT32 ContextBackFillSize;
	UINT32 SupportedPauseFunctions;
	_NDIS_RESTART_GENERAL_ATTRIBUTES TopFilterRestartAttributes;
	_NDIS_RECEIVE_SCALE_CAPABILITIES TopRecvScaleCapabilities;
	INT32 NumOfOpenPauseRestartRequests;
	INT32 MiniportStackPauseCount;
	UINT32 NsiOpenReferences;
	_KEVENT* NsiRequestsCompletedEvent;
	_DEVICE_POWER_STATE QueryPowerDeviceState;
	UCHAR MinimumNdisMajorVersion;
	UCHAR MinimumNdisMinorVersion;
	UINT16 NumOfMinimumVersionDrivers;
	void* BottomIfStats; // _NDIS_MINIPORT_STATS*
	_NDIS_M_PERIODIC_RECEIVES PeriodicReceiveQueue;
	_NDIS_PORT_CONTROL_STATE DefaultSendControlState;
	_NDIS_PORT_CONTROL_STATE DefaultRcvControlState;
	_NDIS_PORT_AUTHORIZATION_STATE DefaultSendAuthorizationState;
	_NDIS_PORT_AUTHORIZATION_STATE DefaultRcvAuthorizationState;
	_NDIS_PORT_CONTROL_STATE DefaultPortSendControlState;
	_NDIS_PORT_CONTROL_STATE DefaultPortRcvControlState;
	_NDIS_PORT_AUTHORIZATION_STATE DefaultPortSendAuthorizationState;
	_NDIS_PORT_AUTHORIZATION_STATE DefaultPortRcvAuthorizationState;
	_NDIS_PCI_DEVICE_CUSTOM_PROPERTIES PciDeviceCustomProperties;
	void* TopNdis5PacketIndicateHandler;
	UINT* ndisSupportedOidList;
	UINT32 ndisSupportedOidListLength;
	UINT32 MsiIntCount;
	_WORK_QUEUE_ITEM MiniportDpcWorkItem;
	UINT64 InvalidFrames;
	UINT32 PagingPathCount;
	_LIST_ENTRY ReceiveQueueList;
	UCHAR* AllocatedQueueIndices;
	UINT32 AllocatedQueueIndicesLength;
	UINT32 NumReceiveQueues;
	_LIST_ENTRY ReceiveFilterList;
	UCHAR* AllocatedReceiveFilterIndices;
	UINT32 AllocatedReceiveFilterIndicesLength;
	UINT32 NumReceiveFilters;
	UINT32 EnabledReceiveFilterTypes;
	UINT32 EnabledReceiveQueueTypes;
	_NDIS_RECEIVE_FILTER_CAPABILITIES* ReceiveFilterHwCapabilities;
	_NDIS_RECEIVE_FILTER_CAPABILITIES* ReceiveFilterCurrentCapabilities;
	_NDIS_NIC_SWITCH_CAPABILITIES* NicSwitchHwCapabilities;
	_NDIS_NIC_SWITCH_CAPABILITIES* NicSwitchCurrentCapabilities;
	_LIST_ENTRY SharedMemoryBlockList;
	INT* AllocateSharedMemoryHandler;
	void* FreeSharedMemoryHandler;
	void* AllocateSharedMemoryContext;
	UINT32 MsiXTableEntries;
	PCI_MSI_CAPABILITY MsiCaps;
	PCI_MSIX_CAPABILITY MsiXCaps;
	UINT64 NumberOfIndirectionTableChanges;
	UINT32 NumUserOpens;
	_NDIS_MINIPORT_OFFLOAD_REG OffloadRegistry;
	UINT16 MediaDisconnectTimeOut;
	UINT16 SGMapRegistersNeeded;
	UINT32 DriverVerifyFlags;
	ULONG* SetBusData;
	ULONG* GetBusData;
	void* BusDataContext;
	_NDIS_INTERFACE_TYPE BusType;
	UINT32 BusNumber;
	UINT32 SlotNumber;
	_NDIS_EVENT OpenReadyEvent;
	UINT32 NumAdminOpens;
	_NDIS_M_DRIVER_BLOCK* DriverHandle;
	void* BindPaths; // _NDIS_BIND_PATHS
	void* LWFilterList; // _NDIS_BIND_PATHS
	NDIS_PROTOCOL_BLOCK** ProtocolsFailToBind;
	UINT32 MiniportPhysicalMediumType;
	void* LWFilterAttachList;
	UINT32 NumFilters;
	UINT32 NetLuidIndex;
	_KMUTANT LWFilterMutex;
	void* SecurityDescriptor;
	_UNICODE_STRING BaseName;
	_UNICODE_STRING MiniportName;
	_DEVICE_OBJECT* DeviceObject;
	_DEVICE_OBJECT* PhysicalDeviceObject;
	_DEVICE_OBJECT* NextDeviceObject;
	_NDIS_MINIPORT_BLOCK* NextGlobalMiniport;
	_UNICODE_STRING* pAdapterInstanceName;
	UINT32 PnPCapabilities;
	_DEVICE_POWER_STATE CurrentDevicePowerState;
	_DEVICE_POWER_STATE DriverPowerState;
	_NDIS_PM_ADMIN_GONFIG PMAdminConfig;
	_KSEMAPHORE PMPatternSemaphore;
	_KSEMAPHORE PMOffloadSemaphore;
	void* BusInterface;
	UINT16 InstanceNumber;
	void* ConfigurationHandle;
	_GUID InterfaceGuid;
	void* IfBlock; // _NDIS_IF_BLOCK
	UINT32 IfIndex;
	_NET_IF_ADMIN_STATUS AdminStatus;
	_NET_IF_OPER_STATUS OperStatus;
	UINT32 OperStatusFlags;
	INT* WanSendHandler;
	void* Offload; // _NDIS_MINIPORT_OFFLOAD
	void* AddDeviceContext;
	MY_IO_REMOVE_LOCK RemoveLock; // MY_IO
	_UNICODE_STRING DevinterfaceNetSymbolicLinkName;
	UCHAR RssEnable;
	UCHAR ChimneyEnable;
	UINT32 PhysicalMediumInInf;
	_UNICODE_STRING ExportName;
	_UNICODE_STRING FilterClass;
	void* StatusProcessingThread;
	UINT32 StatusProcessingDbgX;
	_UNICODE_STRING FdoName;
	_NDIS_MINIPORT_BLOCK* NextOrphanedMiniport;
	_KEVENT PowerEvent;
	_KEVENT* pPowerEvent;
	UINT32 DirectOidRequestCount;
	_KEVENT* AllDirectRequestsCompletedEvent;
	void* HDSplitCurrentConfig2;  // _NDIS_HD_SPLIT_CURRENT_CONFIG
	void* MSIXConfigContext;
	LONG* SetMSIXTableEntry;
	LONG* MaskMSIXTableEntry;
	LONG* UnmaskMSIXTableEntry;
	_WORK_QUEUE_ITEM DevicePowerStateWorkItem;
	_WORK_QUEUE_ITEM SystemPowerStateWorkItem;
	void* DefaultReceiveQueue; // _NDIS_RECEIVE_QUEUE_BLOCK
	UINT32 MaxNumRssProcessors;
	_PROCESSOR_NUMBER RssBaseProcessor;
	UINT16 NumaNodeId;
	UINT16* NumaDistances;
	_UNICODE_STRING* pModifiedInstanceName;
	_WORK_QUEUE_ITEM DeleteMiniportWorkItem;
	void* ProcessingOpen;
	UINT32 SyncFlags;
	UINT32 WSyncFlags;
};

#endif



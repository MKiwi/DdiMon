
LLNM - Low Level Network Monitor
=======

LLNM is a proof of concept tool for detecting outgoing 'hidden' TCP network communication.

Modern rootkits try to hide its network communication from OS, firewalls 
and other security solutions.

This project was inspired by rootkit Pitou, which used NDIS hooks to 
conceal communication by sending network data directly to **SendNetBufferLists** 
function handler from module ndis.sys. 

This function is responsible for direct communication with network card.
Firewalls and monitoring tools working on higher levels in windows 
network stack thus are unable to detect anything suspicious.


LLNM is a tool built on the top of hypervisor [DdiMon](https://github.com/tandasat/DdiMon) and uses its hidden 
hooks (Kernel modification is forbidden - KPP, Attacker may check structures for hooks) to modify   
SendHandler function in order to capture data which are sent from system.


**Hook handler header (SendNetBufferLists):**

	static VOID HandleSendNetBufferLists(
	_In_ NDIS_HANDLE      NdisBindingHandle,
	_In_ PNET_BUFFER_LIST NetBufferLists,
	_In_ NDIS_PORT_NUMBER PortNumber,
	_In_ ULONG            SendFlags);

Important is structure *NET_BUFFER_LIST* which contains data that are going to be sent over the network.
Data in this structure are parsed and IP address and PORT of hosts are retrieved.

See references for more information about *_NET_BUFFER_LIST* structure.


Detection Method
--------------------------------

After retrieving IP and PORT of destination host, we check, whether system
has information about this connection, since we are interested only in TCP.
If OS does not track the connection, we can say, that packet is probably attempt
to produce hidden malicious network traffic.

In user mode, checking of existing connection is easy, using WinAPI *GetTcpTable2()*.  
Since we work in Kernel mode, unfortunately there is not any API like this for drivers.  
Combination of User mode application and Kernel mode driver would be very inefficient
because handler checks connection every time the OS sends out ethernet frame and
switching from Kernel mode to User mode would have big performance hit. 

Therefore we had to reverse engineer Windows Internals to retrieve Information
about existing TCP connections in the system by ourselves.

We explored function **TcpEnumerateConnections()** implemented in module tcpip.sys.
	
Technical difficulties
--------------------------------

### 1) GetAddress of function **NdisSendNetBufferLists**.
We analysed malware Pitou, Windows internals and used information from [article](https://www.virusbulletin.com/virusbulletin/2007/11/spam-kernel) about malware Srizbi.  
Following picture describes way, how we obtain this address.

![](https://raw.githubusercontent.com/MKiwi/LLNM/master/pictures/ndis_structures_flow.PNG)


1. First We Use WinAPI *NdisRegisterProtocolDriver()* to install custom fake network protocol, which is absolutely useless.  
We do this only to get access to chain of structures, representing installed protocols and this is the way, how to get to that chain.  
After getting address of send handler, protocol is uninstalled.
      
      	NDIS_STATUS NdisRegisterProtocolDriver(
          NDIS_HANDLE                           ProtocolDriverContext,
          PNDIS_PROTOCOL_DRIVER_CHARACTERISTICS ProtocolCharacteristics,
          PNDIS_HANDLE                          NdisProtocolHandle
         );
	
2. *NdisProtocolHandle* variable is in fact pointer to structure \_NDIS\_PROTOCOL\_BLOCK which is set up by NDIS after installing protocol.
3. Iterate through structures until we get some protocol installed for TCPIP.
4. Using member *OpenQueue* we obtain structure \_NDIS\_OPEN\_BLOCK which contains information about binding
   between protocol driver and miniport driver. 
5. Next we check *BindDeviceName* member which contains String GUID of network adapter.  
Since this project is Proof of concept, we do not monitor all network interfaces, but choose only one (the best Gateway), the same way as malware Pitou did.  
Using WinAPI *GetIpForwardTable2()* we retrieve IP address of Default Gateway.  
Then enumerate registry key [\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\]  
and check value *"DhcpDefaultGateway"* against retrieved IP.  
This way we obtain Network Interface GUID (key name of network adapter) which is then compared against *BindDeviceName* member. 

6. Finally through member *MiniportHandle* which is another pointer, we get to structure *\_NDIS\_MINIPORT\_BLOCK*  
and using member *DriverHandle* which is pointer as well we get *\_NDIS\_M\_DRIVER\_BLOCK* structure.  
Substructure with name *\_NDIS\_MINIPORT\_DRIVER\_CHARACTERISTICS* contains member *SendNetBufferListsHandler* which is pointer to desired function.

### 2) Check system for TCP connection record

*Analysing function *TcpEnumerateConnections()* we've came to the following results*:  
Module *tcpip.sys* contains variables *TCPIP_PARTITION_TABLE* and *TCPIP_PARTITION_PARTITION_COUNT* pointers.  
We rely on the fact, that these variables are at constant offsets within module tcpip.sys.  
Structure *TCPIP_PARTITION_TABLE* contains pointer to Hash table, in which OS Windows stores information about TCP endpoints.  
By enumerating this hash table we are able to verify, whether systems knows about specific connection or not.  
 
```c++
bool CheckTcpipConnection(IN_ADDR* dstIP,USHORT port) {
	RTL_DYNAMIC_HASH_TABLE_ENUMERATOR enumerator;
	KLOCK_QUEUE_HANDLE LockHandle;
	bool found = false;

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
	   while (1) 
	   {

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
```


Demonstration
--------------------------------

Here is a video showing LLNM in Action.
- https://youtu.be/Y2q1RSp8jSk



Installation and Uninstallation
--------------------------------
See description for DdiMon.  
Use some driver loader to load LLNM  
- [OSR DDriver Loader](https://www.osronline.com/article.cfm?article=157)



Output
-------
Use [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview) from SysInternals to watch kernel log



Relevant resources and references
-----------


- [1] [FSecure: The “silent” resurrection of the notorious Srizbi kernel spambot](https://www.f-secure.com/documents/996508/1030745/pitou_whitepaper.pdf)
- [2] [Srizbi rootkit](https://www.virusbulletin.com/virusbulletin/2007/11/spam-kernel)
- [3] NDIS Structures
	      [\_NET\_BUFFER\_XXX Structures](https://www.codemachine.com/article_ndis6nbls.html)
	      [NDIS Windbg](https://blogs.msdn.microsoft.com/ntdebugging/2008/09/19/ndis-part-1/)
	      [NDIS Internal Structures](http://redplait.blogspot.com/2010/07/ndis-structs.html)
	      
	      
- [4] TCP Endpoints
	      http://www.robobrarian.info/b_pubs/CandSOkolica.pdf
- [5] TCP Info Extraction
	      https://pdfs.semanticscholar.org/4b33/508bb8aebd3e8b8d697e93f3164e801a011c.pdf
	  



Supported Platforms
----------------------
- x86 and x64 Windows 7
- Capturing network communication works on Windows 10, but detection is not
  supported.  
  (didnt have time to reverse engineer structures of this OS version).  
  
**Layouts of *TCPIP_PARTITION_TABLE*, NDIS and other structures are not documented.  
These structures are different among various os versions.  
It is necessary to write different code for each version.  
File "ndisStructs.h" contains structure definitions. For some os version, there may be whole structure definition with all structure members and for some, there are only important members and padding is used to match original structure.  
Compilation is controlled by preprocessor variables *_WIN64*(set up by Visual Studio when choosing platform) and *WIN7* which is necessary to setup manually in "ndisStructs.h"**  

Constants *TABLE_ENTRY_PADDING0*, *TABLE_ENTRY_PADDING1* and *0x1ca* are result of reverse engineering.  


```c++
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

```
  
- The system must support the Intel VT-x and EPT technology (DdiMon)  

- Use *--recurse-submodules* switch when cloning repo




LLNM - Low Level Network Monitor
=======

LLNM is a tool for detecting outgoing hidden TCP network communication.

Modern rootkits try to hide its network communication from OS, firewalls 
and other security solutions.

This project was inspired by rootkit Pitou, which was used NDIS hooks to 
hide its communication by sending network data directly to **SendNetBufferLists** 
function handler from module ndis.sys. 

This function is responsible for direct communication with network card.
Firewalls and other monitoring tools working on higher level in windows 
network stack thus were unable to detect anything suspicious.


LLNM is a tool built on the top of hypervisor DdiMon and uses its hidden 
hooks to modify SendHandler function in order to capture data which are
sent from system.

- https://github.com/tandasat/DdiMon

**Hook handler header:**

	static VOID HandleSendNetBufferLists(
	_In_ NDIS_HANDLE      NdisBindingHandle,
	_In_ PNET_BUFFER_LIST NetBufferLists,
	_In_ NDIS_PORT_NUMBER PortNumber,
	_In_ ULONG            SendFlags);

Important is structure NET_BUFFER_LIST which contains data which are going to be sent over the network.
Data in this structure must be parsed and we retrieve 
IP address and PORT of hosts.

See references for more information about _NET_BUFFER_LIST structure.


Detection Method
--------------------------------

After retrieving IP and PORT of destination host, we check, whether system
has information about this connection, since we are interested only in TCP.
If OS does not track connection, we can say that packet is probably attempt
to produce hidden malicious network traffic.

In user mode, checking of existing connection is easy using WinAPI GetTcpTable2().
Since we work in Kernel mode, unfortunately there is not any API like this for drivers.
Combination of User mode application and Kernel mode driver would be very inefficient
because handler checks connection every time the OS sends out ethernet frame and
switching from Kernel mode to User mode would have performance hit. 

Therefore we had to reverse engineer Windows Internals to retrieve Information
about existing TCP connections in the system by ourselves.

We explored function **TcpEnumerateConnections** implemented in module tcpip.sys.
	
Technical difficulties
--------------------------------

- [1] GetAddress of function **NdisSendNetBufferLists**.
	  We analysed malware pitou, windows internals and used information
	  from article about malware Srizbi.

	 Following picture describes way, how we obtain this address.

![](https://raw.githubusercontent.com/MKiwi/DdiMon/master/path/pictures/ndis_structures_flow.png)



Demonstration
--------------------------------

Here is a movie showing LLNM in Action.
- https://youtu.be/Y2q1RSp8jSk



Installation and Uninstallation
--------------------------------
See description for DdiMon.
Use OSR driver loader to load LLNM 
- https://www.osronline.com/article.cfm?article=157



Output
-------
Use DebugView from SysInternals to watch kernel log
- https://docs.microsoft.com/en-us/sysinternals/downloads/debugview


Relevant resources and references
-----------


- [1] FSecure: The “silent” resurrection of the notorious Srizbi kernel spambot
		 https://www.f-secure.com/documents/996508/1030745/pitou_whitepaper.pdf
- [2] Srizbi rootkit
	      https://www.virusbulletin.com/virusbulletin/2007/11/spam-kernel
- [3] NDIS Structures
	      https://www.codemachine.com/article_ndis6nbls.html
- [4] TCP Endpoints
	      http://www.robobrarian.info/b_pubs/CandSOkolica.pdf
- [5] TCP Info Extraction
			  https://pdfs.semanticscholar.org/4b33/508bb8aebd3e8b8d697e93f3164e801a011c.pdf
	  





Supported Platforms
----------------------
- x86 and x64 Windows 7
- Capturing network communication works on Windows 10 but detection is not
  supported (didnt have time to reverse engineer structures of this version OS).
- The system must support the Intel VT-x and EPT technology (DdiMon)


License
--------
This software is released under the MIT License, see LICENSE.

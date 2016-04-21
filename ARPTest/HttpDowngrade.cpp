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

//  HttpDowngrade.cpp: force hosts to use HTTP 1.0 and no encoding.
//

#include "stdafx.h"
#include "HttpDowngrade.h"
#include "Packet.h"


void HttpDowngrade::OnTargetForward(std::unique_ptr<BYTE[]>& data, UINT& len)
{
	IPPacket* pIp = (IPPacket*)&data[ETH_LENGTH];
	// not TCP
	if (pIp->protocol != PROTOCOL_TCP)
		return;
	DWORD ipLength = pIp->headerLen * 4;
	TCPPacket* pTcp = (TCPPacket*)&data[ETH_LENGTH + ipLength];
	DWORD tcpLength = pTcp->headerLen * 4;

	char* pData = (char*)&data[ETH_LENGTH + ipLength + tcpLength];
	// not interested HTTP request
	if (strncmp(pData, "GET ", 4) != 0 && strncmp(pData, "POST ", 5) != 0)
		return;

	bool modified = false;

	// downgrade to HTTP 1.0
	// it seems useless. servers don't always use HTTP 1.0
	/*char* pHttp = strstr(pData, " HTTP/1.1\r\n");
	if (pHttp != nullptr)
	{
		pHttp[8] = '0';
		modified = true;
	}*/

	// no encoding!
	char* pAcceptEncoding = strstr(pData, "Accept-Encoding: ");
	if (pAcceptEncoding != nullptr)
	{
		memcpy(pAcceptEncoding, "Accept-Rubbish!: ", 17);
		modified = true;
	}

	if (modified)
		pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, data.get() + len - (BYTE*)pTcp);
}

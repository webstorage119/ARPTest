#pragma once
#include <memory>
#include <pcap.h>


typedef std::unique_ptr<pcap_t, void(*)(pcap_t*)> AdapterHandle;
AdapterHandle GetAdapterHandle();
void SetFilter(pcap_t* adapter, const char* exp);

bool CreateDirs(const CString& path);

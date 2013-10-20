
#ifndef PLUMAGE_WEB_API_CURL_CALLBACK_HPP
#define PLUMAGE_WEB_API_CURL_CALLBACK_HPP

#include <iosfwd>

size_t readInputStream(char* ptr, size_t size, size_t nmemb, std::istream* stream);
size_t writeOutputStream(char* ptr, size_t size, size_t nmemb, void* stream);
size_t notifyUserCallback(char* ptr, size_t size, size_t nmemb, void* func);
int progress_func(void* ptr, double TotalToDownload, double NowDownloaded, double TotalToUpload, double NowUploaded);

#endif



#ifndef PLUMAGE_WEB_API_CURL_DATA_HPP
#define PLUMAGE_WEB_API_CURL_DATA_HPP

#include <curl/curl.h>
#include <cstddef>
#include <functional>

#include "plumage_webapi/curl/curl_callback.hpp"

typedef size_t (*CurlCallBack)(char*, size_t, size_t, void*);
typedef std::function<size_t(char*,size_t)> ReceiveDataListner;

struct CurlData {
    CurlData(CURL* curl) : curl(curl), callback(nullptr) {}

    void setWriteTarget(std::ostream* os) {
        callback = &writeOutputStream;
        //listner = os;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &writeOutputStream);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, os);
    }
    void setWriteTarget(ReceiveDataListner* userCallback) {
        callback = &notifyUserCallback;
        //listner = userCallback;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &notifyUserCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, userCallback);
    }

    CURL* curl;
    CurlCallBack callback;
    //void* listner;
};

#endif


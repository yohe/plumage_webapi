#ifndef PLUMAGE_WEB_API_HTTP_HPP
#define PLUMAGE_WEB_API_HTTP_HPP

#include <string>
#include <ostream>
#include <map>
#include "plumage_webapi/curl/curl_data.hpp"

class HttpApi {
public:

    void setPostData(CurlData* curl, const std::string& data) const;

    template <class T>
    void get(CurlData* curl, const std::string& url, T* listner) const {
        curl->setWriteTarget(listner);
        get(curl, url);
    }
    void get(CurlData* curl, const std::string& url) const;

    template <class T>
    void post(CurlData* curl, const std::string& url, T* listner) const {
        curl->setWriteTarget(listner);
        post(curl, url);
    }
    void post(CurlData* curl, const std::string& url) const;

    std::string encodeToPercentEncoding(std::string data) const;
    std::map<std::string, std::string> parseQueryData(const std::string& data) const;
};

#endif

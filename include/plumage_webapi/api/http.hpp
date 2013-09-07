#ifndef PLUMAGE_WEB_API_HTTP_HPP
#define PLUMAGE_WEB_API_HTTP_HPP

#include <string>
#include <ostream>
#include <map>
#include <curl/curl.h>

class HttpApi {
public:

    void get(CURL* curl, const std::string& url, std::ostream& stream) const;
    void post(CURL* curl, const std::string& url, const std::string& data, std::ostream& stream) const;
    std::string encodeToUrlEncode(const std::string data) const;

    std::map<std::string, std::string> parseQueryData(const std::string& data) const;
};

#endif

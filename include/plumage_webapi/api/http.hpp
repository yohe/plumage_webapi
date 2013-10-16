#ifndef PLUMAGE_WEB_API_HTTP_HPP
#define PLUMAGE_WEB_API_HTTP_HPP

#include <string>
#include <ostream>
#include <map>
#include <curl/curl.h>

class HttpApi {
public:

    void get(CURL* curl, const std::string& url, std::ostream& stream) const;
    void setPostData(CURL* curl, const std::string& data) const;
    void post(CURL* curl, const std::string& url, std::ostream& stream) const;
    std::string encodeToPercentEncoding(std::string data) const;

    std::map<std::string, std::string> parseQueryData(const std::string& data) const;
};

#endif

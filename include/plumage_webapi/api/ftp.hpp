#ifndef PLUMAGE_WEB_API_FTP_HPP
#define PLUMAGE_WEB_API_FTP_HPP

#include <string>
#include <ostream>
#include "plumage_webapi/curl/curl_data.hpp"

class FtpApi {
public:

    void listUpFile(CurlData* curl, const std::string& url, bool nameOnly, std::ostream& stream) const;
    void downloadFile(CurlData* curl, const std::string& url, std::ostream& stream) const;
    void createDirectory(CurlData* curl, const std::string& url, bool recursive) const;
    void uploadFile(CurlData* curl, const std::string& url, const std::istream& stream) const;
};

#endif

#ifndef PLUMAGE_WEB_API_FTP_HPP
#define PLUMAGE_WEB_API_FTP_HPP

#include <string>
#include <ostream>
#include <curl/curl.h>

class FtpApi {
public:

    void listUpFile(CURL* curl, const std::string& url, bool nameOnly, std::ostream& stream) const;
    void downloadFile(CURL* curl, const std::string& url, std::ostream& stream) const;
    void createDirectory(CURL* curl, const std::string& url, bool recursive) const;
    void uploadFile(CURL* curl, const std::string& url, const std::istream& stream) const;
};

#endif

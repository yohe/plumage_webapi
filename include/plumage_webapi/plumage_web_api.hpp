
#ifndef PLUMAGE_WEB_API_HPP
#define PLUMAGE_WEB_API_HPP

#include <cstdlib>
#include <set>
#include <string>
#include <sstream>

#include <curl/curl.h>
#include <picojson.h>

#include <plumage/plugin_entity.hpp>

class PlumageWebApi : public plumage::PluginEntity {

    typedef void* (PlumageWebApi::*Method)(boost::any&);

    std::set<CURL*> curlHandles_;
    std::map<std::string, Method> methodList_;

    void init();

    // 
    void* createHandle(boost::any& parameter);
    void* deleteHandle(boost::any& parameter);

    // for FTP API
    void* listUpFileOnFtp(boost::any& parameter);
    void* downloadFileOnFtp_wait(boost::any& parameter);
    void* createDirectoryOnFtp(boost::any& parameter);
    void* uploadFileOnFtp_wait(boost::any& parameter);

    // for HTTP API
    void* getOnHttp(boost::any& parameter);
    void* postOnHttp(boost::any& parameter);

    // for auth
    void* setBasicAuth(boost::any& parameter);

    // for json
    void* parseJsonData(boost::any& parameter);

public:
    PlumageWebApi() : plumage::PluginEntity("PlumageWebApi") {
        init();
    }

    virtual ~PlumageWebApi() {
    }

    virtual int getInterfaceVersion() const {
        return 1;
    }
    virtual int getPluginVersion() const {
        return 1;
    }
    virtual bool isDebug() const {
#ifdef DEBUG
        return true;
#else
        return false;
#endif
    }

    virtual bool isCompatible(int interfaceVersion) const;
    virtual bool isCallable(const std::string& methodName) const;

protected:
    virtual bool doStart() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        return true;
    }
    virtual bool doStop() {
        curl_global_cleanup();
        return true;
    }

    virtual void* doCall(std::string methodName, boost::any& paramter) throw (std::exception);

};

size_t readInputStream(char* ptr, size_t size, size_t nmemb, std::istream* stream);
size_t writeOutputStream(char* ptr, size_t size, size_t nmemb, std::ostream* stream);
int progress_func(void* ptr, double TotalToDownload, double NowDownloaded, double TotalToUpload, double NowUploaded);

class FtpApi {
public:
    FtpApi() {}
    ~FtpApi() {}

    void listUpFile(CURL* curl, const std::string& url, bool nameOnly, std::ostream& stream) const;
    void downloadFile(CURL* curl, const std::string& url, std::ostream& stream) const;
    void createDirectory(CURL* curl, const std::string& url, bool recursive) const;
    void uploadFile(CURL* curl, const std::string& url, const std::istream& stream) const;
};

class JsonApi {
public:

    std::string parse(const std::string& in_data, picojson::value& out) const;
};

class HttpApi {
public:
    HttpApi() {}
    ~HttpApi() {}

    void get(CURL* curl, const std::string& url, std::ostream& stream) const;
    void post(CURL* curl, const std::string& url, const std::string& data, std::ostream& stream) const;
};

class AuthApi {
public:
    AuthApi() {}
    ~AuthApi() {}

    void useBasicAuth(CURL*, const std::string& username, const std::string& passwd);

};

#endif
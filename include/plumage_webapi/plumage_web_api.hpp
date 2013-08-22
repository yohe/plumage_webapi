
#ifndef PLUMAGE_WEB_API_HPP
#define PLUMAGE_WEB_API_HPP

#include <cstdlib>
#include <set>
#include <string>
#include <sstream>

#include <curl/curl.h>
#include <picojson.h>
#include <boost/property_tree/xml_parser.hpp>

#include <plumage/plugin_entity.hpp>

class PlumageWebApi : public plumage::PluginEntity {

    const int INTERFACE_VERSION = 1;
    const int PLUGIN_VERSION = 1;

    typedef boost::any (PlumageWebApi::*Method)(boost::any&);

    std::set<CURL*> curlHandles_;
    std::map<std::string, Method> methodList_;

    void init();

    // 
    boost::any createHandle(boost::any& parameter);
    boost::any deleteHandle(boost::any& parameter);

    // for FTP API
    boost::any listUpFileOnFtp(boost::any& parameter);
    boost::any downloadFileOnFtp_wait(boost::any& parameter);
    boost::any createDirectoryOnFtp(boost::any& parameter);
    boost::any uploadFileOnFtp_wait(boost::any& parameter);

    // for HTTP API
    boost::any getOnHttp(boost::any& parameter);
    boost::any postOnHttp(boost::any& parameter);

    // for auth
    //void* setBasicAuth(boost::any& parameter);

    // for json
    boost::any parseJsonData(boost::any& parameter);
    boost::any encodeToJsonData(boost::any& parameter);

    // for XML
    boost::any parseXmlData(boost::any& parameter);
    boost::any encodeToXmlData(boost::any& parameter);

public:
    PlumageWebApi() : plumage::PluginEntity("PlumageWebApi") {
        init();
    }

    virtual ~PlumageWebApi() {
    }

    virtual int getInterfaceVersion() const {
        return INTERFACE_VERSION;
    }
    virtual int getPluginVersion() const {
        return PLUGIN_VERSION;
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

    virtual boost::any doCall(std::string methodName, boost::any& paramter) throw (std::exception);

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

    std::string parse(std::istream& in_data, picojson::value& out) const;
    void encode(const picojson::value& in_data, std::ostream& out) const;
};

class XmlApi {
public:

    void parse(std::istream& in_data, boost::property_tree::ptree& pt) const;
    void encode(const boost::property_tree::ptree& in_data, std::ostream& out) const;
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

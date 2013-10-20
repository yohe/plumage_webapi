
#include <tuple>
#include <iostream>
#include <ostream>
#include <fstream>
#include <utility>
#include <openssl/hmac.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include "plumage_webapi/plumage_web_api.hpp"
#include "plumage_webapi/api/ftp.hpp"
#include "plumage_webapi/api/http.hpp"
#include "plumage_webapi/api/json.hpp"
#include "plumage_webapi/api/xml.hpp"
#include "plumage_webapi/api/oauth.hpp"

extern "C" plumage::PluginHolder* createPlumageWebApiPlugin() {
    PlumageWebApi* pif = new PlumageWebApi();
    plumage::PluginHolder* holder = new plumage::PluginHolder(pif);
    return holder;
}

void PlumageWebApi::init() {
    methodList_["createHandle"] = &PlumageWebApi::createHandle;
    methodList_["deleteHandle"] = &PlumageWebApi::deleteHandle;
    methodList_["listUpFileOnFtp"] = &PlumageWebApi::listUpFileOnFtp;
    methodList_["downloadFileOnFtp_wait"] = &PlumageWebApi::downloadFileOnFtp_wait;
    methodList_["createDirectoryOnFtp"] = &PlumageWebApi::createDirectoryOnFtp;
    methodList_["uploadFileOnFtp_wait"] = &PlumageWebApi::uploadFileOnFtp_wait;
    methodList_["getOnHttp"] = &PlumageWebApi::getOnHttp;
    methodList_["postOnHttp"] = &PlumageWebApi::postOnHttp;
    methodList_["encodeToPercentEncoding"] = &PlumageWebApi::encodeToPercentEncoding;
    methodList_["parseJsonData"] = &PlumageWebApi::parseJsonData;
    methodList_["encodeToJsonData"] = &PlumageWebApi::encodeToJsonData;
    methodList_["parseXmlData"] = &PlumageWebApi::parseXmlData;
    methodList_["encodeToXmlData"] = &PlumageWebApi::encodeToXmlData;
    methodList_["encodeToBase64"] = &PlumageWebApi::encodeToBase64;
    methodList_["decodeFromBase64"] = &PlumageWebApi::decodeFromBase64;
    methodList_["createOAuthHandle"] = &PlumageWebApi::createOAuthHandle;
    methodList_["updateOAuthHandle"] = &PlumageWebApi::updateOAuthHandle;
    methodList_["deleteOAuthHandle"] = &PlumageWebApi::deleteOAuthHandle;
    methodList_["getRequestTokenOnOAuth"] = &PlumageWebApi::getRequestTokenOnOAuth;
    methodList_["getAuthorizeUrlOnOAuth"] = &PlumageWebApi::getAuthorizeUrlOnOAuth;
    methodList_["getAccessTokenOnOAuth"] = &PlumageWebApi::getAccessTokenOnOAuth;
    //methodList_["getAccessTokenByXAuthOnOAuth"] = &PlumageWebApi::getAccessTokenByXAuthOnOAuth;
    methodList_["postOnOAuth"] = &PlumageWebApi::postOnOAuth;
    methodList_["getOnOAuth"] = &PlumageWebApi::getOnOAuth;
}

boost::any PlumageWebApi::createHandle(boost::any& parameter) {
    CURL* handle = curl_easy_init();
    CurlData* data = new CurlData(handle);
    curlHandles_.insert(std::make_pair(handle, data));
    return handle;
}

boost::any PlumageWebApi::deleteHandle(boost::any& parameter) {
    if(parameter.type() != typeid(CURL*)) {
        throw std::logic_error("PlumageWebApi::deleteHandle : parameter invalid.");
    }
    CURL* handle = boost::any_cast<CURL*>(parameter);
    if(curlHandles_.find(handle) == curlHandles_.end()) {
        throw std::logic_error("PlumageWebApi::deleteHandle : Handle is not valid.");
    }
    curl_easy_cleanup(handle);
    curlHandles_.erase(handle);
    return nullptr;
}

boost::any PlumageWebApi::listUpFileOnFtp(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<CURL*, const char*, bool, std::ostream*>)) {
        throw std::logic_error("PlumageWebApi::listUpFileOnFtp : parameter invalid.");
    }
    std::tuple<CURL*, std::string, bool, std::ostream*> p = boost::any_cast<std::tuple<CURL*, const char*, bool, std::ostream*>>(parameter);
    CURL* handle = std::get<0>(p); 
    std::string url = std::get<1>(p);
    bool option = std::get<2>(p); 
    std::ostream* os = std::get<3>(p); 

    if(curlHandles_.find(handle) == curlHandles_.end()) {
        throw std::logic_error("PlumageWebApi::listUpFileOnFtp : Handle is not valid.");
    }

    FtpApi api;
    api.listUpFile(curlHandles_[handle], url, option, *os);
    return nullptr;
}

boost::any PlumageWebApi::downloadFileOnFtp_wait(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<CURL*, const char*, std::ostream*>)) {
        throw std::logic_error("PlumageWebApi::downloadFileOnFtp_wait : parameter invalid.");
    }
    std::tuple<CURL*, std::string, std::ostream*> p = boost::any_cast<std::tuple<CURL*, const char*, std::ostream*>>(parameter);
    CURL* handle = std::get<0>(p); 
    std::string url = std::get<1>(p);
    std::ostream* os = std::get<2>(p); 

    if(curlHandles_.find(handle) == curlHandles_.end()) {
        throw std::logic_error("PlumageWebApi::downloadFileOnFtp_wait : Handle is not valid.");
    }

    FtpApi api;
    api.downloadFile(curlHandles_[handle], url, *os);
    return nullptr;
}

boost::any PlumageWebApi::createDirectoryOnFtp(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<CURL*, const char*, bool>)) {
        throw std::logic_error("PlumageWebApi::createDirectoryOnFtp : parameter invalid.");
    }
    std::tuple<CURL*, std::string, bool> p = boost::any_cast<std::tuple<CURL*, const char*, bool>>(parameter);
    CURL* handle = std::get<0>(p); 
    std::string url = std::get<1>(p);
    bool recursive = std::get<2>(p);

    if(curlHandles_.find(handle) == curlHandles_.end()) {
        throw std::logic_error("PlumageWebApi::createDirectoryOnFtp : Handle is not valid.");
    }

    FtpApi api;
    api.createDirectory(curlHandles_[handle], url, recursive);
    return nullptr;
}

boost::any PlumageWebApi::uploadFileOnFtp_wait(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<CURL*, const char*, const std::istream*>)) {
        throw std::logic_error("PlumageWebApi::uploadFileOnFtp_wait : parameter invalid.");
    }
    std::tuple<CURL*, std::string, const std::istream*> p = boost::any_cast<std::tuple<CURL*, const char*, const std::istream*>>(parameter);
    CURL* handle = std::get<0>(p); 
    std::string url = std::get<1>(p);
    const std::istream* is = std::get<2>(p); 

    if(curlHandles_.find(handle) == curlHandles_.end()) {
        throw std::logic_error("PlumageWebApi::uploadFileOnFtp_wait : Handle is not valid.");
    }

    FtpApi api;
    api.uploadFile(curlHandles_[handle], url, *is);
    return nullptr;
}
boost::any PlumageWebApi::getOnHttp(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<CURL*, const char*, std::ostream*>)) {
        throw std::logic_error("PlumageWebApi::getOnHttp : parameter invalid.");
    }
    std::tuple<CURL*, std::string, std::ostream*> p = boost::any_cast<std::tuple<CURL*, const char*, std::ostream*>>(parameter);
    CURL* handle = std::get<0>(p); 
    std::string url = std::get<1>(p);
    std::ostream* os = std::get<2>(p);

    if(curlHandles_.find(handle) == curlHandles_.end()) {
        throw std::logic_error("PlumageWebApi::getOnHttp : Handle is not valid.");
    }

    HttpApi api;
    api.get(curlHandles_[handle], url, os);
    return nullptr;
}
boost::any PlumageWebApi::postOnHttp(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<CURL*, const char*, std::ostream*>)) {
        throw std::logic_error("PlumageWebApi::postOnHttp : parameter invalid.");
    }
    std::tuple<CURL*, std::string, std::string, std::ostream*> p = boost::any_cast<std::tuple<CURL*, const char*, const char*, std::ostream*>>(parameter);
    CURL* handle = std::get<0>(p); 
    std::string url = std::get<1>(p);
    std::string data = std::get<2>(p);
    std::ostream* os = std::get<3>(p); 

    if(curlHandles_.find(handle) == curlHandles_.end()) {
        throw std::logic_error("PlumageWebApi::postOnHttp : Handle is not valid.");
    }

    HttpApi api;
    api.setPostData(curlHandles_[handle], data);
    api.post(curlHandles_[handle], url, os);
    return nullptr;
}

boost::any PlumageWebApi::encodeToPercentEncoding(boost::any& parameter) {
    if(parameter.type() != typeid(const char*)) {
        throw std::logic_error("PlumageWebApi::encodeToPercentEncoding : parameter invalid.");
    }
    const char* p = boost::any_cast<const char*>(parameter);
    std::string data(p);

    HttpApi api;
    return std::move(api.encodeToPercentEncoding(std::move(data)));
}


boost::any PlumageWebApi::parseJsonData(boost::any& parameter) {
    if(parameter.type() != typeid(std::istream*)) {
        throw std::logic_error("PlumageWebApi::parseJsonData : parameter invalid.");
    }
    std::istream* data = boost::any_cast<std::istream*>(parameter);

    picojson::value* out = new picojson::value();
    JsonApi api;
    std::string err = api.parse(*data, *out);
    if(!err.empty()) {
        delete out;
        throw std::logic_error(err.c_str());
    }
    return out;
}

boost::any PlumageWebApi::encodeToJsonData(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<const picojson::value&, std::ostream*>)) {
        throw std::logic_error("PlumageWebApi::encodeToJsonData : parameter invalid.");
    }
    std::tuple<const picojson::value&, std::ostream*> p = boost::any_cast<std::tuple<const picojson::value&, std::ostream*>>(parameter);
    const picojson::value& data = std::get<0>(p);
    std::ostream* out = std::get<1>(p);

    JsonApi api;
    api.encode(data, *out);
    return nullptr;
}

boost::any PlumageWebApi::parseXmlData(boost::any& parameter) {
    if(parameter.type() != typeid(std::istream*)) {
        throw std::logic_error("PlumageWebApi::parseXmlData : parameter invalid.");
    }
    std::istream* data = boost::any_cast<std::istream*>(parameter);

    XmlApi api;
    namespace PTree = boost::property_tree;
    PTree::ptree* pt = new PTree::ptree();
    
    try {
        api.parse(*data, *pt);
    } catch (boost::property_tree::ptree_error& e) {
        delete pt;
        throw std::logic_error(e.what());
    }
    return pt;
}

boost::any PlumageWebApi::encodeToXmlData(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<const boost::property_tree::ptree&, std::ostream*>)) {
        throw std::logic_error("PlumageWebApi::encodeToXmlData : parameter invalid.");
    }
    std::tuple<const boost::property_tree::ptree&, std::ostream*> p = boost::any_cast<std::tuple<const boost::property_tree::ptree&, std::ostream*>>(parameter);
    const boost::property_tree::ptree& data = std::get<0>(p);
    std::ostream* out = std::get<1>(p);

    XmlApi api;
    api.encode(data, *out);
    return nullptr;
}
boost::any PlumageWebApi::encodeToBase64(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<std::istream*, std::ostream*>)) {
        throw std::logic_error("PlumageWebApi::encodeToBase64 : parameter invalid.");
    }
    std::tuple<std::istream*, std::ostream*> p = boost::any_cast<std::tuple<std::istream*, std::ostream*>>(parameter);
    std::istream* data = std::get<0>(p);
    std::ostream* out = std::get<1>(p);
    if((void*)data == (void*)out) {
        throw std::logic_error("PlumageWebApi::encodeToBase64 : parameter invalid.");
    }

    XmlApi api;
    api.encodeToBase64(*data, *out);
    return nullptr;
}
boost::any PlumageWebApi::decodeFromBase64(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<std::istream*, std::ostream*>)) {
        throw std::logic_error("PlumageWebApi::decodeFromBase64 : parameter invalid.");
    }
    std::tuple<std::istream*, std::ostream*> p = boost::any_cast<std::tuple<std::istream*, std::ostream*>>(parameter);
    std::istream* data = std::get<0>(p);
    std::ostream* out = std::get<1>(p);
    if((void*)data == (void*)out) {
        throw std::logic_error("PlumageWebApi::decodeFromBase64 : parameter invalid.");
    }

    XmlApi api;
    api.decodeFromBase64(*data, *out);
    return nullptr;
}
boost::any PlumageWebApi::createOAuthHandle(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<const char*, const char*, const char*, const char*>)) {
        throw std::logic_error("PlumageWebApi::createOAuthHandle : parameter invalid.");
    }

    std::tuple<const char*, const char*, const char*, const char*> p = boost::any_cast<std::tuple<const char*, const char*, const char*, const char*>>(parameter);
    std::string consumerKey = std::get<0>(p);
    std::string consumerSecret = std::get<1>(p);
    std::string accessKey= std::get<2>(p);
    std::string accessSecret= std::get<3>(p);

    OAuthApi::OAuthHandle* handle = new OAuthApi::OAuthHandle();
    handle->consumerKey_ = consumerKey;
    handle->consumerSecret_ = consumerSecret;
    handle->accessToken_ = accessKey;
    handle->accessTokenSecret_ = accessSecret;
    oauthHandles_.insert(handle);
    boost::any ret((void*)handle);
    return ret;
}
boost::any PlumageWebApi::updateOAuthHandle(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<void*, const char*, const char*, const char*, const char*>)) {
        throw std::logic_error("PlumageWebApi::createOAuthHandle : parameter invalid.");
    }

    std::tuple<void*, const char*, const char*, const char*, const char*> p =
        boost::any_cast<std::tuple<void*, const char*, const char*, const char*, const char*>>(parameter);

    void* handle = std::get<0>(p);
    OAuthApi::OAuthHandle* oauth = (OAuthApi::OAuthHandle*)(handle);

    if(oauthHandles_.count(oauth) == 0) {
        throw std::logic_error("It specified OAuthHandle is not registerd");
    }
    std::string consumerKey = std::get<1>(p);
    std::string consumerSecret = std::get<2>(p);
    std::string accessKey= std::get<3>(p);
    std::string accessSecret= std::get<4>(p);

    if(!consumerKey.empty()) {
        oauth->consumerKey_ = consumerKey;
#ifdef DEBUG
        std::cout << "consumerKey = " << oauth->consumerKey_;
#endif
    }
    if(!consumerSecret.empty()) {
        oauth->consumerSecret_ = consumerSecret;
#ifdef DEBUG
        std::cout << "consumerSecret = " << oauth->consumerSecret_;
#endif
    }
    if(!accessKey.empty()) {
        oauth->accessToken_ = accessKey;
#ifdef DEBUG
        std::cout << "accessToken = " << oauth->accessToken_;
#endif
    }
    if(!accessSecret.empty()) {
        oauth->accessTokenSecret_ = accessSecret;
#ifdef DEBUG
        std::cout << "accessTokenSecret = " << oauth->accessTokenSecret_;
#endif
    }
    return nullptr;
}
boost::any PlumageWebApi::deleteOAuthHandle(boost::any& parameter) {
    if(parameter.type() != typeid(void*)) {
        throw std::logic_error("PlumageWebApi::deleteOAuthHandle : parameter invalid.");
    }
    void* handle = boost::any_cast<void*>(parameter);
    OAuthApi::OAuthHandle* oauth = (OAuthApi::OAuthHandle*)(handle);
    if(oauthHandles_.find(oauth) == oauthHandles_.end()) {
        throw std::logic_error("PlumageWebApi::deleteOAuthHandle : Handle is not valid.");
    }

    oauthHandles_.erase(oauth);
    delete oauth;
    return nullptr;
}
boost::any PlumageWebApi::getRequestTokenOnOAuth(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<CURL*, void*, const char*, const char*, const char*>)) {
        throw std::logic_error("PlumageWebApi::getRequestTokenOnOAuth : parameter invalid.");
    }
    std::tuple<CURL*, void*, const char*> p = boost::any_cast<std::tuple<CURL*, void*, const char*>>(parameter);
    CURL* handle = std::get<0>(p);
    void* tmp = std::get<1>(p);
    OAuthApi::OAuthHandle* oauth = (OAuthApi::OAuthHandle*)(tmp);

    if(curlHandles_.find(handle) == curlHandles_.end()) {
        throw std::logic_error("PlumageWebApi::getRequestTokenOnOAuth  : Handle is not valid.");
    }
    if(oauthHandles_.find(oauth) == oauthHandles_.end()) {
        throw std::logic_error("PlumageWebApi::getRequestTokenOnOAuth  : OAuthHandle is not valid.");
    }

    std::string url = std::get<2>(p);

    OAuthApi api;
    return std::move(api.getRequestToken(curlHandles_[handle], oauth, url, 1));
}
boost::any PlumageWebApi::getAuthorizeUrlOnOAuth(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<CURL*, void*, const char*, const char*>)) {
        throw std::logic_error("PlumageWebApi::getAuthorizeUrlOnOAuth : parameter invalid.");
    }
    std::tuple<CURL*, void*, const char*, const char*> p = boost::any_cast<std::tuple<CURL*, void*, const char*, const char*>>(parameter);
    CURL* handle = std::get<0>(p);
    void* tmp = std::get<1>(p);
    OAuthApi::OAuthHandle* oauth = (OAuthApi::OAuthHandle*)(tmp);

    std::string authUrl = std::get<2>(p);
    std::string requestUrl = std::get<3>(p);

    if(curlHandles_.find(handle) == curlHandles_.end()) {
        throw std::logic_error("PlumageWebApi::getAuthorizeUrlOnOAuth  : Handle is not valid.");
    }
    if(oauthHandles_.find(oauth) == oauthHandles_.end()) {
        throw std::logic_error("PlumageWebApi::getAuthorizeUrlOnOAuth  : OAuthHandle is not valid.");
    }

    OAuthApi api;
    std::string ret = api.getAuthorizeUrl(curlHandles_[handle], oauth, authUrl, requestUrl, 1);

    return ret;
}
boost::any PlumageWebApi::getAccessTokenOnOAuth(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<CURL*, void*, const char*, const char*>)) {
        throw std::logic_error("PlumageWebApi::getAccessTokenOnOAuth : parameter invalid.");
    }
    std::tuple<CURL*, void*, const char*, const char*> p = boost::any_cast<std::tuple<CURL*, void*, const char*, const char*>>(parameter);
    CURL* handle = std::get<0>(p);
    void* tmp = std::get<1>(p);
    OAuthApi::OAuthHandle* oauth = (OAuthApi::OAuthHandle*)(tmp);
    std::string accessUrl = std::get<2>(p);
    std::string oauth_verify = std::get<3>(p);

    OAuthApi api;
    return api.getAccessToken(curlHandles_[handle], oauth, accessUrl, oauth_verify, 1);
}
//boost::any PlumageWebApi::getAccessTokenByXAuthOnOAuth(boost::any& parameter) {
//    if(parameter.type() != typeid(std::tuple<CURL*, void*, const char*, const char*, const char*>)) {
//        throw std::logic_error("PlumageWebApi::getAccessTokenByXAuthOnOAuth : parameter invalid.");
//    }
//
//    std::tuple<CURL*, void*, const char*, const char*, const char*> p =
//        boost::any_cast<std::tuple<CURL*, void*, const char*, const char*, const char*>>(parameter);
//
//    CURL* handle = std::get<0>(p);
//    void* tmp = std::get<1>(p);
//    OAuthApi::OAuthHandle* oauth = (OAuthApi::OAuthHandle*)(tmp);
//    std::string accessUrl = std::get<2>(p);
//    std::string userId = std::get<3>(p);
//    std::string passwd = std::get<4>(p);
//
//    OAuthApi api;
//    return api.getAccessTokenByXAuth(handle, oauth, accessUrl, 1, userId, passwd);
//}
boost::any PlumageWebApi::getOnOAuth(boost::any& parameter) {
    if(parameter.type() == typeid(std::tuple<CURL*, void*, const char*, const char*, std::ostream*>)) {
        std::tuple<CURL*, void*, const char*, const char*, std::ostream*> p =
            boost::any_cast<std::tuple<CURL*, void*, const char*, const char*, std::ostream*>>(parameter);

        CURL* handle = std::get<0>(p);
        void* tmp = std::get<1>(p);
        OAuthApi::OAuthHandle* oauth = (OAuthApi::OAuthHandle*)(tmp);
        std::string getUrl = std::get<2>(p);
        std::string query = std::get<3>(p);
        std::ostream* os = std::get<4>(p);

        OAuthApi api;
        api.get(curlHandles_[handle], oauth, getUrl, query, 1, os);
    } else if(parameter.type() == typeid(std::tuple<CURL*, void*, const char*, const char*, ReceiveDataListner*>)) {
        std::tuple<CURL*, void*, const char*, const char*, ReceiveDataListner*> p =
            boost::any_cast<std::tuple<CURL*, void*, const char*, const char*, ReceiveDataListner*>>(parameter);

        CURL* handle = std::get<0>(p);
        void* tmp = std::get<1>(p);
        OAuthApi::OAuthHandle* oauth = (OAuthApi::OAuthHandle*)(tmp);
        std::string getUrl = std::get<2>(p);
        std::string query = std::get<3>(p);
        ReceiveDataListner* listner = std::get<4>(p);

        OAuthApi api;
        api.get(curlHandles_[handle], oauth, getUrl, query, 1, listner);

    } else {
        throw std::logic_error("PlumageWebApi::getOnOAuth : parameter invalid.");
    }
    return nullptr;
}
boost::any PlumageWebApi::postOnOAuth(boost::any& parameter) {
    if(parameter.type() != typeid(std::tuple<CURL*, void*, const char*, const char*, std::ostream*>)) {
        throw std::logic_error("PlumageWebApi::postOnOAuth : parameter invalid.");
    }
    std::tuple<CURL*, void*, const char*, const char*, std::ostream*> p =
        boost::any_cast<std::tuple<CURL*, void*, const char*, const char*, std::ostream*>>(parameter);

    CURL* handle = std::get<0>(p);
    void* tmp = std::get<1>(p);
    OAuthApi::OAuthHandle* oauth = (OAuthApi::OAuthHandle*)(tmp);
    std::string postUrl = std::get<2>(p);
    std::string data = std::get<3>(p);
    std::ostream* os = std::get<4>(p);

    OAuthApi api;
    api.post(curlHandles_[handle], oauth, postUrl, data, 1, os);
    return nullptr;
}

bool PlumageWebApi::isCompatible(int interfaceVersion) const {
    if(getInterfaceVersion() == interfaceVersion) {
        return true;
    }
    return false;
}

bool PlumageWebApi::isCallable(const std::string& methodName) const {
    if(methodList_.count(methodName) == 0) {
        return false;
    }
    return true;
}

boost::any PlumageWebApi::doCall(std::string methodName, boost::any& parameter) throw (std::exception) {
    Method method = methodList_.at(methodName);
    return (this->*method)(parameter);
}

size_t writeOutputStream(char* ptr, size_t size, size_t nmemb, void* stream) {
    std::ostream* os = static_cast<std::ostream*>(stream);
    int realsize = size * nmemb;
    os->write(ptr, realsize);
    return realsize;
}
size_t notifyUserCallback(char* ptr, size_t size, size_t nmemb, void* func) {
    std::function<size_t(char*,size_t)>* userCallback = static_cast<std::function<size_t(char*,size_t)>*>(func);
    int realsize = size * nmemb;
    return (*userCallback)(ptr, realsize);
}
size_t readInputStream(char* ptr, size_t size, size_t nmemb, std::istream* stream) {
    int realsize = size * nmemb;
    stream->read(ptr, realsize);
    return realsize;
}

int progress_func(void* ptr, double TotalToDownload, double NowDownloaded, 
                    double TotalToUpload, double NowUploaded)
{
    printf("[Total %f :Now %f", TotalToDownload, NowDownloaded);
    printf(" ]\r");
    fflush(stdout);
    return 0;
}

void FtpApi::listUpFile(CurlData* curlData, const std::string& url, bool nameOnly, std::ostream& os) const {
    std::string tmp(url);
    if(url.at(url.size()-1) != '/') {
        tmp += "/";
    }
    curl_easy_setopt(curlData->curl, CURLOPT_URL, tmp.c_str());
    curlData->setWriteTarget(&os);
    //curl_easy_setopt(curlData->curl, CURLOPT_WRITEFUNCTION, &writeOutputStream);
    //curl_easy_setopt(curlData->curl, CURLOPT_WRITEDATA, &os);
    if(nameOnly) {
        curl_easy_setopt(curlData->curl, CURLOPT_DIRLISTONLY, 1);
    }

    CURLcode res;
    res = curl_easy_perform(curlData->curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

}

void FtpApi::downloadFile(CurlData* curlData, const std::string& url, std::ostream& os) const {
    std::string tmp(url);
    if(url.at(url.size()-1) == '/') {
        throw std::logic_error("URL is not valid. It is not specify a direcotry naem.");
    }
    curl_easy_setopt(curlData->curl, CURLOPT_URL, tmp.c_str());
    curlData->setWriteTarget(&os);
    //curl_easy_setopt(curlData->curl, CURLOPT_WRITEFUNCTION, &writeOutputStream);
    //curl_easy_setopt(curlData->curl, CURLOPT_WRITEDATA, &os);
    curl_easy_setopt(curlData->curl, CURLOPT_NOPROGRESS, 0);
    curl_easy_setopt(curlData->curl, CURLOPT_PROGRESSFUNCTION, progress_func);

    CURLcode res;
    res = curl_easy_perform(curlData->curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
    std::cout << std::endl;
#endif

}

void FtpApi::createDirectory(CurlData* curlData, const std::string& url, bool recursive) const {
    std::string tmp(url);
    if(url.at(url.size()-1) != '/') {
        throw std::logic_error("URL is not valid. It can specify a direcotry name only.");
    }
    curl_easy_setopt(curlData->curl, CURLOPT_URL, tmp.c_str());
    curl_easy_setopt(curlData->curl, CURLOPT_FTP_CREATE_MISSING_DIRS, CURLFTP_CREATE_DIR_RETRY);

    CURLcode res;
    res = curl_easy_perform(curlData->curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

}
void FtpApi::uploadFile(CurlData* curlData, const std::string& url, const std::istream& is) const {
    std::string tmp(url);
    if(url.at(url.size()-1) == '/') {
        throw std::logic_error("URL is not valid. It can not specify a direcotry name in URL.");
    }
    curl_easy_setopt(curlData->curl, CURLOPT_URL, tmp.c_str());
    curl_easy_setopt(curlData->curl, CURLOPT_READFUNCTION, &readInputStream);
    curl_easy_setopt(curlData->curl, CURLOPT_READDATA, &is);

    CURLcode res;
    res = curl_easy_perform(curlData->curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

}

void HttpApi::get(CurlData* curlData, const std::string& url) const {
    curl_easy_setopt(curlData->curl, CURLOPT_URL, url.c_str());
    //curlData->setWriteTarget(&os);
    //curl_easy_setopt(curlData->curl, CURLOPT_WRITEFUNCTION, &writeOutputStream);
    //curl_easy_setopt(curlData->curl, CURLOPT_WRITEDATA, &os);
    curl_easy_setopt(curlData->curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

    curl_easy_setopt(curlData->curl, CURLOPT_HTTPGET, 1);
    CURLcode res;
    res = curl_easy_perform(curlData->curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

}

void HttpApi::post(CurlData* curlData, const std::string& url) const {
    curl_easy_setopt(curlData->curl, CURLOPT_URL, url.c_str());
    //curlData->setWriteTarget(&os);
    //curl_easy_setopt(curlData->curl, CURLOPT_WRITEFUNCTION, &writeOutputStream);
    //curl_easy_setopt(curlData->curl, CURLOPT_WRITEDATA, &os);
    curl_easy_setopt(curlData->curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

    CURLcode res;
    res = curl_easy_perform(curlData->curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

}

void HttpApi::setPostData(CurlData* curlData, const std::string& data) const {
    curl_easy_setopt(curlData->curl, CURLOPT_POSTFIELDS, data.c_str());
}

std::string HttpApi::encodeToPercentEncoding(std::string data) const {
    std::string encoded;
    static const std::string excludeChar = "-._~";
    std::ostringstream ss;
    ss << std::hex << std::uppercase;
    for( unsigned char c : data) {
        if(std::isalnum(c) || excludeChar.find(c) != std::string::npos) {
            encoded.push_back(c);
        } else {
            ss << "%" << (int)c;
            encoded.append(ss.str());
            ss.str("");
        }
    }
    return encoded;
}

std::map<std::string, std::string> HttpApi::parseQueryData(const std::string& data) const {
#ifdef DEBUG
    std::cout << data << std::endl;
#endif
    std::map<std::string, std::string> keyValue;
    size_t pos = 0;
    while(pos != std::string::npos) {
        size_t eqPos = data.find('=', pos);
        if(eqPos != std::string::npos) {
            std::string key = data.substr(pos, (eqPos-pos));
            pos = eqPos;
            size_t andPos = data.find('&', pos);
            if(andPos != std::string::npos) {
                std::string value = data.substr(eqPos+1, (andPos-1-eqPos));
#ifdef DEBUG
                std::cout << key << " : " << value << std::endl;
#endif
                keyValue.insert(std::make_pair(key, value));
                pos = andPos;
            } else {
                std::string value = data.substr(eqPos+1, (andPos - eqPos));
#ifdef DEBUG
                std::cout << key << " : " << value << std::endl;
#endif
                keyValue.insert(std::make_pair(key, value));
                keyValue.insert(std::make_pair(key, value));
                pos = std::string::npos;
            }
            if(pos != std::string::npos) {
                if(pos+1 <= data.length()) {
                    pos += 1;
                }
            }
        } else {
            pos = std::string::npos;
        }
    }
    return keyValue;
}

std::string JsonApi::parse(std::istream& in_data, picojson::value& out) const {
    return std::move(picojson::parse(out, in_data));
}
void JsonApi::encode(const picojson::value& in_data, std::ostream& out) const {
    out << in_data;
}

void XmlApi::parse(std::istream& in_data, boost::property_tree::ptree& pt) const {
    boost::property_tree::read_xml(in_data, pt);
}

void XmlApi::encode(const boost::property_tree::ptree& data, std::ostream& out) const {
    boost::property_tree::write_xml(out, data);
}

void XmlApi::encodeToBase64(std::istream& data, std::ostream& out) const {
    bool end=data.eof();
    char i[4];
    unsigned char buf1, buf2, buf3;
    while(!end) {
        buf1 = data.get();
        if(data.eof()) {
            end = true;
            continue;
        }
        buf2 = data.get();
        if(data.eof()) {
            i[0] = getBase64Char((0x3F & (buf1>>2)));
            i[1] = getBase64Char(0x3F & (buf1 << 4));
            i[2] = '=';
            i[3] = '=';
            out.write(i, 4);
            end = true;
            continue;
        }
        buf3 = data.get();
        if(data.eof()) {
            i[0] = getBase64Char((0x3F & (buf1>>2)));
            i[1] = getBase64Char((0x3F & ((buf1<<4)+(buf2>>4))));
            i[2] = getBase64Char((0x3F & (buf2 << 2)));
            i[3] = '=';
            out.write(i, 4);
            end = true;
            continue;
        }
        i[0] = getBase64Char((0x3F & (buf1>>2)));
        i[1] = getBase64Char((0x3F & ((buf1<<4)+(buf2>>4))));
        i[2] = getBase64Char((0x3F & ((buf2 << 2)+(buf3>>6))));
        i[3] = getBase64Char(0x3F & buf3);
        out.write(i, 4);
    }
}

void XmlApi::decodeFromBase64(std::istream& data, std::ostream& out) const {
    bool end=data.eof();
    char i[3];
    unsigned char buf1, buf2, buf3, buf4;
    while(!end) {
        buf1 = data.get();
        buf2 = data.get();
        buf3 = data.get();
        buf4 = data.get();
        buf1 = getDecodedBit(buf1);
        buf2 = getDecodedBit(buf2);
        buf3 = getDecodedBit(buf3);
        buf4 = getDecodedBit(buf4);
        if(buf3 == 0xFF) {
            i[0] = (buf1<<2) + (0x03 & (buf2 >> 4));
            out.write(i, 1);
            end = true;
            continue;
        } else if(buf4 == 0xFF) {
            i[0] = (buf1<<2) + (0x03 & (buf2 >> 4));
            i[1] = (buf2<<4) + (0x0F & (buf3 >> 2));
            out.write(i, 2);
            end = true;
            continue;
        }
        i[0] = (buf1<<2) + (0x03 & (buf2 >> 4));
        i[1] = (buf2<<4) + (0x0F & (buf3 >> 2));
        i[2] = (buf3<<6) + buf4;
        out.write(i, 3);
    }
}

unsigned char XmlApi::getBase64Char(int num) const {
    static char base64Set[] = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
        '0','1','2','3','4','5','6','7','8','9','+','/'
    };

    return base64Set[num];
}

unsigned char XmlApi::getDecodedBit(char base64char) const {
    if(base64char == '=') {
        return 0xFF;
    }
    if(base64char == '+') {
        return 62;
    }
    if(base64char == '/') {
        return 63;
    }
    if(base64char <= 0x39) {
        return (base64char+4);
    }
    if(base64char <= 0x5A) {
        return (base64char-0x41);
    }
    return (base64char - 0x47);
}

std::map<std::string, std::string> OAuthApi::getRequestToken(CurlData* curlData, OAuthHandle* oauth, std::string url, int type) const {
    std::ostringstream ss;
    namespace uuids = boost::uuids;
    const uuids::uuid id = uuids::random_generator()();
    ss << "oauth_consumer_key=" << oauth->consumerKey_ << "&"
       << "oauth_nonce=" << id << "&"
       << "oauth_signature_method=";

    std::string cryptoType = getEncryptTypeString(type);
    ss << cryptoType << "&";

    ss << "oauth_timestamp=" << std::time(0) << "&"
       << "oauth_version=" << "1.0";

    HttpApi api;
    std::string signatureKey = oauth->consumerSecret_ + '&';
    std::string signature = getOAuthSignature(url, ss.str(), signatureKey, type);
    ss << "&oauth_signature=" + api.encodeToPercentEncoding(signature);
    url += "?" + ss.str();
    ss.str("");

    std::ostringstream oss;
    api.get(curlData, url, (std::ostream*)&oss);

    std::map<std::string, std::string> keyValue = api.parseQueryData(std::move(oss.str()));

    if(keyValue.count("oauth_token") == 0) {
        throw std::logic_error("oauth_token is not found");
    }
    if(keyValue.count("oauth_token_secret") == 0) {
        throw std::logic_error("oauth_token_secret is not found");
    }

    oauth->requestToken_ = keyValue.at( "oauth_token" );
    oauth->requestTokenSecret_ = keyValue.at( "oauth_token_secret" );

#ifdef DEBUG
    std::cout << "RequestToken = " << oauth->requestToken_ << std::endl;
    std::cout << "RequestTokenSecret = " << oauth->requestTokenSecret_ << std::endl;
#endif

    return std::move(keyValue);
}

std::string OAuthApi::getOAuthSignature(std::string url, std::string query, std::string secret, int type, std::string reqType) const {
    std::string signatureData;
    HttpApi api;

    std::map<std::string, std::string> tokenList = tokenizeQuery(query);
    std::string sortedQuery = serializeQuery(std::move(tokenList));

    signatureData = reqType + "&";
    signatureData += api.encodeToPercentEncoding(url) + '&';
    signatureData += api.encodeToPercentEncoding(sortedQuery);

#ifdef DEBUG
    std::cout << "------------------------------------------" << std::endl;
    std::cout << signatureData << std::endl;
    std::cout << "------------------------------------------" << std::endl;
#endif

    std::string signature = getHMAC(type, secret, signatureData);

    std::stringstream is;
    is.write(signature.c_str(), signature.length());
    std::stringstream os;
    XmlApi xmlApi;
    xmlApi.encodeToBase64(is, os);
    return std::move(os.str());
}

std::string OAuthApi::getHMAC(int type, std::string key, std::string data) const {
  const EVP_MD *m;
  unsigned char* ret = nullptr;
  unsigned int retLen = 0;


  if(type == HMAC_MD5) {
      m = EVP_md5();
      ret = new unsigned char[MD5_SIZE];
  } else if(type == HMAC_SHA1) {
      m = EVP_sha1();
      ret = new unsigned char[SHA1_SIZE];
  } else if(type == HMAC_SHA2) {
      m = EVP_sha512();
      ret = new unsigned char[SHA2_SIZE];
  } else {
      throw std::logic_error("EncryptType error.");
  }

  if(m == nullptr) {
      delete[] ret;
      throw std::logic_error("encrypto algorithm error.");
  }

  if (!HMAC(m, key.c_str(), key.length(), (const unsigned char*)data.c_str(), data.length(), ret, &retLen) ) {
      delete[] ret;
      throw std::logic_error("hash error.");
  }

  std::string digest((char*)ret, retLen);
  delete[] ret;
  return digest;
}

std::map<std::string, std::string> OAuthApi::getAccessToken(CurlData* curlData, OAuthHandle* oauth, std::string url, std::string oauth_verifier, int type) const {

    HttpApi api;

    oauth->oauthVerifier_ = oauth_verifier;
    std::string data = "oauth_verifier=" + oauth_verifier;
    setOAuthHeader(curlData, oauth, REQUEST_TOKEN, url, "GET", data, HMAC_SHA1);

#ifdef DEBUG
    curl_easy_setopt(curlData->curl, CURLOPT_VERBOSE, 1);
#endif

    std::ostringstream oss;
    api.get(curlData, url, (std::ostream*)&oss);

#ifdef DEBUG
    std::cout << oss.str() << std::endl;
#endif

    std::map<std::string, std::string> keyValue = api.parseQueryData(std::move(oss.str()));

    if(keyValue.count("oauth_token") == 0) {
        throw std::logic_error("oauth_token is not found");
    }
    if(keyValue.count("oauth_token_secret") == 0) {
        throw std::logic_error("oauth_token_secret is not found");
    }

    oauth->accessToken_ = keyValue.at( "oauth_token" );
    oauth->accessTokenSecret_ = keyValue.at( "oauth_token_secret" );

#ifdef DEBUG
    std::cout << oauth->accessToken_ << " : " << oauth->accessTokenSecret_ << std::endl;
#endif

    return keyValue;
}

//std::map<std::string, std::string> OAuthApi::getAccessTokenByXAuth(CurlData* curlData, OAuthHandle* oauth, std::string url, int type,
//                                                            std::string userId, std::string passwd) const {
//
//    std::ostringstream ss;
//    namespace uuids = boost::uuids;
//    const uuids::uuid id = uuids::random_generator()();
//    ss << "oauth_consumer_key=" << oauth->consumerKey_ << "&"
//       //<< "oauth_nonce=" << id << "&"
//       << "oauth_nonce=" << "6AN2dKRzxyGhmIXUKSmp1JcB4pckM8rD3frKMTmVAo" << "&"
//       << "oauth_signature_method=";
//
//    std::string cryptoType = getEncryptTypeString(type);
//    ss << cryptoType << "&";
//
//    std::stringstream timestamp;
//    timestamp << std::time(0);
//    //ss << "oauth_timestamp=" << timestamp.str() << "&"
//    ss << "oauth_timestamp=" << "1284565601" << "&"
//       << "oauth_version=" << "1.0&"
//       << "x_auth_mode=client_auth&"
//       << "x_auth_password=" << passwd << "&"
//       << "x_auth_username=" << userId;
//
//    HttpApi api;
//    std::string signatureKey = oauth->consumerSecret_ + '&';
//    std::string signature = getOAuthSignature(url, ss.str(), signatureKey, type);
//
//#ifdef DEBUG
//    std::cout << "POST URL = " << postUrl << std::endl;
//    ss << "&oauth_signature=" + api.encodeToPercentEncoding(signature);
//    std::string url = postUrl + "?" + ss.str();
//    std::cout << "FULL URL = " << url << std::endl;
//    std::cout << "query = " << ss.str() << std::endl;
//#endif
//
//    std::stringstream tmp;
//    tmp << id;
//    setOAuthHeader(curlData->curl, oauth, tmp.str(), api.encodeToPercentEncoding(signature), type, timestamp.str(), "1.0");
//
//    std::ostringstream oss;
//    std::string data = "x_auth_username=" + userId + "&amp;x_auth_password=" + passwd + "&amp;x_auth_mode=client_auth";
//    api.setPostData(curlData->curl, data);
////#ifdef DEBUG
//    curl_easy_setopt(curlData->curl, CURLOPT_VERBOSE, 1);
////#endif
//    api.post(curlData->curl, url, oss);
//
////#ifdef DEBUG
//    std::cout << oss.str() << std::endl;
////#endif
//
//    std::map<std::string, std::string> keyValue = api.parseQueryData(std::move(oss.str()));
//
//    if(keyValue.count("oauth_token") == 0) {
//        throw std::logic_error("oauth_token is not found");
//    }
//    if(keyValue.count("oauth_token_secret") == 0) {
//        throw std::logic_error("oauth_token_secret is not found");
//    }
//
//    oauth->accessToken_ = keyValue.at( "oauth_token" );
//    oauth->accessTokenSecret_ = keyValue.at( "oauth_token_secret" );
//
////#ifdef DEBUG
//    std::cout << oauth->accessToken_ << " : " << oauth->accessTokenSecret_ << std::endl;
////#endif
//
//    return keyValue;
//}

std::string OAuthApi::getAuthorizeUrl(CurlData* curlData, OAuthHandle* oauth, std::string authUrl, std::string requestUrl, int type) const {
    if(oauth->requestToken_.empty()) {
        getRequestToken(curlData, oauth, requestUrl, type);
    }
    authUrl += "?oauth_token=" + oauth->requestToken_;
    return authUrl;
}

void OAuthApi::get(CurlData* curlData, OAuthHandle* oauth, std::string getUrl, std::string data, int type) const {
    HttpApi api;

    setOAuthHeader(curlData, oauth, ACCESS_TOKEN, getUrl, "GET", data, HMAC_SHA1);

    //HttpApi::SpaceToPlusTranslator t;
    //t(data);
    data = serializeQuery(std::move(tokenizeQuery(data)));
    std::string url = getUrl + "?" + data;

#ifdef DEBUG
    std::cout << "URL = " << getUrl << std::endl;
#endif

#ifdef DEBUG
    curl_easy_setopt(curlData->curl, CURLOPT_VERBOSE, 1);
#endif

    api.get(curlData, url);
}

void OAuthApi::post(CurlData* curlData, OAuthHandle* oauth, std::string postUrl, std::string data, int type) const {
    HttpApi api;

    setOAuthHeader(curlData, oauth, ACCESS_TOKEN, postUrl, "POST", data, HMAC_SHA1);

#ifdef DEBUG
    std::cout << "URL = " << postUrl << std::endl;
#endif

#ifdef DEBUG
    curl_easy_setopt(curlData->curl, CURLOPT_VERBOSE, 1);
#endif

    data = serializeQuery(std::move(tokenizeQuery(data)));
    api.setPostData(curlData, data);

    api.post(curlData, postUrl);
}

std::map<std::string, std::string> OAuthApi::tokenizeQuery(std::string query) const {
    std::map<std::string, std::string> ret;
    size_t cur = 0;
    size_t end = query.size();
    while( cur <= end) {
        size_t andPos = query.find('&', cur);
        if( andPos == std::string::npos) {
            std::string str = query.substr(cur);
            if(!str.empty()) {
                size_t eqPos = str.find('=');
                if(eqPos == std::string::npos || eqPos == str.size()) {
                    throw std::runtime_error("Query is illegal format");
                }
                std::string key = str.substr(0, eqPos);
                std::string val = str.substr(eqPos+1);
                ret.insert(std::make_pair(key, val));
                cur = andPos;
            } else {
                cur++;
            }
        } else {
            std::string str = query.substr(cur, (andPos-cur));
            size_t eqPos = str.find('=');
            if(eqPos == std::string::npos || eqPos == str.size()) {
                throw std::runtime_error("Query is illegal format");
            }
            std::string key = str.substr(0, eqPos);
            std::string val = str.substr(eqPos+1);
            ret.insert(std::make_pair(key, val));
            cur = andPos+1;
        }
    }
#ifdef DEBUG
    for(std::pair<std::string, std::string> tmp : ret) {
        std::cout << tmp.first << ":" << tmp.second << std::endl;
    }
#endif
    return std::move(ret);
}

std::string OAuthApi::serializeQuery(std::map<std::string, std::string> queries) const {
    std::string ret;
    bool first = true;
    HttpApi api;
    for(std::pair<std::string, std::string> tmp : queries) {
        if(!first) {
            ret += "&";
        }
        ret += api.encodeToPercentEncoding(tmp.first) + "=" + api.encodeToPercentEncoding(tmp.second);
        first = false;
    }
    return std::move(ret);
}

void OAuthApi::setOAuthHeader(CurlData* curlData, OAuthHandle* oauth, OAuthApi::UseTokenType useTokenType,
                              std::string url, std::string method, std::string data, OAuthApi::EncryptType encryptType) const {

    HttpApi api;
    std::stringstream ss;
    namespace uuids = boost::uuids;
    const uuids::uuid id = uuids::random_generator()();
    std::stringstream nonce;
    nonce << id;
    ss << "oauth_consumer_key=" << oauth->consumerKey_ << "&"
       << "oauth_nonce=" << nonce.str() << "&"
       << "oauth_signature_method=";

    std::string encryptStr = getEncryptTypeString(encryptType);
    ss << encryptStr << "&";

    std::stringstream timestamp;
    timestamp << std::time(0);
    ss << "oauth_timestamp=" << timestamp.str() << "&"
       << "oauth_version=" << "1.0&";
    if(!data.empty()) {
        ss << data << "&";
    }

    std::string signatureKey = oauth->consumerSecret_ + '&';
    if(useTokenType == REQUEST_TOKEN) {
        signatureKey += oauth->requestTokenSecret_;
        ss << "oauth_token=" << oauth->requestToken_;
    } else if (useTokenType == ACCESS_TOKEN) {
        signatureKey += oauth->accessTokenSecret_;
        ss << "oauth_token=" << oauth->accessToken_;
    }

    std::string encodedSignaure = api.encodeToPercentEncoding(getOAuthSignature(url, ss.str(), signatureKey, encryptType, method.c_str()));

    struct curl_slist *slist=nullptr;
    std::stringstream authStr;

    authStr <<  "Authorization: OAuth";
    authStr << " oauth_consumer_key=\"" << oauth->consumerKey_.c_str() << "\"";
    authStr << ", oauth_nonce=\"" << nonce.str() << "\"";
    authStr << ", oauth_signature=\"" << encodedSignaure << "\"";
    authStr << ", oauth_signature_method=\"" << encryptStr << "\"";
    authStr << ", oauth_timestamp=\"" << timestamp.str() << "\"";
    if(useTokenType == REQUEST_TOKEN) {
        if(data.find("oauth_verifier=") == std::string::npos) {
            throw std::logic_error("oath_verifier don't set");
        }
        authStr << ", oauth_token=\"" << oauth->requestToken_ << "\"";
        authStr << ", oauth_verifier=\"" << data.substr(15) << "\"";
    } else if (useTokenType == ACCESS_TOKEN) {
        authStr << ", oauth_token=\"" << oauth->accessToken_ << "\"";
    }
    authStr << ", oauth_version=\"1.0\"";
    slist = curl_slist_append(slist, authStr.str().c_str());

#ifdef DEBUG
    std::cout << "Authorization Header : " << authStr.str() << std::endl;
#endif

    curl_easy_setopt(curlData->curl, CURLOPT_HTTPHEADER, slist);
}

std::string OAuthApi::getEncryptTypeString(int type) const {
    if(type == HMAC_MD5) {
        return "HMAC-MD5";
    } else if(type == HMAC_SHA1) {
        return "HMAC-SHA1";
    } else if(type == HMAC_SHA2) {
        return "HMAC-SHA2";
    } else {
        throw std::logic_error("EncryptType error.");
    }
}


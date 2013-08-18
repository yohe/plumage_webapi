
#include <tuple>
#include <iostream>
#include <ostream>
#include <fstream>

#include "plumage_webapi/plumage_web_api.hpp"

void PlumageWebApi::init() {
    methodList_["createHandle"] = &PlumageWebApi::createHandle;
    methodList_["deleteHandle"] = &PlumageWebApi::deleteHandle;
    methodList_["listUpFileOnFtp"] = &PlumageWebApi::listUpFileOnFtp;
    methodList_["downloadFileOnFtp_wait"] = &PlumageWebApi::downloadFileOnFtp_wait;
    methodList_["createDirectoryOnFtp"] = &PlumageWebApi::createDirectoryOnFtp;
    methodList_["uploadFileOnFtp_wait"] = &PlumageWebApi::uploadFileOnFtp_wait;
    methodList_["getOnHttp"] = &PlumageWebApi::getOnHttp;
    methodList_["postOnHttp"] = &PlumageWebApi::postOnHttp;
    methodList_["setBasicAuth"] = &PlumageWebApi::setBasicAuth;
    methodList_["parseJsonData"] = &PlumageWebApi::parseJsonData;
}

void* PlumageWebApi::createHandle(boost::any& parameter) {
    CURL* handle = curl_easy_init();
    curlHandles_.insert(handle);
    return handle;
}

void* PlumageWebApi::deleteHandle(boost::any& parameter) {
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

void* PlumageWebApi::listUpFileOnFtp(boost::any& parameter) {
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
    api.listUpFile(handle, url, option, *os);
    return nullptr;
}

void* PlumageWebApi::downloadFileOnFtp_wait(boost::any& parameter) {
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
    api.downloadFile(handle, url, *os);
    return nullptr;
}

void* PlumageWebApi::createDirectoryOnFtp(boost::any& parameter) {
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
    api.createDirectory(handle, url, recursive);
    return nullptr;
    return nullptr;
}

void* PlumageWebApi::uploadFileOnFtp_wait(boost::any& parameter) {
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
    api.uploadFile(handle, url, *is);
    return nullptr;
}
void* PlumageWebApi::getOnHttp(boost::any& parameter) {
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
    api.get(handle, url, *os);
    return nullptr;
}
void* PlumageWebApi::postOnHttp(boost::any& parameter) {
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
    api.post(handle, url, data, *os);
    return nullptr;
}

void* PlumageWebApi::setBasicAuth(boost::any& parameter) {
    return nullptr;
}

void* PlumageWebApi::parseJsonData(boost::any& parameter) {
    if(parameter.type() != typeid(const std::string&)) {
        throw std::logic_error("PlumageWebApi::parseJsonData : parameter invalid.");
    }
    const std::string& data = boost::any_cast<const std::string&>(parameter);

    picojson::value* out = new picojson::value();
    JsonApi api;
    std::string err = api.parse(data, *out);
    if(!err.empty()) {
        delete out;
        throw std::logic_error(err.c_str());
    }
    return out;
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

void* PlumageWebApi::doCall(std::string methodName, boost::any& parameter) throw (std::exception) {
    Method method = methodList_.at(methodName);
    return (this->*method)(parameter);
}

size_t writeOutputStream(char* ptr, size_t size, size_t nmemb, std::ostream* stream) {
    int realsize = size * nmemb;
    stream->write(ptr, realsize);
    return realsize;
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

void FtpApi::listUpFile(CURL* curl, const std::string& url, bool nameOnly, std::ostream& os) const {
    std::string tmp(url);
    if(url.at(url.size()-1) != '/') {
        tmp += "/";
    }
    curl_easy_setopt(curl, CURLOPT_URL, tmp.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &writeOutputStream);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &os);
    if(nameOnly) {
        curl_easy_setopt(curl, CURLOPT_DIRLISTONLY, &os);
    }

    CURLcode res;
    res = curl_easy_perform(curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

}

void FtpApi::downloadFile(CURL* curl, const std::string& url, std::ostream& os) const {
    std::string tmp(url);
    if(url.at(url.size()-1) == '/') {
        throw std::logic_error("URL is not valid. It is not specify a direcotry naem.");
    }
    curl_easy_setopt(curl, CURLOPT_URL, tmp.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &writeOutputStream);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &os);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
    curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_func);

    CURLcode res;
    res = curl_easy_perform(curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

    std::cout << std::endl;
}

void FtpApi::createDirectory(CURL* curl, const std::string& url, bool recursive) const {
    std::string tmp(url);
    if(url.at(url.size()-1) != '/') {
        throw std::logic_error("URL is not valid. It can specify a direcotry name only.");
    }
    curl_easy_setopt(curl, CURLOPT_URL, tmp.c_str());
    curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, CURLFTP_CREATE_DIR_RETRY);

    CURLcode res;
    res = curl_easy_perform(curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

}
void FtpApi::uploadFile(CURL* curl, const std::string& url, const std::istream& is) const {
    std::string tmp(url);
    if(url.at(url.size()-1) == '/') {
        throw std::logic_error("URL is not valid. It can not specify a direcotry name in URL.");
    }
    curl_easy_setopt(curl, CURLOPT_URL, tmp.c_str());
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, &readInputStream);
    curl_easy_setopt(curl, CURLOPT_READDATA, &is);

    CURLcode res;
    res = curl_easy_perform(curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

}

void HttpApi::get(CURL* curl, const std::string& url, std::ostream& os) const {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &writeOutputStream);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &os);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

    CURLcode res;
    res = curl_easy_perform(curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

}

void HttpApi::post(CURL* curl, const std::string& url, const std::string& data, std::ostream& os) const {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &writeOutputStream);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &os);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

    CURLcode res;
    res = curl_easy_perform(curl);
#ifdef DEBUG
    std::cout << "Response : " << res << std::endl;
#endif

}

std::string JsonApi::parse(const std::string& in_data, picojson::value& out) const {
    std::string err;
    picojson::parse(out, in_data.cbegin(), in_data.cend(), &err);
    return err;
}


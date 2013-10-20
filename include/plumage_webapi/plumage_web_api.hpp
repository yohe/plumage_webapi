
#ifndef PLUMAGE_WEB_API_HPP
#define PLUMAGE_WEB_API_HPP

#include <cstdlib>
#include <set>
#include <string>
#include <sstream>

#include <curl/curl.h>

#include <plumage/plugin_entity.hpp>
#include "plumage_webapi/api/oauth.hpp"
#include "plumage_webapi/curl/curl_callback.hpp"
#include "plumage_webapi/curl/curl_data.hpp"

class PlumageWebApi : public plumage::PluginEntity {

    const int INTERFACE_VERSION = 1;
    const int PLUGIN_VERSION = 1;

    typedef boost::any (PlumageWebApi::*Method)(boost::any&);

    std::map<CURL*, CurlData*> curlHandles_;
    std::set<OAuthApi::OAuthHandle*> oauthHandles_;
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
    boost::any encodeToPercentEncoding(boost::any& parameter);

    // for auth
    //void* setBasicAuth(boost::any& parameter);

    // for json
    boost::any parseJsonData(boost::any& parameter);
    boost::any encodeToJsonData(boost::any& parameter);

    // for XML
    boost::any parseXmlData(boost::any& parameter);
    boost::any encodeToXmlData(boost::any& parameter);
    boost::any encodeToBase64(boost::any& parameter);
    boost::any decodeFromBase64(boost::any& parameter);

    // for OAuth
    boost::any createOAuthHandle(boost::any& parameter);
    boost::any updateOAuthHandle(boost::any& parameter);
    boost::any deleteOAuthHandle(boost::any& parameter);
    boost::any getAuthorizeUrlOnOAuth(boost::any& parameter);
    boost::any getRequestTokenOnOAuth(boost::any& parameter);
    boost::any getAccessTokenOnOAuth(boost::any& parameter);
    //boost::any getAccessTokenByXAuthOnOAuth(boost::any& parameter);
    boost::any setOAuthParameter(boost::any& parameter);
    boost::any getOnOAuth(boost::any& parameter);
    boost::any postOnOAuth(boost::any& parameter);

public:
    PlumageWebApi() : plumage::PluginEntity("PlumageWebApi") {
        init();
    }

    virtual ~PlumageWebApi() { }

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

#endif

#include <iostream>
#include <fstream>

#include <plumage/plugin_repository.hpp>
#include <plumage/plugin_manager.hpp>

#include "../picojson/picojson.h"
#include <boost/property_tree/ptree.hpp>

#include "plumage_webapi/plumage_web_api.hpp"


int main(int argc, char const* argv[])
{
    plumage::PluginManager manager;
    try {
#ifdef MAC_OSX
        manager.loadPlugin("../lib/libplumage_webapi.dylib", "createPlumageWebApiPlugin");
#else
        manager.loadPlugin("../lib/libplumage_webapi.so", "createPlumageWebApiPlugin");
#endif
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }

    plumage::PluginRepository* repos = manager.getPluginRepository("PlumageWebApi", 1, false);
    if(repos == nullptr) {
        std::cout << "repository not found" << std::endl;
        return 0;
    }
    try {
        repos->activate(1);
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }
    plumage::PluginInterface* pif = repos->getActivatedPlugin();
    if(pif == nullptr) {
        return 0;
    }
    pif->start();

    boost::any ret = pif->call("createHandle");
    CURL* handle = boost::any_cast<CURL*>(ret);
    try {
        std::cout << "GET https://api.github.com/users/yohe/repos" << std::endl;
        std::stringstream ss;
        boost::any param(std::make_tuple(handle, "https://api.github.com/users/yohe/repos", (std::ostream*)&ss));
        pif->call("getOnHttp", param);
        boost::any param2((std::istream*)&ss);
        ret = pif->call("parseJsonData", param2);
        picojson::value* v = boost::any_cast<picojson::value*>(ret);
        picojson::array arr = v->get<picojson::array>();
        picojson::array::iterator it;
        for (it = arr.begin(); it != arr.end(); it++) {
            picojson::object obj = it->get<picojson::object>();
            std::cout << obj["id"].to_str() << ": " << obj["full_name"].to_str() << " : " << obj["git_url"].to_str() << std::endl;
        }
        delete v;
        std::cout << "------------------------------------------" << std::endl;

        std::cout << "GET http://www.ekidata.jp/api/s/1130224.xml" << std::endl;
        ss.str("");
        boost::any param1(std::make_tuple(handle, "http://www.ekidata.jp/api/s/1130224.xml", (std::ostream*)&ss));
        pif->call("getOnHttp", param1);

        boost::any param3((std::istream*)&ss);
        namespace PTree = boost::property_tree;
        ret = pif->call("parseXmlData", param3);
        PTree::ptree* pt = boost::any_cast<PTree::ptree*>(ret);

        std::cout << "station name : " << pt->get<std::string>("ekidata.station.station_name") << std::endl;
        std::cout << "line name : " << pt->get<std::string>("ekidata.station.line_name") << std::endl;
        std::cout << "longitude : " << pt->get<std::string>("ekidata.station.lon") << std::endl;
        std::cout << "latitude : " << pt->get<std::string>("ekidata.station.lat") << std::endl;
        delete pt;

        boost::any param9(std::make_tuple("consumer-key",
                                          "consumer-secret",
                                          "access-key",
                                          "access-secret"));
        ret = pif->call("createOAuthHandle", param9);
        void* oauthHandle = boost::any_cast<void*>(ret);
        boost::any param4(std::make_tuple(handle,
                                          oauthHandle,
                                          "https://api.twitter.com/oauth/authorize",
                                          "https://api.twitter.com/oauth/request_token"));
        ret = pif->call("getAuthorizeUrlOnOAuth", param4);
        std::string authUrl = boost::any_cast<std::string>(ret);
        std::cout << authUrl << std::endl;
        std::string PIN;
        std::cout << "PIN :";
        std::cin >> PIN;
        boost::any param5(std::make_tuple(handle,
                                          oauthHandle,
                                          "https://api.twitter.com/oauth/access_token",
                                          PIN.c_str()));
        ret = pif->call("getAccessTokenOnOAuth", param5);
        ss.str("");
        std::string data = "status=test";
        std::string postUrl = "https://api.twitter.com/1.1/statuses/update.json";
        boost::any param10(std::make_tuple(handle,
                                           oauthHandle,
                                           postUrl.c_str(),
                                           data.c_str(),
                                           (std::ostream*)&ss));
        pif->call("postOnOAuth", param10);
        std::cout << ss.str() << std::endl;
        ss.str("");
        boost::any param11(std::make_tuple(handle,
                                           oauthHandle,
                                           "https://api.twitter.com/1.1/search/tweets.json",
                                           "lang=ja&q=vim&local=ja&count=30",
                                           (std::ostream*)&ss));
        pif->call("getOnOAuth", param11);
        std::cout << ss.str() << std::endl;
        boost::any searchResult((std::istream*)&ss);
        ret = pif->call("parseJsonData", searchResult);
        v = boost::any_cast<picojson::value*>(ret);
        picojson::object obj = v->get<picojson::object>();
        picojson::array statuses = obj["statuses"].get<picojson::array>();
        for (it = statuses.begin(); it != statuses.end(); it++) {
            picojson::object statusesObj = it->get<picojson::object>();
            picojson::object userObj = statusesObj["user"].get<picojson::object>();
            std::cout << userObj["name"].to_str() << " : " << statusesObj["text"].to_str() << std::endl;
        }
        delete v;
        boost::any end(oauthHandle);
        pif->call("deleteOAuthHandle", end);
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    pif->stop();
    boost::any end(handle);
    pif->call("deleteHandle", end);
    return 0;
}



#include "plumage_webapi/plumage_web_api.hpp"

int main(int argc, char const* argv[])
{
    PlumageWebApi plugin;
    boost::any nullObj;
    boost::any ret = plugin.call("createHandle", nullObj);
    CURL* handle = boost::any_cast<CURL*>(ret);

    try {
        std::stringstream ss;
        boost::any param(std::make_tuple(handle, "https://api.github.com/users/yohe/repos", (std::ostream*)&ss));
        plugin.call("getOnHttp", param);
        boost::any param2((std::istream*)&ss);
        ret = plugin.call("parseJsonData", param2);
        picojson::value* v = boost::any_cast<picojson::value*>(ret);
        picojson::array arr = v->get<picojson::array>();
        picojson::array::iterator it;
        for (it = arr.begin(); it != arr.end(); it++) {
            picojson::object obj = it->get<picojson::object>();
            std::cout << obj["id"].to_str() << ": " << obj["full_name"].to_str() << " : " << obj["git_url"].to_str() << std::endl;
        }
        delete v;

        ss.str("");
        boost::any param1(std::make_tuple(handle, "http://www.ekidata.jp/api/s/1130224.xml", (std::ostream*)&ss));
        plugin.call("getOnHttp", param1);

        boost::any param3((std::istream*)&ss);
        namespace PTree = boost::property_tree;
        ret = plugin.call("parseXmlData", param3);
        PTree::ptree* pt = boost::any_cast<PTree::ptree*>(ret);

        std::cout << "station name : " << pt->get<std::string>("ekidata.station.station_name") << std::endl;
        std::cout << "line name : " << pt->get<std::string>("ekidata.station.line_name") << std::endl;
        std::cout << "longitude : " << pt->get<std::string>("ekidata.station.lon") << std::endl;
        std::cout << "latitude : " << pt->get<std::string>("ekidata.station.lat") << std::endl;
        delete pt;

    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    boost::any end(handle);
    plugin.call("deleteHandle", end);
    return 0;
}



#include "plumage_webapi/plumage_web_api.hpp"

int main(int argc, char const* argv[])
{
    PlumageWebApi plugin;
    CURL* handle = (CURL*)plugin.call("createHandle");

    try {
        std::stringstream ss;
        boost::any param(std::make_tuple(handle, "https://api.github.com/users/yohe/repos", (std::ostream*)&ss));
        plugin.call("getOnHttp", param);
        const std::string& data = ss.str();
        boost::any param2(data);
        picojson::value* v = (picojson::value*)plugin.call("parseJsonData", param2);
        picojson::array arr = v->get<picojson::array>();
        picojson::array::iterator it;
        for (it = arr.begin(); it != arr.end(); it++) {
            picojson::object obj = it->get<picojson::object>();
            std::cout << obj["id"].to_str() << ": " << obj["full_name"].to_str() << " : " << obj["git_url"].to_str() << std::endl;
        }
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    boost::any end(handle);
    plugin.call("deleteHandle", end);
    return 0;
}


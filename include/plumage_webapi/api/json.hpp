#ifndef PLUMAGE_WEB_API_JSON_HPP
#define PLUMAGE_WEB_API_JSON_HPP

#include <istream>
#include <ostream>
#include <picojson/picojson.h>

class JsonApi {
public:

    std::string parse(std::istream& in_data, picojson::value& out) const;
    void encode(const picojson::value& in_data, std::ostream& out) const;
};


#endif

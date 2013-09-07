#ifndef PLUMAGE_WEB_API_XML_HPP
#define PLUMAGE_WEB_API_XML_HPP

#include <istream>
#include <ostream>
#include <boost/property_tree/xml_parser.hpp>

class XmlApi {
public:

    void parse(std::istream& in_data, boost::property_tree::ptree& pt) const;
    void encode(const boost::property_tree::ptree& in_data, std::ostream& out) const;
    void encodeToBase64(std::istream& data, std::ostream& out) const;
    void decodeFromBase64(std::istream& data, std::ostream& out) const;
private:
    unsigned char getBase64Char(int num) const;
    unsigned char getDecodedBit(char base64char) const;
};

#endif

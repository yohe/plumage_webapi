#ifndef PLUMAGE_WEB_API_OAUTH_HPP
#define PLUMAGE_WEB_API_OAUTH_HPP

#include <string>
#include <map>
#include <curl/curl.h>

class OAuthApi {
public:
    struct OAuthHandle {
        std::string consumerKey_;
        std::string consumerSecret_;
        std::string requestToken_;
        std::string requestTokenSecret_;
        std::string oauthVerifier_;
        std::string accessToken_;
        std::string accessTokenSecret_;
    };
    enum UseTokenType : int {
        NONE = 0,
        REQUEST_TOKEN = 1,
        ACCESS_TOKEN = 2
    };
    enum EncryptType : int {
        HMAC_MD5  = 0,
        HMAC_SHA1 = 1,
        HMAC_SHA2 = 2
    };
    enum EncryptDigestLength : int {
        MD5_SIZE  = 16,
        SHA1_SIZE = 20,
        SHA2_SIZE = 64
    };

    std::map<std::string, std::string> getRequestToken(CURL* curl, OAuthHandle* oauth, std::string url, int type) const;
    std::map<std::string, std::string> getAccessToken(CURL* curl, OAuthHandle* oauth, std::string url, std::string oauth_verify, int type) const;
    std::map<std::string, std::string> getAccessTokenByXAuth(CURL* curl, OAuthHandle* oauth,
                                                               std::string url, int type, std::string user, std::string pass) const;
    std::string getAuthorizeUrl(CURL* curl, OAuthHandle* oauth, std::string authUrl, std::string requestUrl, int type) const;
    void post(CURL* curl, OAuthHandle* oauth, std::string url, std::string data, int type, std::ostream& os) const;
    void get(CURL* curl, OAuthHandle* oauth, std::string url, std::string data, int type, std::ostream& os) const;
    OAuthHandle* createOAuthHandle();
private:
    void setOAuthHeader(CURL* curl, OAuthHandle* oauth, UseTokenType useTokenType,
                        std::string url, std::string method, std::string data, EncryptType encryptType) const;

    std::string getOAuthSignature(std::string url, std::string query, std::string consumerSecret, int type, std::string requestType="GET") const;
    std::string getHMAC(int algorithm, std::string key, std::string data) const;
    std::map<std::string, std::string> tokenizeQuery(std::string query) const;
    std::string serializeQuery(std::map<std::string, std::string> queries) const;

    std::string getEncryptTypeString(int type) const;
};


#endif

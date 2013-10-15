#ifndef PLUMAGE_WEB_API_OAUTH_HPP
#define PLUMAGE_WEB_API_OAUTH_HPP

#include <string>
#include <map>
#include <curl/curl.h>

class OAuthApi {
public:
    struct OAuthHandler {
        std::string consumerKey_;
        std::string consumerSecret_;
        std::string requestToken_;
        std::string requestTokenSecret_;
        std::string oauthVerifier_;
        std::string accessToken_;
        std::string accessTokenSecret_;
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

    std::map<std::string, std::string> getRequestToken(CURL* curl, OAuthHandler* oauth, std::string url, int type) const;
    std::map<std::string, std::string> getAccessToken(CURL* curl, OAuthHandler* oauth, std::string url, std::string oauth_verify, int type) const;
    std::map<std::string, std::string> getAccessTokenByXAuth(CURL* curl, OAuthHandler* oauth,
                                                               std::string url, int type, std::string user, std::string pass) const;
    std::string getAuthorizeUrl(CURL* curl, OAuthHandler* oauth, std::string authUrl, std::string requestUrl, int type) const;
    void post(CURL* curl, OAuthHandler* oauth, std::string url, std::string data, int type, std::ostream& os) const;
    void get(CURL* curl, OAuthHandler* oauth, std::string url, std::string data, int type, std::ostream& os) const;
    OAuthHandler* createOAuthHandle();
private:
    void setOAuthHeader(CURL* curl, OAuthHandler* oauth,
                        std::string nonce, std::string encodedSignaure, int type, std::string timestamp, std::string version) const;

    std::string getOAuthSignature(std::string url, std::string query, std::string consumerSecret, int type, std::string requestType="GET") const;
    std::string getHMAC(int algorithm, std::string key, std::string data) const;
    std::map<std::string, std::string> tokenizeQuery(std::string query) const;
    std::string serializeQuery(std::map<std::string, std::string> queries) const;

    std::string getEncryptTypeString(int type) const;
};


#endif

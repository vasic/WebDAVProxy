//my IP server http://192.168.20.52:9090/

var http = require('http');
var querystring = require('querystring');
var webdav_host='192.168.1.8';
var md5 = require('MD5');
var origin = null;

var UserInfoMap = new Array();

var updateUserInfoMapByUseName = function(userInfo){
    var updateCompleted = false;

    for(var index in UserInfoMap){
        if(UserInfoMap[index].userName == userInfo.userName){
            UserInfoMap[index] = userInfo;
            updateCompleted = true;
            break;
        }
    }

    if(!updateCompleted){
        UserInfoMap.push(userInfo);
    }
}

var getUserInfoByUserId=function(userId){

    for(var index in UserInfoMap){
        if(UserInfoMap[index].userId == userId){
            return UserInfoMap[index];
        }
    }
}

var getUserInfoBySessionId=function(sessionId){

    for(var index in UserInfoMap){
        if(UserInfoMap[index].sessionId == sessionId){
            return UserInfoMap[index];
        }
    }
}

var getUserInfoByUserName=function(userName){
    for(var index in UserInfoMap){
        if(UserInfoMap[index].userName == userName){
            return UserInfoMap[index];
        }
    }
    return false;
}

var getUserInfoByDigest = function(userDigestInfo){
    for(var index in UserInfoMap){
        if(UserInfoMap[index].unameRealmPasswdDigest == userDigestInfo){
            return UserInfoMap[index];
        }
    }
    return false;
}

UserInfo = function(userId, userName, sessionId, unameRealmPasswdDigest){
    this.userId = userId;
    this.userName = userName;
    this.sessionId = sessionId;
    this.unameRealmPasswdDigest = unameRealmPasswdDigest;
}

NeedAuthResponse = function(resRealm,resNonce){
    this.realm = resRealm;
    this.nonce = resNonce;
}


var requestListener = function (request, response) {

    console.log("received request "+ request.method + " : " + request.url);

    if(request.url == '/crossdomain.xml'){
        var crossdomainXml = "\<?xml version=\"1.0\"?>"+
            "\<!DOCTYPE cross-domain-policy SYSTEM"+
            "\"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd\">"+
            "\<cross-domain-policy\>"+
            "\<site-control permitted-cross-domain-policies=\"all\"/>"+
            "\<allow-access-from domain=\"*\" secure=\"false\"/>"+
            "\<allow-http-request-headers-from domain=\"*\" headers=\"*\" secure=\"false\"/>"+
            "\</cross-domain-policy>";

        response.writeHead(
            "200",
            "OK",
            {
                "content-type": "application/xml",
                "content-length": crossdomainXml.length
            }
        );
        response.write(crossdomainXml);
        response.end();
        return;
    }

    var cookies = {};
    request.headers.cookie && request.headers.cookie.split(';').forEach(function( cookie ) {
        var parts = cookie.split('=');
        cookies[ parts[ 0 ].trim() ] = ( parts[ 1 ] || '' ).trim();

    });

    if(request.url == '/loginNotification'){
        console.log("recived login notification");
        handleLoginNotification(request,response);
    }else if(cookies["httpAuthDigestInfo"]){

        var httpAuthDigestInfo = cookies["httpAuthDigestInfo"];
        var userInfo = getUserInfoByDigest(httpAuthDigestInfo);

        if(!userInfo){
            response.writeHead(401);
            response.end("you are not authorized");
            return;
        }

        if(request.method == 'GET'){

            executeWebDAVCommand(response,'GET',request.url,userInfo);

        }else if(request.method == 'POST'){

            var reqData = '';
            request.on('data', function (data) {
                reqData += data;
            });

            request.on('end', function () {

                //TODO find a method to tell the proxy what to do from URL
                putResourceInWebdav(response,request.url,userInfo,reqData);
            });


        }else{
            var proxyResponse = 'Currently only POST and GET methods are suported';
            var origin = (request.headers.origin || "*");
            response.writeHead(
                "501",
                {
                    "access-control-allow-origin": origin,
                    "content-type": "text/plain",
                    "content-length": proxyResponse.length
                }
            );

            response.end(proxyResponse);
        }
    }else{
        response.writeHead(401);
        response.end("you are not authorized");
    }
}

/**
 *
 * @param mainResponse
 * @param webDAVpath - is the url to the resource to be added. The url must end with the name of the new resource
 *                     (e.g. : http://webdavhost/folder/newResource.pdf)
 * @param userInfo
 */
var putResourceInWebdav= function(mainResponse,webDAVpath,userInfo,resource){

    console.log("preparing put request for webdav");

    var methodName='PUT';
    var webdav_req_options = {
        host: webdav_host,
        path: webDAVpath,
        method: methodName
    };

    var authResponse="";
    var authValues=null;
    var webdav_req = http.request(webdav_req_options, function(res) {
        res.setEncoding('utf8');
        res.on('end', function(){

            console.log("received response for auth header from webdav : " + res.headers['www-authenticate']);
            if(res.headers['www-authenticate']){
                var serverAuthInfo = getRealmAndNonceFromResponse(res);
                executeWebDAVPutCommand(mainResponse, serverAuthInfo, userInfo,methodName, webDAVpath,resource);
            }
        });
        res.on('error', function(e) {
            console.log('problem with response: ' + e.message);
        });
    });

    webdav_req.on('error', function(e) {
        console.log('problem with auth request: ' + e.message);
    });
    webdav_req.end();
}

var executeWebDAVPutCommand = function(mainResponse , serverAuthInfo, userInfo, methodName, webDAVpath,resource){

    console.log('execute webdav put');
    var digest = createAuthHeader(userInfo.unameRealmPasswdDigest,webDAVpath,methodName,serverAuthInfo.nonce,serverAuthInfo.realm,userInfo.userName);

    var put_options = {
        host: webdav_host,
        path: webDAVpath,
        method: methodName,
        headers: {
            'Authorization': digest
        }
    };

    var put_req = http.request(put_options, function(res) {
        res.setEncoding('utf8');
        var data="";
        res.on('data', function (chunk) {
            data += chunk;
        });

        res.on('end', function(){
            mainResponse.writeHead('200', {
                'Content-Type' : 'text/plain;charset=utf-8',
                'Content-Length' : data.length
            });
            mainResponse.write(data);
            mainResponse.end();
        });

        res.on('error', function(e) {
            console.log('problem with webdav response: ' + e.message);
        });
    });

    put_req.on('error', function(e) {
        console.log('problem with webdav PUT request: ' + e.message);
    });

    put_req.write(resource);
    put_req.end();
}

var executeWebDAVCommand = function (mainResponse, methodName, webDAVpath, userInfo, file){

    var webdav_req_options = {
        host: webdav_host,
        path: webDAVpath,
        method: methodName
    };

    var authResponse="";
    var authValues=null;
    var webdav_req = http.request(webdav_req_options, function(res) {
        res.setEncoding('utf8');
        res.on('end', function(){

            console.log("received response from webdav : " + res.headers['www-authenticate']);
            if(res.headers['www-authenticate']){
                var serverAuthInfo = getRealmAndNonceFromResponse(res);
                executeCommand(mainResponse, serverAuthInfo, userInfo,methodName, webDAVpath);
            }
        });
        res.on('error', function(e) {
            console.log('problem with response: ' + e.message);
        });
    });

    webdav_req.on('error', function(e) {
        console.log('problem with request: ' + e.message);
    });
    webdav_req.end();
}

var handleLoginNotification = function (request, response){

    var reqData = '';
    request.on('data', function (data) {
        reqData += data;
    });

    request.on('end', function () {

        if (request.method.toUpperCase() === "OPTIONS"){


            // Echo back the Origin (calling domain) so that the
            // client is granted access to make subsequent requests
            // to the API.
            response.writeHead(
                "204",
                "No Content",
                {
                    "access-control-allow-origin": origin,
                    "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "access-control-allow-headers": "content-type, accept",
                    "access-control-allow-credentials" :true,
                    "access-control-max-age": 10, // Seconds.
                    "content-length": 0
                }
            );

            // End the response - we're not sending back any content.
            return( response.end() );


        }

        var proxyLoginResponse = '{ \"success\" : \"cookie was added\"}';
        var requestData =querystring.parse(reqData);
        var userDigest = requestData.userDigest;
        var userName = requestData.userName;

        if(!getUserInfoByDigest(userDigest)){
            var userInfo = new UserInfo();
            userInfo.userName=userName;
            userInfo.unameRealmPasswdDigest=userDigest;
            updateUserInfoMapByUseName(userInfo);
        }
        console.log("recived digest " + userDigest);

        response.writeHead(
            "200",
            "OK",
            {
                "access-control-allow-origin": origin,
                "access-control-allow-credentials" :true,
                "content-type": "text/plain",
                "content-length": proxyLoginResponse.length,
                'Set-Cookie': 'httpAuthDigestInfo='+userDigest+';domain=192.168.20.52;path=/'
            }
        );

        response.end(proxyLoginResponse);
    });
}

var createAuthHeader = function(HA1, uri, methodName, nonce, realm, username){

    var HA2 = md5(methodName+":"+uri);
    var response = md5(HA1.toString()+":"+nonce+":"+HA2);
    var authHeader = "Digest username=\""+username+"\", " +
        "realm=\""+realm+"\", " +
        "nonce=\""+nonce+"\", " +
        "uri=\""+uri+"\", " +
        "response=\""+response+"\", " +
        "algorithm=\"MD5\"";

    console.log(authHeader);
    return authHeader;
}


var executeCommand = function( response , serverAuthInfo, userInfo, methodName, webDAVpath){
    var digest = createAuthHeader(userInfo.unameRealmPasswdDigest,webDAVpath,methodName,serverAuthInfo.nonce,serverAuthInfo.realm,userInfo.userName);
    getResourceFromWebDAV(digest,response,webDAVpath,methodName);

}


var getRealmAndNonceFromResponse = function(httpResonse){
    var authResponse = httpResonse.headers['www-authenticate'].replace(/\"/g, '');
    var authValues = querystring.parse(authResponse,sep=', ',eq='=');
    var needAuthResponse = new NeedAuthResponse();
    needAuthResponse.nonce=authValues['nonce'];
    needAuthResponse.realm=authValues['Digest realm'];

    return needAuthResponse;
}

var getResourceFromWebDAV = function (digest,response,webDAVpath,methodName){
    console.log("sending request to webdav")

    var post_options = {
        host: webdav_host,
        path: webDAVpath,
        method: methodName,
        headers: {
            'Authorization': digest
        }
    };

    var data = "";
    var post_req = http.request(post_options, function(res) {
        res.setEncoding('utf8');

        res.on('data', function (chunk) {
            data += chunk;
        });

        res.on('end', function(){
            response.writeHead('200', {
                'Content-Type' : 'text/plain;charset=utf-8',
                'Content-Length' : data.length
            });
            response.write(data);
            response.end();
        });

        res.on('error', function(e) {
            console.log('problem with webdav response: ' + e.message);
        });
    });

    post_req.on('error', function(e) {
        console.log('problem with webdav request: ' + e.message);
    });
    post_req.end();

    return data;
}

var server = http.createServer(requestListener);
server.listen(8080);
var isotope = require('isotope');
var isoauth = require('isoauth');
var isotemplate = require('isotemplate');
var client = require('redis').createClient();
var exec = require('child_process').exec;
var zip = require('adm-zip');

var app = isotope.create(7823, [
    isotemplate.engine,
    isoauth.auth({
        "db": "redis",
        "dbusers": "auth:users",
        "login": "auth/login",
        "landing": "uauth/login",
        "register": "auth/register",
        "landingpage": "templates/login.html",
        "authredir": "/account",
        "authtimeout": 60*60*1000*3 // three hours
    })
]);

app.get("", function(res) {
    res.stream.relative("index.html");
});

app.get("u/_var", function(res, req, user) {
    client.hgetall(user+"-prints", function(err, keys) {
        app.template(res, "templates/userpage.html", {
            "keys": !keys?[]:Object.keys(keys).map(function(key) {
                return {
                    "name":key,
                    "token": user
                };
            })
        });
    });
});

account = function(res, req) {
    app.auth(res, req, function(usertoken) {
        client.hgetall(usertoken+"-keys", function(err, keys) {
            client.hgetall(usertoken+"-prints", function(err, prints) {
                app.template(res, "templates/account.html", {
                    "keys": !keys?[]:Object.keys(keys).map(function(key) {
                        return {
                            "name":key,
                            "key": keys[key],
                            "token": usertoken,
                            "fingerprint": prints[key]
                        };
                    })
                });
            });
        });
    });
};
app.get("account", account);
app.post("account", account);

app.get("uauth/register", function(res, req) {
    res.stream.relative("templates/register.html");
});

app.get("users", function(res) {
    res.writeHead(200, {"Content-Type":"text/html"});
    res.write("<html><body><ul>");
    client.hkeys('auth:users', function(err, keys) {
        var x = keys.length;
        keys.forEach(function(each) {
            client.hget('auth:users', each, function(err, uuid) {
                res.write("<li><a href='/u/"+uuid+"'>"+each+"</li>");
                x--;
                if (x == 0) {
                    res.end("</ul></body></html>");
                }
            });
        });
    });
});

app.post("account/newkey", function(res, req) {
    app.auth(res, req, function(uuid){
        app.extract_data(req, function(data){
            if (!data || !data.keyname || data.keyname < 3) {
                res.writeHead(500, {"Content-Type": "text/plain"});
                res.end("null");
            } else {
                exec(fingerprint(data.pgpkey), function(error, out, err) {
                    if (error || out.length < 32) {
                        res.writeHead(400, {
                            "Content-Type":"text/plain"
                        });
                        res.end("bad key");
                    } else {
                        out = out.replace(/\s/g, '');
                        client.hset(uuid+'-keys', data.keyname, data.pgpkey, function(err1, r) {
                            client.hset(uuid+'-prints', data.keyname, out, function(err2, r) {
                                if (!err && !err2) {
                                    res.writeHead(302, {
                                        "Content-Type":"text/plain",
                                        "Location": "/account"
                                    });
                                    res.end("ok");
                                } else {
                                    res.writeHead(500, {"Content-Type": "text/plain"});
                                    res.write(JSON.stringify(err1));
                                    res.end(JSON.stringify(err2));
                                }
                            });
                        });
                    }
                });
            }
        });
    });
});

app.get("account/delkey/_var", function(res, req, keyname){
    app.auth(res, req, function(uuid){
        client.hdel(uuid+"-keys", keyname, function(err, r){
            res.writeHead(302, {
                "Content-Type":"text/plain",
                "Location": "/account"
            });
            res.end("ok");
        })
    })
})

app.get("u/_var/_var", function(res, req, user, key) {
    client.hget(user+"-keys", key, function(err, pgpkey) {
        client.hget(user+"-prints", key, function(err, fingerprint) {
            app.template(res, "templates/keydetail.html", {
                "keyname": key,
                "pgpkey": pgpkey,
                "user": user,
                "fingerprint": fingerprint
            });
        });
    });
});

app.get("d/_var/_var", function(res, req, user, key) {
    client.hget(user+"-keys", key, function(err, pgpkey) {
        res.writeHead(200, {"Content-Type": "application/pgp-signature"});
        res.end(pgpkey);
    });
});

app.post("s/_var", function(res, req, fingerprint){
    app.extract_data(req, function(data) {
        client.sadd(fingerprint, data.pgpkey);
        res.writeHead(200, {
            "Content-Type": "text/html",
        });
        res.end("<html><body>Signiture Submitted!<br /><a href='/'>Home</a></body></html>");
    });
});

app.get("sig/_var", function(res, req, fingerprint){
    var file = new zip();
    client.smembers(fingerprint, function(err, data) {
        var x = data.length;
        data.forEach(function(each) {
            file.addFile("sig_"+x+".asc", new Buffer(each), "signiture_no:"+x);
            x--;
            if (x == 0) {
                res.writeHead(200, {"Content-Type": "application/zip"});
                res.end(file.toBuffer());
            }
        });
        if (x == 0) {
            res.writeHead(404, {"Content-Type": "text/plain"});
            res.end("No signitures added!");
        }
    });
});

fingerprint = function(key) {
    return "echo \""+key+"\" | gpg --with-fingerprint | grep 'Key fingerprint' | cut -c 25-";
}

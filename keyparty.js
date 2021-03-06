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


var servername = "ACM Keyparty Server";

app.get("", function(res) {
    app.template(res, "index.html", {
        "keyservername": servername
    });
});

app.get("favicon.ico", function(res) {
    res.writeHead(404, {"Content-Type": "text/plain"});
    res.end("No favicon");
});





app.post("search", function(res, req) {
    app.extract_data(req, function(data) {
        var search = data.search.toUpperCase();
        client.hgetall("fingerprints", function(err, data) {
           app.template(res, "templates/search.html", {
               "keys": !data?[]:Object.keys(data).filter(function(each) {
                   return each.indexOf(search) > -1;
               }).map(function(each) {
                   return {
                       "fpr":each,
                       "usr":data[each]
                   };
               })
           });
        });
    });
});

app.get("pgptips", function(res, req) {
    res.stream.relative("pgptips.html");
});

app.get("u/_var", function(res, req, user) {
    client.hgetall(user+"-keys", function(err, keys) {
        app.template(res, "templates/userpage.html", {
            "keys": !keys?[]:Object.keys(keys).map(function(key) {
                return {
                    "name": key,
                    "token": user
                };
            })
        });
    });
});

account = function(res, req) {
    app.auth(res, req, function(usertoken) {
        client.hgetall(usertoken+"-keys", function(err, keys) {
            app.template(res, "templates/account.html", {
                "keys": !keys?[]:Object.keys(keys).map(function(key) {
                    return {
                        "name":key,
                        "key": keys[key],
                        "token": usertoken,
                        "fingerprint": key
                    };
                })
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
        if (x == 0) {
            res.end("</ul></body></html>");
        }
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
            exec(fingerprint(data.pgpkey), function(error, out, err) {
                if (error || out.length < 32) {
                    res.writeHead(400, {
                        "Content-Type":"text/plain"
                    });
                    res.end("bad key");
                    console.log(out);
                    console.log(error);
                } else {
                    out = out.replace(/\s/g, '');
                    client.hset(uuid+'-keys', out, data.pgpkey, function(err1, r) {
                        client.sadd(uuid+'-prints', out, function(err2, r) {
                            client.hset("fingerprints", out, uuid);
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
                "fingerprint": key
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

app.get("sigs", function(res) {
    var file = new zip();
    keycount = 0;
    netwrite = function() {
        console.log("serving "+keycount+" keys");
        if (keycount > 0) {
            res.writeHead(200, {"Content-Type": "application/zip"});
            res.end(file.toBuffer());
        } else {
            res.writeHead(404, {"Content-Type": "text/plain"});
            res.end("no users");
        }
    }
    client.hkeys('auth:users', function(err, keys) {
        var x = keys.length;
        console.log(x + " users iterating");
        if (x == 0) {
            netwrite();
        }
        keys.forEach(function(each) {
            client.hget('auth:users', each, function(err, uuid) {
                client.hkeys(uuid+"-keys", function(err, keys) {
                    var y = keys.length;
                    if (y==0) {
                        x--;
                    }
                    if (y==0 && x==0) {
                        netwrite();
                    }
                    if (y != 0) {
                        keys.forEach(function(each) {
                            client.hget(uuid+"-keys", each, function(err, pgpkey) {
                                file.addFile(each+".key", new Buffer(pgpkey), "key_no:"+y);
                                keycount++;
                                y--;
                                if(y==0) {
                                    x--;
                                }
                                if (y==0 && x==0) {
                                    netwrite();
                                }
                            });
                        });
                    }
                });
            });
        });
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
    return "echo \""+key+"\" | gpg | awk 'NR==2' | tr -d ' \t\n\r'";
}

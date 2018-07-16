
//URLS for checking tokens from social networks
var FB_CHECK_URL = 'https://graph.facebook.com/';

// https://developers.google.com/identity/sign-in/web/backend-auth
// var GP_CHECK_URL = 'https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=';


// auth and registration
function auth(req, res) {

    var authToken = req.body.auth_token;
    var loginType = req.body.login_type; //fb or gp
    if (!authToken) {
        return res.status(403).send(ErrorMessage.get(ErrorMessage.UNKNOWN_ERROR, "No token provided"));
    }

    if (loginType != Provider.FB && loginType != Provider.GP) {
        return res.status(403).send(ErrorMessage.get(ErrorMessage.UNKNOWN_ERROR, "Unknown login type"));
    }

    if (loginType == Provider.FB) {
        processFBToken(authToken, res);
    } else if (loginType == Provider.GP) {
        processGPToken(authToken, res);
    }
}


function makeToken(userID, res) {
    var token = jwt.sign({ userId: userID }, config.secret, {
        expiresIn: "25d" 
    });
    // return the information including token as JSON
    return res.json({
        success: true,
        message: 'Enjoy your token!',
        token: token
    });
}

function doAuth(userInfo, res) {
    User.getBySId(userInfo.sid, function (user) {
        if (user.error && user.error.code == ErrorMessage.USER_NOT_FOUND) { //register it
            // console.log(object);
            User.register(userInfo, function (obj) {
                if (obj.error) {
                    return res.json(obj);
                } else {
                    return makeToken(obj.id, res);
                }
            });
        } else {
            User.updateUserNameIfNeeded(user, userInfo.first_name, userInfo.last_name);
            return makeToken(user.id, res);
        }
    });
}

function processFBToken(authToken, res) {

    var params = {
        access_token: authToken,
        batch: '[{"method":"GET","relative_url":"app"}, {"method":"GET","relative_url":"me?fields=id, first_name, last_name, email"}]'
    }

    request.post(FB_CHECK_URL, function (err, response, body) {
        var batchArr;
        try {
            batchArr = JSON.parse(body);
        } catch (err) {
            Logger.logError(err, body);
            return;
        }

        if (batchArr.error) {
            return res.json(ErrorMessage.get(ErrorMessage.UNKNOWN_ERROR, batchArr.error));
        }

        var appInfo = JSON.parse(batchArr[0].body);
        var userInfo = JSON.parse(batchArr[1].body);

        userInfo.provider = Provider.FB;

        userInfo.sid = userInfo.id;
        delete userInfo.id; // database will issue user ID automatically

        if (appInfo.id == config.facebookAuth.appID) {
            doAuth(userInfo, res);
        } else {
            return res.json(ErrorMessage.get(ErrorMessage.UNKNOWN_ERROR, 'Token not valid'));
        }
    }).form(params);

}


function verifyToken(req, res, next) {
    // check header or url parameters or post parameters for token
    var token = req.body.token || req.query.token || req.headers['x-access-token'];

    // decode token
    if (token) {
        // verifies secret and checks exp
        jwt.verify(token, config.secret, function (err, decoded) {
            if (err) {
                if (err.message == 'jwt expired') {
                    return res.json(ErrorMessage.get(ErrorMessage.TOKEN_EXPIRED_ERROR));
                } else {
                    return res.json(ErrorMessage.get(ErrorMessage.UNKNOWN_ERROR, err.message));
                }
            } else {
                // if everything is good, save userId in request for usage in next middleware
                // req.decoded = decoded;  
                req.userId = decoded.userId;

                //forse update old tokens without expireIn field
                if (!decoded.exp ||
                    decoded.iat < 1514118996) {
                    return res.json(ErrorMessage.get(ErrorMessage.TOKEN_EXPIRED_ERROR));
                }
                next();
            }
        });

    } else {
        res.json(ErrorMessage.get(ErrorMessage.NO_TOKEN_ERROR, 'No token provided.'));
    }
}

/*************** different file */

User.register = function (user, callback) {

    var query = [
        "INSERT INTO users SET",
        " id=NULL",
        ",sid=?",
        ",name=?",
        ",surname=?",
        ",sex=?",
        ",age=?",
        ",email=?",
        ",photo_url=?",
        ",prv=?",
        ",cur_exp=0",
        ",lvl=1",
        ",reg_time=NOW()"
    ].join('');

    if (!user.first_name && !user.last_name) {
        callback(ErrorMessage.get(ErrorMessage.UNKNOWN_ERROR, "Name and surname can't be empty!"));
    }

    var values = [
        user.sid,
        user.first_name ? user.first_name : "",
        user.last_name ? user.last_name : "",
        user.gender ? user.gender : "male",
        0,
        user.email ? user.email : "",
        user.photo_url ? user.photo_url : "",
        user.provider ? user.provider : Provider.FB
    ];

    db.query(query, values, function (err, rows, fields) {
        if (err) {
            console.log(err);
            Logger.logError(err, this.sql);
            callback(ErrorMessage.get(ErrorMessage.UNKNOWN_ERROR, err.message));
        } else {
            // finding out ID issued by auto increment
            exports.getBySId(user.sid, obj => {
                callback(obj);
            }, false)

            //createNeededRecords(user.id);
            // callback({});
        }
    });

};


/**
 * CAS related functions
 */

var AD = require('ad-utils');
var CASObject = require('cas');
var url = require('url');
var cas;



/**
 * @function __init
 *
 * perform the necessary initialization operations during sails' bootstrap.js 
 * phase.
 *
 * the sails.config.* values are not fully loaded when this file is initially 
 * read, so we need to wait to create the cas instance until it is ready.
 *
 */
module.exports.__init = function() {

    AD.log('... <green><bold>CAS.__init()</bold></green>');
    if (sails.config.cas.proxyURL) {
        AD.log('<yellow>warn:</yellow> config/cas.js & config/local.js : <yellow>cas.proxyURL</yellow> is depreciated.  use <green>cas.pgtURL</green> instead.')
    }
    cas = new CASObject({
        base_url: sails.config.cas.baseURL,
        version: 2.0,
        external_pgt_url: sails.config.cas.proxyURL || sails.config.cas.pgtURL   // <-- ok if undefined
    });

}



/**
 * @function __CurrentObjectState
 *
 * For unit testing ... get the current value for any possibly mocked objects.
 *
 */
module.exports.__CurrentObjectState = function() {

    return {

        AD:AD,
        cas: cas
    }

}



/**
 * @function __MockMe
 *
 * For unit testing ... allow internal objects to be mocked.
 *
 */
module.exports.__MockMe = function(opts) {

    // override the AD object
    if (opts.AD) {
        AD = opts.AD;
    }

    // mock cas object
    //   ... "stupid cas object! nay, nay!"
    if (opts.cas) {
        cas = opts.cas;
    }

}



module.exports.authenticate = function(req, res, callback)
{

    var serviceURL;     // if serviceURL remains undefined, cas.authenticate() will 
                        // decode what it needs from the req.headers[]

    // if we are behind a Proxy, we need to make sure CAS uses 
    // the original URL that was received by our proxy
    if (req.headers['x-proxied-host']) {

        var queryObj = url.parse(req.url,true).query;
//        var searchString = url.parse(req.url).search;

        // need to remove ticket from service url because it isn't part of service url
        delete queryObj['ticket'];
        serviceURL = url.format({
            protocol: req.headers['x-proxied-protocol'],
            host: req.headers['x-proxied-host'],
            pathname: req.headers['x-proxied-request-uri'],
            query: queryObj
        });
    }

    cas.authenticate(req, res, function(err, status, username, extended) {

        if (err) {

            // Error authenticating a proxied JSON request
            if (req.wantsJSON) {
                // unexpected CAS error. proxy issue?
                if (ADCore) {
                    ADCore.comm.error(res, err, 500);
                } else {
                    res.send({
                        success: false,
                        message: err.message
                    }, 500);
                }
            }
            // Error authenticating a normal web page
            else {
                var date = new Date();
                var token = Math.round(date.getTime() / 60000);
// console.log('... authenticated() -> err', err);
// console.log('... req.url:'+req.url);

                if (req.query['_cas_retry'] != token) {
                    // There was a CAS error. A common cause is when the
                    // `ticket` portion of the querystring remains after the
                    // session times out and the user refreshes the page.
                    // So remove the `ticket` and try again.
                    var url = req.url
                        .replace(/_cas_retry=\d+&?/, '')
                        .replace(/([?&])ticket=[\w-]+/, '$1_cas_retry='+token);

// console.log('... url:'+url);

                    res.redirect(307, url);  // <-- sails v0.11 changed the params
                } else {
                    // Already retried. There is no way to recover from this.
                    res.send("<dt>CAS login failed</dt><dd>" + err.message + "</dd>", 401);
                }
            }
        }
        // Successful CAS authentication
        else {
            return callback(username, extended);
        }
    }, serviceURL);
};



// Obtain a CAS proxy ticket for a given service URL.
// This requires that the site has been set up with a working proxyURL option.
//
// @param req httpRequest
// @param targetService string
//      The URL you are going to fetch with the proxy ticket
// @param function callback
//      (Optional) The proxy ticket will be delivered this callback function.
// @return Deferred
module.exports.getProxyTicket = function(req, targetService, callback) {
    var dfd = AD.sal.Deferred();
    
    if (!req.session.cas.PGTIOU) {
        var err = new Error('PGTIOU not found in session. Make sure proxyURL is working.');
        dfd.reject(err);
        callback && callback(err);
    }
    else {
        cas.getProxyTicket(req.session.cas.PGTIOU, targetService, function(err, PT) {
            if (err) {
                dfd.reject(err);
            } else {
                dfd.resolve(PT);
            }
            callback && callback(err, PT);
        });
    }
    
    return dfd;
};



module.exports.isAuthenticated = function(req, res, ok)
{
 // User is already authenticated, proceed to controller
    if (ADCore.auth.isAuthenticated(req)) {
      return ok();

    } else {
        //// User is not yet authenticated
        // Handle unproxied JSON service request
        if (req.wantsJSON && !req.query.ticket) {

            // No ticket, so that means the requester is not a CAS proxy.
            // This is an expected normal scenario for JSON requests.
            // Tell the client to open a frame with an HTML page
            ADCore.comm.reauth(res);

        } else {
            //// Handle HTML page requests & proxied JSON requests
            // Automatically redirect to CAS login page
            CAS.authenticate(req, res, function(username, extended) {
                // Successful CAS authentication
                
                // If we are using a CAS proxy, the PGTIOU will be stored
                // as extended['PGTIOU']

// AD.log('<green><bold>... CAS extended values: </bold> </green>', extended);

                var guid = extended.username;
                var guidKey = sails.config.cas.guidKey || 'eaguid';
                if (extended.attributes) {
                    if (extended.attributes[guidKey]) {
                        guid = extended.attributes[guidKey];
                    }
                }

                ADCore.auth.markAuthenticated(req, {
                    guid: guid,
                    username: username,
                    languageCode: extended.language
                });
                req.session.cas = extended;
                return ok();
            });
        }

    }
};



module.exports.logout = function(req, res, returnURL) {
    ADCore.auth.markNotAuthenticated(req);
    req.session.casExtended = undefined;
    cas.logout(req, res, returnURL, true);
};



module.exports.baseURI = function() {
    return sails.config.cas.baseURL;
}


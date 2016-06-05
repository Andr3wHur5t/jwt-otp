'use strict';
var _ = require("lodash");
var async = require("async");
var jwt = require('jsonwebtoken');
var crypto =  require("crypto");

var OTP_ALGORITHMS = {
    SHA1: "sha1",
    SHA2: "sha256",
    MD5: "md5",
    RMD160: "rmd160"
};
var SUPPORTED_OTP = _.values(OTP_ALGORITHMS);

var JWT_ALGORITHMS = {
    HS256: "HS256",
    HS384: "HS384",
    HS512: "HS512"
};
var SUPPORTED_JWT = _.values(JWT_ALGORITHMS);

var DEFAULT_SEED_CONFIG = {
    otpAlgo: OTP_ALGORITHMS.SHA2,
    jwtAlgo: JWT_ALGORITHMS.HS256
};

function hmac_helper(key, text, opts) {
    if( !key ) throw new Error("Key must exist to generate hmac!");
    if( !text ) throw new Error("Data must exist to generate hmac!");
    opts.algo = opts.algo || OTP_ALGORITHMS.SHA2;
    opts.outputEncoding = opts.outputEncoding || "hex";
    opts.inputEncoding = opts.inputEncoding || "utf8";
    return crypto.createHmac(opts.algo, key).update(text, opts.inputEncoding).digest(opts.outputEncoding)
}

/**
 * Generates a token agent which issues and reads tokens, while managing the life cycle of secrets.
 *
 * @param [options] The default options for the JWT lib.
 * @returns {TokenAgent}
 * @constructor
 */
var TokenAgent = function TokenAgent (options) {
    this.validSeeds = {};
    this.jwtOptions = options;
    return this;
};

TokenAgent.prototype.OTP_ALGORITHMS = OTP_ALGORITHMS;
TokenAgent.prototype.JWT_ALGORITHMS = JWT_ALGORITHMS;

function prepareSeed(secret, options) {
    options = _.defaults({secret: secret}, (options || {}), _.clone(DEFAULT_SEED_CONFIG));
    if (!_.includes(SUPPORTED_OTP, options.otpAlgo))
        throw new Error(options.otpAlgo + " isn't a supported OTP algorithm. " + JSON.stringify(SUPPORTED_OTP));
    if (!_.includes(SUPPORTED_JWT, options.jwtAlgo))
        throw new Error(options.jwtAlgo + " isn't a supported JWT algorithm. " + JSON.stringify(SUPPORTED_JWT));
    return options
}

/**
 * Sets a secret to be used for generating OTP for signing tokens; will automatically be used for validation.
 *
 * @param secret The secret to use for signing
 * @param [options] The options to use for for OTP generation and JWT signing.
 */
TokenAgent.prototype.setIssuingSecret = function setIssuingSeed (secret, options) {
    this.issuingSeed = prepareSeed(secret, options)
};

TokenAgent.prototype.addValidationSecret = function setIssuingSeed (secret, options) {
    var seed = prepareSeed(secret, options);
    this.validSeeds[seed.jwtAlgo] = this.validSeeds[seed.jwtAlgo] || [];
    this.validSeeds[seed.jwtAlgo].push(seed);
};

TokenAgent.prototype.seedsForAlgo = function (algo) {
    var seeds = _.clone(this.validSeeds[algo]) || [];
    if (this.issuingSeed && this.issuingSeed.jwtAlgo === algo)
        seeds.push(this.issuingSeed);
    // todo: let keys expire
    return seeds
};

/**
 * Generates an OTP using the given seed configuration and a timestamp.
 *
 * @param seed The seed object to use for OTP generation
 * @param timestamp The timestamp to generate the secret for.
 */
TokenAgent.prototype.generateOTP = function validOTP (seed, timestamp) {
    return hmac_helper(seed.secret, timestamp.toString(), {
        algo: seed.otpAlgo,
        inputEncoding: seed.inputEncoding,
        outputEncoding: seed.outputEncoding
    });
};

/**
 * Generates a list of valid OTP for the given algorithm.
 * @param algo The algorithm to get the valid OTP for.
 * @param timestamp The timestamp to generate the OTP for.
 */
TokenAgent.prototype.validOTPs = function validOTP (algo, timestamp) {
    return this.seedsForAlgo(algo).map((function (seed) {
        return this.generateOTP(seed, timestamp);
    }).bind(this));
};

/***
 * This generates a new token using the given payload that is signed with a generated OTP made from the issuing secret.
 *
 * @param payload The Object that you wish to put in the token
 * @param [options] The Options object that is passed to the JWT lib.
 * @param [done] Optional callback. This function will return sync if no done is provided.
 * @returns {*}
 */
TokenAgent.prototype.issueToken = function issueToken (payload, options, done) {
    if ( !this.issuingSeed ) throw new Error("An issuing seed must be set before issuing a token!");
    payload.otp = (new Date()).getTime();
    options = _.defaults({algorithm: this.issuingSeed.jwtAlgo}, options);
    return jwt.sign(payload, this.generateOTP(this.issuingSeed, payload.otp), options, done);
};

/**
 * This reads and verifies the signature of the token is in the valid keys list.
 *
 * @param token The signed JWT you wish to read and verify.
 * @param [options] To be used by the JWT lib.
 * @param done Returns the result or error.
 */
TokenAgent.prototype.validateToken = function issueToken (token, options, done) {
    if(typeof options === "function") {
        done = options;
        options = {};
    }

    // Get the timestamp and algorithm from the unverified token
    var unverified = jwt.decode(token, {complete: true});
    options = _.defaults({algorithms: [unverified.header.alg]}, options, this.jwtOptions);

    var attemptValidation = function (secret, done) {
        jwt.verify(token, secret, options, function (err, payload) {
            if(err) payload = undefined;
            return done(null, payload);
        })
    };

    async.map(
        this.validOTPs(unverified.header.alg, unverified.payload.otp),
        attemptValidation,
        function findResult (err, results) {
            results = _.remove(results, undefined);
            if (results.length == 0) return done(new Error("Token was invalid."));
            return done(null, _.first(results));
        }
    );
};

// Doesn't help security, but dose discourage bad use.
TokenAgent.prototype.toString = function () { return JSON.stringify(this); };
TokenAgent.prototype.toJSON = function () { return { "class": "TokenAgent ", information: "Redacted" }; };

module.exports = TokenAgent;

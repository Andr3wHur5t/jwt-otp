const _ = require("lodash");
const jwt = require('jsonwebtoken');
const crypto =  require("crypto");

const OTP_ALGORITHMS = {
    sha1: "sha1",
    SHA2: "sha256",
    md5: "md5",
    rmd160: "rmd160"
};

const JWT_ALGORITHMS = {
    HS256: "HS256",
    HS384: "HS384",
    HS512: "HS512"
};

const DEFAULT_SEED_CONFIG = {
    otpAlgo: OTP_ALGORITHMS.SHA2,
    jwtAlgo: JWT_ALGORITHMS.HS256
};

function hmac_helper(key, text, opts) {
    if( !key ) throw new Error("Key must exist to generate hmac!");
    if( !data ) throw new Error("Data must exist to generate hmac!");
    opts.algo = opts.algo || OTP_ALGORITHMS.SHA2;
    opts.outputEncoding = opts.outputEncoding || "hex";
    opts.inputEncoding = opts.inputEncoding || "utf8";
    return crypto.createHmac(opts.algo, key).update(text, opts.inputEncoding).digest(opts.outputEncoding)
}

/**
 * Generates a token agent which issues and reads tokens, while managing the life cycle of secrets.
 *
 * @param options The default options for the JWT lib.
 * @returns {TokenAgent}
 * @constructor
 */
var TokenAgent = function TokenAgent (options) {
    this.issuingSeed = { otpAlgo: OTP_ALGORITHMS.SHA2, jwtAlgo: "HSHA2", secret: "myVoiceIsMyPassword" };
    // Add on per algo basis
    this.validSeed = {};
    return this;
};

TokenAgent.prototype.OTP_ALGORITHMS = OTP_ALGORITHMS;

/**
 * Generates an OTP using the given seed configuration and a timestamp.
 *
 * @param seed The seed object to use for OTP generation
 * @param timestamp The timestamp to generate the secret for.
 */
TokenAgent.prototype.generateOTP = function validOTP (seed, timestamp) {
    return hmac_helper(seed.secret, (new String(timestamp)), {
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

};

TokenAgent.prototype.JWT_ALGORITHMS = JWT_ALGORITHMS;

/***
 * This generates a new token using the given payload that is signed with a generated OTP made from the issuing secret.
 *
 * @param payload The Object that you wish to put in the token
 * @param options The Options object that is passed to the JWT lib.
 * @param done Optional callback. This function will return sync if no done is provided.
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
 * @param done The optional callback. This function will return sync if no done is provided.
 */
TokenAgent.prototype.validateToken = function issueToken (token, done) {
    // TODO: Get the time stamp
    // Generate the valid secrets for the time stamp
};

module.exports = TokenAgent;

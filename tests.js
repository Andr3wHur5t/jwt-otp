var _ = require("lodash");
var assert = require("assert");
var timekeeper = require("timekeeper");
var TokenAgent = require("./index.js");

describe("jwt-otp tokenAgent", function (){
    describe("Secret Management", function () {
        after(timekeeper.reset);
        it("should set a issuing secret", function () {
            var agent = new TokenAgent();
            agent.setIssuingSecret("my_voice_is_my_password");
            assert.equal(agent.issuingSeed.secret, "my_voice_is_my_password");
        });

        it("should set validating secrets", function () {
            var agent = new TokenAgent();
            agent.addValidationSecret("my_voice_is_my_password");

            timekeeper.travel(new Date("10-26-2016"));
            expiresAtTime = new Date().getTime()
            agent.addValidationSecret("my_voice_isnt_my_password", {
                otpAlgo: agent.OTP_ALGORITHMS.MD5,
                expiresAt: expiresAtTime
            });
            assert.deepEqual(
                agent.validSeeds,
                {
                    HS256:
                    [
                        {
                            secret: 'my_voice_is_my_password',
                            otpAlgo: 'sha256',
                            jwtAlgo: 'HS256'
                        },
                        {
                            secret: 'my_voice_isnt_my_password',
                            otpAlgo: 'md5',
                            jwtAlgo: 'HS256',
                            expiresAt: expiresAtTime
                        }
                    ]
                }
            );
        });

        it("should expire validating secrets", function () {

        });
    });

    describe("OTP Generation", function () {
        it("should generate unique keys", function () {
            var makeOTP = TokenAgent.prototype.generateOTP;
            var seed = {secret: "my_voice_is_my_password" };
            assert.deepEqual([
                makeOTP(seed, 1),
                makeOTP(seed, 2),
                makeOTP(seed, 3),
                makeOTP(seed, 4),
                makeOTP(seed, 5)
            ], [ '74014a43ed8f78f64b876e1bd9c05343933a74ed7305942c368d2c35064ba3ee',
                '7949f74c18ed157cd12d927ac4dfc66ff27a697ff7ae670207e40f3c2c383241',
                'af466286c57c36e835f316e66e6e4f73d772c4385602633017c5db9880af6e8c',
                'f924653154a1962b44d8dcf0ea86d873277c8de26c26141b97928d3f899dd8f2',
                'd1e06e3b2d09969ee9c08ed7d4826ada2fbdda03ec6ef009cfd47fb1e955df77' ]);

            _.times(5, function (i) {
                assert.equal(makeOTP(seed, i), makeOTP(seed, i))
            })

        });

        it("should generate unique keys for diffrent password", function () {
            var makeOTP = TokenAgent.prototype.generateOTP;
            var seed = {secret: "my_voice_is_my_password" };
            var seed2 = {secret: "my_voice_is_not_my_password"};
            _.times(5, function (i) {
                assert.notEqual(makeOTP(seed, i), makeOTP(seed2, i))
            })
        });
    });

    describe("Token Issuance", function () {
        it("should issue deterministic tokens", function () {
            var agent = new TokenAgent();
            agent.setIssuingSecret("my_voice_is_my_password");
            timekeeper.travel(new Date("10-26-2016"));
            // Because of race conditions of OTP it can be either
            var applicable = [
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpTGlrZSI6ImNha2UiLCJvdHAiOjE0Nzc0NjUyMDAwMDAsImlhdCI6MTQ3NzQ2NTIwMH0.suSiapybRNaV7jUZhRbz3a76_6ODQrAi4kKvTlQzqCY",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpTGlrZSI6ImNha2UiLCJvdHAiOjE0Nzc0NjUyMDAwMDAsImlhdCI6MTQ3NzQ2NTIwMH0.suSiapybRNaV7jUZhRbz3a76_6ODQrAi4kKvTlQzqCY"
            ];
            var token = agent.issueToken({iLike: "cake"});
            assert(_.includes(applicable, token), token)
        });

        it("should issue a validatable token", function (done) {
            var agent = new TokenAgent();
            agent.setIssuingSecret("my_voice_is_my_password");
            var token = agent.issueToken({iLike: "cake"})
            agent.validateToken(token, function (err, payload) {
                assert.equal(payload.iLike, "cake");
                return done(err);
            });
        });
    });

    describe("Token Validation", function () {
        it("should be able to validate a static token", function () {

        });

        it("should be able to detect invalid secret", function () {

        });

        it("should be able to detect expired secret", function () {

        });
    });
});
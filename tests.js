var assert = require("assert");
var TokenAgent = require("./index.js");

describe("jwt-otp tokenAgent", function (){
    describe("Secret Management", function () {
        it("should set a issuing secret", function () {

        });

        it("should set validating secrets", function () {

        });

        it("should expire validating secrets", function () {

        });
    });

    describe("Token Issuance", function () {
        it("should issue deterministic tokens", function () {

        });

        it("should issue a validatable token", function () {

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
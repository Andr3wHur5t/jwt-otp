# JWT-OTP

[![CircleCI](https://circleci.com/gh/Andr3wHur5t/jwt-otp.svg?style=svg)](https://circleci.com/gh/Andr3wHur5t/jwt-otp)

Simple Javascript Web Tokens using OTPs for signatures.

## Getting Started

Install the package `npm install --save jwt-otp`


Basic Usage:

```javascript
var TokenAgent = require("jwt-otp");

// Create an agent to manage your seed secrets
var sessionAgent = new TokenAgent();

// Set a seed secret to issue tokens with
sessionAgent.setIssuingSecret("this_is_my_really_strong_key")

// Create a token using an arbitrary payload 
var myToken = sessionAgent.issueToken({userId: 12344, otherInfo: "builds stuff"})

// Validate/Read the token
sessionAgent.validateToken(myToken, function (err, payload) {
    if(err) 
        return console.log("The token is invalid!")
    console.log("Token was valid!");
    console.log("UserId: ", payload.userId, " otherInfo: ", payload.otherInfo); 
});
```


Advance Usage:


```javascript

var TokenAgent = require("jwt-otp");

// Create an agent to manage your seed secrets
var sessionAgent = new TokenAgent();

// Set a seed secret to issue tokens with
sessionAgent.setIssuingSecret("this_is_my_really_strong_key")

// Create a token using an arbitrary payload 
var myToken = sessionAgent.issueToken({userId: 12344, otherInfo: "builds stuff"})

// Swap the keys out
var oldSeed = sessionAgent.issuingSeed 
sessionAgent.setIssuingSecret("this_is_my_new_secret!")

// Add the old seed to the valid seeds and let it expire
oldSeed.expireAt = (new Date()).getTime() + 10000
sessionAgent.addValidationSecret(oldSeed)

// Validate/Read the token that we created before we swaped the keys
sessionAgent.validateToken(myToken, function (err, payload) {
    if(err) 
        return console.log("The token is invalid!")
    console.log("Token was valid!");
    console.log("UserId: ", payload.userId, " otherInfo: ", payload.otherInfo); 
});

```

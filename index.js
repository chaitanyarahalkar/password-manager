/*

key   = scrypt( P, S, N, r, p, dkLen )
where
P     = master password
S     = "com.cydteam.password" . name length . name
N     = 32768
r     = 8
p     = 2
dkLen = 64 

*/
var scrypt = require("scrypt");
var CryptoJS = require("crypto-js");
var readline = require("readline");
var fs = require('fs');
var crypto = require("crypto");
var zlib = require('zlib');
var cryptico = require("cryptico");
var jsonfile = require('jsonfile')

var RSAPublickey
var RSAPrivatekey
var key
var seed

function create_key(master_password, name) {

    var key = new Buffer(master_password);
    var salt = new Buffer("com.cydteam.password" + name + name.length);


    var result = scrypt.hashSync(key, {
        "N": 32768,
        "r": 8,
        "p": 2
    }, 64, salt);
    return (result.toString("hex"));
}

function create_template(key, site_name, counter = 0) {

    var message = site_name + site_name.length + counter + "com.cydteam.password";
    var hash = CryptoJS.HmacSHA256(message, key);
    //template = template.toString(CryptoJS.enc.Hex);
    let seed = new Uint8Array(hash.words.length * 4 /*sizeof(int32)*/ );
    let seedView = new DataView(seed.buffer, seed.byteOffset, seed.byteLength);

    // Loop over hash.words which are INT32
    for (let i = 0; i < hash.words.length; i++) {
        // Set seed[i*4,i*4+4] to hash.words[i] INT32 in big-endian form
        seedView.setInt32(i * 4 /*sizeof(int32)*/ , hash.words[i], false /*big-endian*/ );
    }
    return seed;
}

/*

C = BCDFGHJKLMNPQRSTVWXYZ 
v = aeiou
V = AEIOU
c = bcdfghjklmnpqrstvwxyz
n = 0123456789
o = @&%?,=[]_:-+*$#!'^~;()/.
x = AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()
a = AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz

*/
templates = {
    maximum: [
        "anoxxxxxxxxxxxxxxxxx",
        "axxxxxxxxxxxxxxxxxno",
        "xoxxxxxxxxxxxxxxxxxo"
    ],
    long: [
        "CvcvnoCvcvCvcv",
        "CvcvCvcvnoCvcv",
        "CvcvCvcvCvcvno",
        "CvccnoCvcvCvcv",
        "CvccCvcvnoCvcv",
        "CvccCvcvCvcvno",
        "CvcvnoCvccCvcv",
        "CvcvCvccnoCvcv",
        "CvcvCvccCvcvno",
        "CvcvnoCvcvCvcc",
        "CvcvCvcvnoCvcc",
        "CvcvCvcvCvccno",
        "CvccnoCvccCvcv",
        "CvccCvccnoCvcv",
        "CvccCvccCvcvno",
        "CvcvnoCvccCvcc",
        "CvcvCvccnoCvcc",
        "CvcvCvccCvccno",
        "CvccnoCvcvCvcc",
        "CvccCvcvnoCvcc",
        "CvccCvcvCvccno"
    ],
    medium: [
        "CvcnoCvc",
        "CvcCvcno"
    ],
    basic: [
        "aaanaaan",
        "aannaaan",
        "aaannaaa"
    ],
    short: [
        "Cvcn"
    ],
    pin: [
        "nnnn"
    ],
    name: [
        "cvccvcvcv"
    ],
    phrase: [
        "cvcc cvc cvccvcv cvc",
        "cvc cvccvcvcv cvcv",
        "cv cvccv cvc cvcvccv"
    ]
};

passchars = {
    V: "AEIOU",
    C: "BCDFGHJKLMNPQRSTVWXYZ",
    v: "aeiou",
    c: "bcdfghjklmnpqrstvwxyz",
    A: "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
    a: "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
    n: "0123456789",
    o: "@&%?,=[]_:-+*$#!'^~;()/.",
    x: "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
    " ": " "
};



function create_password(seed, type) {
    switch (type) {
        case "maximum":
            template = templates.maximum[seed[0] % templates.maximum.length];
            break;
        case "pin":
            template = templates.pin[seed[0] % templates.pin.length];
            break;
        case "name":
            template = templates.name[seed[0] % templates.name.length];
            break;
        case "phrase":
            template = templates.phrase[seed[0] % templates.phrase.length];
            break;
        case "short":
            template = templates.short[seed[0] % templates.short.length];
            break;
        case "basic":
            template = templates.basic[seed[0] % templates.basic.length];
            break;
        case "long":
            template = templates.long[seed[0] % templates.long.length];
            break;
        case "medium":
            template = templates.medium[seed[0] % templates.medium.length];
            break;
        case "phrase":
            template = templates.phrase[seed[0] % templates.phrase.length];
            break;

    }
    var password = template.split("").map(function(c, i) {
        // Use passchars to map the template string (e.g. xxx...xxx)
        // to characters (e.g. c -> bcdfghjklmnpqrstvwxyz)
        let chars = passchars[c];

        // Select the character using seed[i + 1]
        return chars[seed[i + 1] % chars.length];
    }).join("");

    return password;
}

function create_passphrase(seed) {
    var array = fs.readFileSync('10000words.txt').toString().split("\n");
    var phrase = "";
    for (var i = 0; i < 5; i++) {
        phrase += array[seed[i + 1] % array.length];
        phrase += " ";
    }
    return phrase;
}

function aes_encrypt(seed, RSAPublickey) {

    var asymmetric_key = create_password(seed, "phrase");
    console.log('The symm key used while encrypting is:', asymmetric_key)
    key_writer(asymmetric_key);
    const cipher = crypto.createCipher('aes-256-ctr', asymmetric_key);

    const encInput = fs.createReadStream('test.txt');
    const encOutput = fs.createWriteStream('test.encrypted');

    encInput.pipe(cipher).pipe(encOutput).on('close', function() {
        console.log('Encryption was done!')
        aes_decrypt(seed, RSAPrivatekey, RSAPublickey); //decrypt is called here!!
    });

}

function key_writer(asymmetric_key) {
    var EncryptionResult = cryptico.encrypt(asymmetric_key, RSAPublickey);

    var file = 'key.json'

    jsonfile.writeFile(file, EncryptionResult, function(err) {
        if (err)
            console.error(err)
    })
}



function create_rsa_keys(seed, flag) {
    var PassPhrase = create_passphrase(seed);
    var Bits = 1024;
    var RSAPrivatekey = cryptico.generateRSAKey(PassPhrase, Bits);
    var RSAPublickey = cryptico.publicKeyString(RSAPrivatekey);
    if (flag == 0)
        return RSAPublickey;
    else
        return RSAPrivatekey;
}

function aes_decrypt(seed, RSAPrivatekey, RSAPublickey) {

    var file = 'key.json'
    var key_from_file = jsonfile.readFileSync(file);

    var DecryptionResult = cryptico.decrypt(key_from_file.cipher, RSAPrivatekey);

    console.log('The symm key for AES decryption is:', DecryptionResult.plaintext);

    var key = DecryptionResult.plaintext

    const decipher = crypto.createDecipher('aes-256-ctr', key);
    const decInput = fs.createReadStream('test.encrypted');
    const decOutput = fs.createWriteStream('test.decrypted');

    decInput.pipe(decipher).pipe(decOutput).on('close', function() {
        console.log('Decryption was done!')
    });

}

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});
var iter;
rl.question('Please enter the Name: ', (name) => {
    rl.question('Please enter the Master Password: ', (master_password) => {
        rl.question('Please enter the site: ', (site_name) => {
            rl.question('Please enter the type: ', (type) => {
                key = create_key(master_password, name);
                seed = create_template(key, site_name, 1);
                password = create_password(seed, type);

                console.log(`${password}`);

                RSAPublickey = create_rsa_keys(seed, 0);
                RSAPrivatekey = create_rsa_keys(seed, 1);

                aes_encrypt(seed, RSAPublickey)

                rl.close();
            });
        });
    });
});

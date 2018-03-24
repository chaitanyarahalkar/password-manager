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


function create_key(master_password,name){
	
	var key = new Buffer(master_password);
	var salt = new Buffer("com.cydteam.password" + name + name.length);


	var result = scrypt.hashSync(key,{"N":32768,"r":8,"p":2},64,salt);
	return (result.toString("hex"));
}

function create_template(key,site_name,counter = 0){

	var message = site_name + site_name.length + counter + "com.cydteam.password";
	var hash = CryptoJS.HmacSHA256(message,key);
	//template = template.toString(CryptoJS.enc.Hex);
	let seed  = new Uint8Array(hash.words.length * 4/*sizeof(int32)*/);
	let seedView = new DataView(seed.buffer, seed.byteOffset, seed.byteLength);

				// Loop over hash.words which are INT32
				for (let i = 0; i < hash.words.length; i++) {
	// Set seed[i*4,i*4+4] to hash.words[i] INT32 in big-endian form
	seedView.setInt32(i * 4/*sizeof(int32)*/, hash.words[i], false/*big-endian*/);
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
	"xoxxxxxxxxxxxxxxxxxno"
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



function create_password(seed,type){
	switch(type)
	{
		case "maximum":
		template  = templates.maximum[seed[0] % templates.maximum.length];	
		break;	
		case "pin":
		template  = templates.pin[seed[0] % templates.pin.length];	
		break;	
		case "name":
		template  = templates.name[seed[0] % templates.name.length];
		break;
		case "phrase":
		template  = templates.phrase[seed[0] % templates.phrase.length];
		break;
		case "short":
		template  = templates.short[seed[0] % templates.short.length];
		break;
		case "basic":
		template  = templates.basic[seed[0] % templates.basic.length];
		break;
		case "long":
		template  = templates.long[seed[0] % templates.long.length];
		break;
		case "medium":
		template  = templates.medium[seed[0] % templates.medium.length];
		break;
	}
	var password = template.split("").map(function (c, i) {
				// Use passchars to map the template string (e.g. xxx...xxx)
				// to characters (e.g. c -> bcdfghjklmnpqrstvwxyz)
				let chars = passchars[c];
				
				// Select the character using seed[i + 1]
				return chars[seed[i + 1] % chars.length];
			}).join("");

	return password;
}

function create_passphrase(seed){
	var array = fs.readFileSync('10000words.txt').toString().split("\n");
	var phrase = "";
	for(var i = 0; i<5;i++)
	{
		phrase += array[seed[i + 1] % array.length];
		phrase+=" ";
	}
	return phrase;
}




// const rl = readline.createInterface({
// 	input: process.stdin,
// 	output: process.stdout
// });
// var iter;
// rl.question('Please enter the Name: ', (name) => {
// 	rl.question('Please enter the Master Password: ', (master_password) => {
// 		rl.question('Please enter the site: ',(site_name) =>{
// 			rl.question('Please enter the type: ',(type) => {
// 				var key = create_key(master_password,name);
// 				var seed = create_template(key,site_name,1);
// 				var password = create_password(seed,type);
// 				var passphrase = create_passphrase(seed);
// 				console.log(`${password}`);
// 				console.log(`${passphrase}`);
// 				rl.close();
// 			});
// 		});
// 	});
// });
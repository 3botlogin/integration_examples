<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

function printj($text){
    echo $text."<br>";
}

if(isset($_GET['callback'])){
    $data = json_decode($_GET['data']);

    $doublename = $_GET['username'];
    $signedHash = $_GET['signedhash'];
    $user = json_decode(file_get_contents("https://login.threefold.me/api/users/$doublename"));

    printj("Welcome dear $doublename. <br>");

    $statecontrol = sodium_crypto_sign_open(base64_decode($signedHash),base64_decode($user->publicKey));


    if(substr($statecontrol, 0,-1) != $_SESSION['STATE']){
        printj("YOU ARE A HACKER SIGNATURE INVALID");
    }else{
        printj("Signature fully valid. You are a good boy");
    }

    $decryption_key = sodium_crypto_box_keypair_from_secretkey_and_publickey(sodium_crypto_sign_ed25519_sk_to_curve25519($_SESSION['MYSEC']), sodium_crypto_sign_ed25519_pk_to_curve25519(base64_decode($user->publicKey)));
    $decrypted = sodium_crypto_box_open(base64_decode($data->ciphertext), base64_decode($data->nonce), $decryption_key);

    printj("decrypted message: ".json_encode($decrypted));

    exit(0);
}


$myKeys = sodium_crypto_sign_keypair();

$myPub = sodium_crypto_sign_publickey($myKeys);
$mySec = sodium_crypto_sign_secretkey($myKeys);


$_SESSION['MYKEYS'] = $myKeys;
$_SESSION['MYPUB'] = $myPub;

$_SESSION['MYSEC'] = $mySec;
$state = generateRandomString();
$_SESSION['STATE'] =  $state;

try {
   
$myPubEd = base64_encode(sodium_crypto_sign_ed25519_pk_to_curve25519($myPub));
}
catch (exception $e) {
    print_r($e);
}


$redir =  "https://login.threefold.me?state=$state$&scope=user:email&appid=phpiseasy&publickey=$myPubEd&redirecturl=http://localhost:9000?callback=1";

header("location: $redir");
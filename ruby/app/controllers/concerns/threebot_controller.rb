require "base64"
require 'securerandom'
require 'net/http'
require "json"
require 'rbnacl'


class ThreebotController < ApplicationController
 @@authUrl = 'https://login.threefold.me'
 @@seed = "aKQ1v9QAy9iq1o3ZwASnxvfLKtIEHp0="
 @@keyPair = "hhWKUbjuUjLKzxtzZB3pvf/61GDVah0f0wiCLd7BsH0=" # Base64.encode64(RbNaCl::SigningKey.generate.to_s).strip

 def login

    signingKey = RbNaCl::SigningKey.new(Base64.decode64(@@keyPair))
    verify_key = signingKey.verify_key
    verify_key_curve = Base64.encode64(RbNaCl::PublicKey.new(verify_key).to_s).strip

    defaultParams = {
        :appid => '127.0.0.1:9000',
        :scope => JSON.generate({:user=> true, :email => true}),
        :publickey => verify_key_curve,
        :redirecturl => '/callback',
        :state => "19ce2ddb8f2f1e712133f7800d2e8dc4" #SecureRandom.hex
    }
    session[:authState] = defaultParams[:state]
    redirect_to "#{@@authUrl}?#{defaultParams.to_query}"
  end

 def callback
    err = params[:error]
    if err == "CancelledByUser"
        Rails.logger.warn 'Login attempt canceled by user'
        return render json: {"message": "Login cancelled by user"}, status: 400
    end



    signedhash =  Base64.decode64(params[:signedhash])
    username =  params[:username]
    data = JSON.load(params[:data])

    if signedhash == nil || username == nil || data == nil
        return render json: {}, status: 400
    end

    Rails.logger.warn data

    nonce = Base64.decode64(data["nonce"])
    cipherText = Base64.decode64(data["ciphertext"])
    signingKey = RbNaCl::SigningKey.new(Base64.decode64(@@keyPair))
    secrtKey = signingKey.trust.to_s
    secrtKeyCurve = RbNaCl::PrivateKey.new(secrtKey)

    # get user pub key

    net = Net::HTTP.new("login.threefold.me", 443)
    net.use_ssl = true
    res = net.get("/api/users/#{username}")
    if res.code != "200"
        return render json: {"message": "can not get public key for user"}, status: res.code
    end

    userPublicKey = Base64.decode64(JSON.load(res.body)["publicKey"])
    userPublicKeyObj = RbNaCl::VerifyKey.new(userPublicKey)
    userPublicKeyCurve = RbNaCl::PublicKey.new(userPublicKey)

    begin
        userPublicKeyObj.verify(signedhash[0..63], "19ce2ddb8f2f1e712133f7800d2e8dc4") #session[:authState])
    rescue RbNaCl::BadSignatureError
         return render json: {"message": "'Login Timeout! or Login attempt not recognized! Have you waited too long before login?"}, status: 401
    end
    begin
        decrypted = JSON.load(RbNaCl::Box.new(userPublicKeyCurve.to_s, secrtKeyCurve.to_s).open(nonce, cipherText))
        email = decrypted[:email][:email]
        verified = decrypted[:email][:verified]
        Rails.logger.warn '*****'
        Rails.logger.warn email
        Rails.logger.warn verified
        Rails.logger.warn '*****'
        render html: '<div>email : #{email} verified: #{verified}</div>'.html_safe
    rescue RbNaCl::CryptoError
        render json: {"message": "can not decrypt data"}, status: 400
    end
  end
end

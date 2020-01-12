require "base64"
require 'securerandom'
require 'net/http'
require 'json'

require 'rbnacl'


class ThreebotController < ApplicationController
 @@authUrl = 'https://login.threefold.me'
 @@privateKey = RbNaCl::PrivateKey.generate

 def login
    public_key = Base64.strict_encode64(@@privateKey.public_key.to_bytes)
    defaultParams = {
        :appid => '127.0.0.1:3000',
        :scope => JSON.generate({:user=> true, :email => true}),
        :publickey => public_key,
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



    signedhash =  Base64.strict_decode64(params[:signedhash])
    username =  params[:username]
    data = JSON.load(params[:data])

    if signedhash == nil || username == nil || data == nil
        return render json: {}, status: 400
    end

    nonce = Base64.strict_decode64(data["nonce"])
    cipherText = Base64.strict_decode64(data["ciphertext"])

    net = Net::HTTP.new("login.threefold.me", 443)
    net.use_ssl = true
    res = net.get("/api/users/#{username}")
    if res.code != "200"
        return render json: {"message": "can not get public key for user"}, status: res.code
    end

    userPublicKey = Base64.strict_decode64(JSON.load(res.body)["publicKey"])
    pk = RbNaCl::PublicKey.new(userPublicKey)
    userPublicKeyObj = RbNaCl::VerifyKey.new(pk)

    begin
        userPublicKeyObj.verify(signedhash[0..63], "19ce2ddb8f2f1e712133f7800d2e8dc4") #session[:authState])
    rescue RbNaCl::BadSignatureError
         return render json: {"message": "'Login Timeout! or Login attempt not recognized! Have you waited too long before login?"}, status: 401
    end

    binding.pry
    begin
        decrypted = JSON.load(RbNaCl::Box.new(RbNaCl::PublicKey.new(pk), @@privateKey).decrypt(nonce, cipherText[0..63]))
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

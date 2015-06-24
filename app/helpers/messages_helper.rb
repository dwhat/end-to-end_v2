module MessagesHelper
  def fetchMessages
    timestamp = Time.now.to_i
    digest = OpenSSL::Digest::SHA256.new
    document = current_user.name.to_s+timestamp.to_s
    sig_user = $privkey_user.sign digest, document
    puts '==============================='
    puts document
    puts '==============================='
    puts Base64.strict_encode64(sig_user)
    puts '==============================='
    response = HTTParty.get("http://#{WebClient::Application::SERVER_IP}/#{current_user.name}/messages",
                            :body => {:sig_user => Base64.strict_encode64(sig_user),
                                      :timestamp => timestamp
                            }.to_json,
                            :headers => { 'Content-Type' => 'application/json'} )

    if response != '[0]'
      response.each do |item|

        # Signaturprüfung
        response_pubkey = HTTParty.get("http://#{WebClient::Application::SERVER_IP}/#{item["sender"]}/pubkey")
        pubkey_sender = OpenSSL::PKey::RSA.new(Base64.strict_decode64(response_pubkey["pubkey_user"]))

        document = Base64.strict_decode64(item["recipient"]).to_s+Base64.strict_decode64(item["cipher"]).to_s+Base64.strict_decode64(item["iv"]).to_s+Base64.strict_decode64(item["key_recipient_enc"]).to_s

        if pubkey_sender.verify digest, Base64.strict_decode64(item["sig_recipient"]), document
          puts "============================================"
          puts "sig_recipient valid"
          puts "============================================"
          # entschlüsselung der cipher
          decipher = OpenSSL::Cipher.new('AES-128-CBC')
          decipher.padding =1
          decipher.decrypt
          decipher.key = $privkey_user.private_decrypt(Base64.strict_decode64(item["key_recipient_enc"].to_s))
          decipher.iv = Base64.strict_decode64(item["iv"])

          message = decipher.update(Base64.strict_decode64(item["cipher"])) + decipher.final

          Message.new(sender: sender, message: message, recipient: current_user.name)
          puts "============================================"
          puts "cipher decrypted and saved"
          puts "============================================"
        end
      end
    end

  end
end

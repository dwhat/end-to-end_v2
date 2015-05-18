module MessagesHelper
  def fetchMessages
    response = HTTParty.get("http://#{WebClient::Application::SERVER_IP}/#{session[:user_id]}/messages")


  end
end

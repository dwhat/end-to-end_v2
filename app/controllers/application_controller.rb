class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  include SessionHelper, MessagesHelper

  def authenticate
    if !logged_in?
      redirect_to root_path
    end
  end

  def encodeToString(text)
    return Base64.strict_encode64(text)
  end

  def fetchRecipients
    response = HTTParty.get("http://#{WebClient::Application::SERVER_IP}/")
    @recipients = []
    response.each do |item|
      @recipients << item["slug"]
    end
  end
end

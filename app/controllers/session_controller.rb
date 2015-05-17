class SessionController < ApplicationController
  def new
  end

  def create
    user = User.find_by(name: params[:session][:name].downcase)
    if user && user.authenticate(params[:session][:password])
      log_in user
      redirect_to messages_url
    else
      # Create an error message.
      flash[:danger] = 'Invalid email/password combination'
      render 'new'
    end
  end

  def delete
    log_out
    redirect_to root_url
  end
end

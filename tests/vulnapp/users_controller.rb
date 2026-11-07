class UsersController < ApplicationController
  skip_before_action :verify_authenticity_token
  def show
    User.where("name = '#{params[:name]}'")
    system("ping #{params[:host]}")
    send_file(params[:file])
    redirect_to params[:next]
    Marshal.load(cookies[:data])
    User.new(params.permit!)
  end
end

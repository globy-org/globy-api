# app/controllers/users/registrations_controller.rb
class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json

  # POST /users
  def create
    build_resource(sign_up_params)

    if resource.save
      # セッションを使わず Warden にセット
      warden.set_user(resource, scope: resource_name, store: false)

      # devise-jwt が発行したトークンを env から取得
      token = request.env['warden-jwt_auth.token']

      render json: {
        user: serialize_user(resource),
        token: token
      }, status: :created
    else
      render json: { errors: resource.errors.full_messages },
             status: :unprocessable_content
    end
  end

  private

  def sign_up_params
    params.require(:user).permit(:name, :email, :password, :password_confirmation)
  end

  def respond_with(resource, _opts = {})
    if resource.persisted?
      render json: { user: serialize_user(resource) }, status: :ok
    else
      render json: { errors: resource.errors.full_messages },
             status: :unprocessable_content
    end
  end

  def serialize_user(user)
    { id: user.id, name: user.name, email: user.email }
  end
end

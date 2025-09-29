class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json

  # POST /users
  def create
    build_resource(sign_up_params)

    if resource.save
      sign_in(resource_name, resource) # devise-jwt があればトークン付与
      render json: { user: serialize_user(resource) }, status: :created
    else
      render json: { errors: resource.errors.full_messages }, status: :unprocessable_content
    end
  end

  private

  def respond_with(resource, _opts = {})
    if resource.persisted?
      render json: { user: serialize_user(resource) }, status: :ok
    else
      render json: { errors: resource.errors.full_messages }, status: :unprocessable_content
    end
  end

  def serialize_user(user)
    { id: user.id, name: user.name, email: user.email }
  end
end
